package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type upconf struct {
	username   string
	userpublic string
	userip     string
	keeptime   string
	wgconfpath string
	status     bool // true = add to tail  | false = find and delete Peer block
}

const (
	wgSaveDebounce = 1 * time.Second
	wgSaveTimeout  = 5 * time.Second
)

var (
	wgSaveOnce    sync.Once
	wgSaveCh      chan wgSaveRequest
	wgSaveQueueCh chan wgSaveRequest
	wgSaveStopCh  chan struct{}
)

type wgSaveRequest struct {
	iface    string
	confPath string
}

func startWGSaver() {
	wgSaveOnce.Do(func() {
		wgSaveCh = make(chan wgSaveRequest, 64)
		wgSaveQueueCh = make(chan wgSaveRequest, 64)
		wgSaveStopCh = make(chan struct{})

		go func() {
			for {
				select {
				case req := <-wgSaveQueueCh:
					ctx, cancel := context.WithTimeout(context.Background(), wgSaveTimeout)
					_ = persistWG(ctx, req.iface, req.confPath)
					cancel()
				case <-wgSaveStopCh:
					return
				}
			}
		}()

		go func() {
			pending := make(map[string]wgSaveRequest)
			var timer *time.Timer
			for {
				if timer == nil {
					select {
					case req := <-wgSaveCh:
						pending[req.iface] = req
						timer = time.NewTimer(wgSaveDebounce)
					case <-wgSaveStopCh:
						return
					}
					continue
				}

				select {
				case req := <-wgSaveCh:
					pending[req.iface] = req
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(wgSaveDebounce)
				case <-timer.C:
					for _, req := range pending {
						wgSaveQueueCh <- req
					}
					for k := range pending {
						delete(pending, k)
					}
					timer = nil
				case <-wgSaveStopCh:
					if timer != nil {
						timer.Stop()
					}
					return
				}
			}
		}()
	})
}

func stopWGSaver() {
	if wgSaveStopCh == nil {
		return
	}
	select {
	case <-wgSaveStopCh:
		return
	default:
		close(wgSaveStopCh)
	}
}

func scheduleWGPersist(iface string, confPath string) {
	if strings.TrimSpace(confPath) == "" {
		return
	}
	startWGSaver()
	select {
	case wgSaveCh <- wgSaveRequest{iface: iface, confPath: confPath}:
	default:
		select {
		case <-wgSaveCh:
		default:
		}
		select {
		case wgSaveCh <- wgSaveRequest{iface: iface, confPath: confPath}:
		default:
			logJSON("warn", "wg_save_queue_full", logFields{"iface": iface})
		}
	}
}

func persistWG(ctx context.Context, iface string, confPath string) error {
	if strings.TrimSpace(confPath) == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, "wg-quick", "save", iface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logJSON("error", "wg_save_failed", logFields{
			"iface":    iface,
			"confPath": confPath,
			"err":      err.Error(),
			"out":      string(out),
		})
		return fmt.Errorf("wg-quick save failed: %v", err)
	}
	logJSON("info", "wg_save_ok", logFields{"iface": iface, "confPath": confPath})
	return nil
}

func updatewg(ctx context.Context, conf *upconf, iface string) error {
	if err := ValidatePeer(conf); err != nil {
		logJSON("warn", "peer_validation_failed", logFields{
			"user":        conf.username,
			"ip":          conf.userip,
			"pubkey_hash": pubKeyHash(conf.userpublic),
			"err":         err.Error(),
		})
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if conf.status {
		args := []string{
			"set", iface,
			"peer", conf.userpublic,
			"allowed-ips", conf.userip,
		}
		if strings.TrimSpace(conf.keeptime) != "" {
			args = append(args, "persistent-keepalive", conf.keeptime)
		}
		cmd := exec.CommandContext(ctx, "wg", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			logJSON("error", "wg_add_failed", logFields{
				"user":        conf.username,
				"ip":          conf.userip,
				"pubkey_hash": pubKeyHash(conf.userpublic),
				"err":         err.Error(),
				"out":         string(out),
			})
			return fmt.Errorf("add peer failed: %v", err)
		}
		logJSON("info", "wg_add_ok", logFields{"user": conf.username, "ip": conf.userip})
		scheduleWGPersist(iface, conf.wgconfpath)
	} else {
		cmd := exec.CommandContext(
			ctx,
			"wg", "set", iface,
			"peer", conf.userpublic,
			"remove",
		)

		out, err := cmd.CombinedOutput()
		if err != nil {
			logJSON("error", "wg_remove_failed", logFields{
				"user":        conf.username,
				"pubkey_hash": pubKeyHash(conf.userpublic),
				"err":         err.Error(),
				"out":         string(out),
			})
			return fmt.Errorf("remove peer failed: %v", err)
		}

		logJSON("info", "wg_remove_ok", logFields{"user": conf.username})
		scheduleWGPersist(iface, conf.wgconfpath)
	}

	return nil
}
