// keel-node: one process per server that serves AnyTLS, VLESS Reality and
// Shadowsocks 2022 for many users, counts traffic per user and enforces quota
// and expiry locally.
//
// It skips the sing-box framework (router, DNS, rules, cache) and wires the
// protocol libraries straight to direct TCP/UDP dialing, so the binary and its
// runtime footprint stay small. Protocols are picked at build time:
//
//	go build -tags anytls,vless,ss ./cmd/keel-node
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var verbose bool

const (
	configRecheck = 2 * time.Second
	quotaRecheck  = time.Second
	saveInterval  = 10 * time.Second
)

func main() {
	configPath := flag.String("c", "/etc/keel/node.json", "config file, reloaded when it changes")
	statePath := flag.String("state", "/var/lib/keel/usage.json", "where per-user traffic counters are kept across restarts")
	flag.BoolVar(&verbose, "v", false, "log every connection")
	flag.Parse()
	log.Print("keel-node protocols: ", builtProtocols())

	n := &node{users: newRegistry(*statePath), running: make(map[string]*runningInbound)}
	n.handler = &handler{users: n.users}
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if err = n.reload(config); err != nil {
		log.Fatal(err)
	}
	configStat, _ := os.Stat(*configPath)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)
	configTicker := time.NewTicker(configRecheck)
	quotaTicker := time.NewTicker(quotaRecheck)
	saveTicker := time.NewTicker(saveInterval)
	for {
		select {
		case sig := <-signals:
			switch sig {
			case syscall.SIGHUP:
				n.reloadFile(*configPath)
				continue
			case syscall.SIGUSR1:
				if err := n.users.save(); err != nil {
					log.Print("save usage: ", err)
				}
				continue
			}
			n.shutdown()
			return
		case <-configTicker.C:
			stat, err := os.Stat(*configPath)
			if err != nil || (configStat != nil && stat.ModTime().Equal(configStat.ModTime()) && stat.Size() == configStat.Size()) {
				continue
			}
			configStat = stat
			n.reloadFile(*configPath)
		case now := <-quotaTicker.C:
			if n.users.check(now) {
				n.pushUsers()
			}
		case <-saveTicker.C:
			if err := n.users.save(); err != nil {
				log.Print("save usage: ", err)
			}
			if verbose {
				for _, u := range n.users.usage() {
					log.Printf("usage %s up=%d down=%d conns=%d blocked=%v", u.Name, u.Up, u.Down, u.Conns, u.Blocked)
				}
			}
		}
	}
}

type node struct {
	mu      sync.Mutex
	running map[string]*runningInbound
	users   *registry
	handler *handler
}

type runningInbound struct {
	config InboundConfig
	inbound
}

func (n *node) reloadFile(path string) {
	config, err := loadConfig(path)
	if err != nil {
		log.Print("reload: ", err, " (keeping current config)")
		return
	}
	if err = n.reload(config); err != nil {
		log.Print("reload: ", err, " (keeping current config)")
		return
	}
	log.Print("reloaded ", path)
}

// reload applies a new config. Listeners whose settings did not change keep
// running; changed or removed ones stop accepting, but connections already
// established on them continue.
func (n *node) reload(config *Config) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := newRouter(config, currentRouter.Load())
	if err != nil {
		return err
	}
	currentRouter.Store(r)
	n.users.apply(config.Users)
	active := n.users.active()

	wanted := make(map[string]InboundConfig, len(config.Inbounds))
	for _, c := range config.Inbounds {
		wanted[c.ID()] = c
	}
	for key, r := range n.running {
		if c, ok := wanted[key]; !ok || !c.equal(r.config) {
			r.close()
			delete(n.running, key)
			log.Print("stopped ", key)
		}
	}
	for _, c := range config.Inbounds {
		key := c.ID()
		if r, ok := n.running[key]; ok {
			if err := r.updateUsers(active); err != nil {
				log.Print(key, ": update users: ", err)
			}
			continue
		}
		in, err := protocols[c.Type](c, n.handler)
		if err != nil {
			log.Print(key, ": ", err)
			continue
		}
		if err = in.updateUsers(active); err != nil {
			log.Print(key, ": update users: ", err)
		}
		n.running[key] = &runningInbound{config: c, inbound: in}
		log.Print("started ", key)
	}
	return nil
}

// pushUsers re-sends the active user list after quota or expiry changed it.
func (n *node) pushUsers() {
	n.mu.Lock()
	defer n.mu.Unlock()
	active := n.users.active()
	for key, r := range n.running {
		if err := r.updateUsers(active); err != nil {
			log.Print(key, ": update users: ", err)
		}
	}
}

func (n *node) shutdown() {
	n.mu.Lock()
	for _, r := range n.running {
		r.close()
	}
	n.mu.Unlock()
	if err := n.users.save(); err != nil {
		log.Print("save usage: ", err)
	}
}

// stdLogger adapts the standard logger to sing's logger interface.
type stdLogger struct{}

func (stdLogger) Trace(...any) {}
func (stdLogger) Debug(...any) {}
func (stdLogger) Info(args ...any) {
	if verbose {
		log.Print(args...)
	}
}
func (stdLogger) Warn(args ...any)  { log.Print(args...) }
func (stdLogger) Error(args ...any) { log.Print(args...) }
func (stdLogger) Fatal(args ...any) { log.Fatal(args...) }
func (stdLogger) Panic(args ...any) { log.Panic(args...) }

func (l stdLogger) TraceContext(_ context.Context, args ...any) {}
func (l stdLogger) DebugContext(_ context.Context, args ...any) {}
func (l stdLogger) InfoContext(_ context.Context, args ...any)  { l.Info(args...) }
func (l stdLogger) WarnContext(_ context.Context, args ...any)  { l.Warn(args...) }
func (l stdLogger) ErrorContext(_ context.Context, args ...any) { l.Error(args...) }
func (l stdLogger) FatalContext(_ context.Context, args ...any) { l.Fatal(args...) }
func (l stdLogger) PanicContext(_ context.Context, args ...any) { l.Panic(args...) }
