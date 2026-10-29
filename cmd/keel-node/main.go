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
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var verbose bool

const (
	configRecheck = 2 * time.Second
	quotaRecheck  = 250 * time.Millisecond // over-quota traffic is cut within this
	// Shorter than the service's restart delay, so a crash loop cannot
	// keep throwing away usage.
	saveInterval = 2 * time.Second
)

func main() {
	if version == "" {
		version = buildVersion()
	}
	if filepath.Base(os.Args[0]) == "agent" || len(os.Args) > 1 && os.Args[1] == "agent" {
		args := os.Args[1:]
		if len(args) > 0 && args[0] == "agent" {
			args = args[1:]
		}
		os.Exit(agentMain(args))
	}
	configPath := flag.String("c", "/etc/keel/node.json", "config file, reloaded when it changes; with -master it caches the master's config")
	statePath := flag.String("state", "/var/lib/keel/usage.json", "where per-user traffic counters are kept across restarts")
	master := flag.String("master", "", "master address, e.g. https://panel.example.com:8443; the node connects out to it")
	token := flag.String("token", "", "this node's token on the master (or env KEEL_TOKEN)")
	fingerprint := flag.String("fingerprint", "", "hex SHA-256 of the master's certificate; when set it replaces CA verification")
	flag.BoolVar(&verbose, "v", false, "log every connection")
	flag.Parse()
	log.Print("keel-node ", version, " protocols: ", builtProtocols())
	setMemoryLimit()

	certDir = filepath.Dir(*configPath)
	n := &node{users: newRegistry(*statePath), running: make(map[string]*runningInbound), prober: newProber(), started: time.Now()}
	n.handler = &handler{users: n.users}
	config, err := loadConfig(*configPath, *master == "")
	n.strict = *master == ""
	switch {
	case err == nil:
	case *master != "" && errors.Is(err, os.ErrNotExist):
		log.Print("no cached config yet, waiting for the master")
		config = &Config{}
	default:
		log.Fatal(err)
	}
	n.users.restoreUsage(config)
	if err = n.reload(config); err != nil {
		log.Fatal(err)
	}
	configStat, _ := os.Stat(*configPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.prober.run(ctx)
	go runHealthChecks(ctx)
	masterConfigs := make(chan masterConfig)
	if *master != "" {
		if *token == "" {
			*token = os.Getenv("KEEL_TOKEN")
		}
		wsURL, err := masterWebSocketURL(*master)
		if err != nil {
			log.Fatal(err)
		}
		pin, err := parseFingerprint(*fingerprint)
		if err != nil {
			log.Fatal(err)
		}
		if *token == "" {
			log.Fatal("-master needs -token or KEEL_TOKEN")
		}
		client := &masterClient{url: wsURL, token: *token, pin: pin, node: n, configs: masterConfigs}
		go client.run(ctx)
	}

	statusPath := filepath.Join(filepath.Dir(*configPath), "status.json")
	go n.writeStatus(ctx, statusPath, *master, *fingerprint)
	defer os.Remove(statusPath)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)
	configTicker := time.NewTicker(configRecheck)
	quotaTicker := time.NewTicker(quotaRecheck)
	saveTicker := time.NewTicker(saveInterval)
	// Saving writes and syncs a file, which can take a while on slow disks;
	// it runs beside this loop so quota checks are never held up by it.
	saveNow := make(chan struct{}, 1)
	go func() {
		for range saveNow {
			if err := n.users.save(); err != nil {
				log.Print("save usage: ", err)
			}
		}
	}()
	requestSave := func() {
		select {
		case saveNow <- struct{}{}:
		default: // one is already pending
		}
	}
	for {
		select {
		case sig := <-signals:
			switch sig {
			case syscall.SIGHUP:
				n.reloadFile(*configPath)
				continue
			case syscall.SIGUSR1:
				requestSave()
				continue
			}
			n.shutdown()
			return
		case mc := <-masterConfigs:
			if mc.revoke {
				n.revoke(*configPath)
				mc.result <- nil
				continue
			}
			if mc.usage != nil {
				if n.users.applyUsage(n.rev(), *mc.usage) {
					if n.users.check(time.Now()) {
						n.pushUsers()
					}
					requestSave()
				}
				mc.result <- nil
				continue
			}
			err := n.applyMaster(mc.content, mc.rev, *configPath)
			if stat, statErr := os.Stat(*configPath); statErr == nil {
				configStat = stat // our own write must not trigger a reload
			}
			mc.result <- err
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
				requestSave()
			}
		case <-saveTicker.C:
			requestSave()
			if verbose {
				for _, u := range n.users.usage() {
					log.Printf("usage %s up=%d down=%d conns=%d blocked=%v", u.Name, u.Up, u.Down, u.Conns, u.Blocked)
				}
			}
		}
	}
}

// applyMaster applies a config pushed by the master and caches it at path,
// so the node comes back with it after a restart even if the master is down.
func (n *node) applyMaster(content []byte, rev int64, path string) error {
	config, err := parseConfig(content, false)
	if err != nil {
		return err
	}
	if rev != 0 && config.Rev != rev {
		// The message's rev wins; keep it in the cached copy so the node
		// reports it again after a restart.
		config.Rev = rev
		var fields map[string]json.RawMessage
		if json.Unmarshal(content, &fields) == nil {
			fields["rev"], _ = json.Marshal(rev)
			if updated, err := json.Marshal(fields); err == nil {
				content = updated
			}
		}
	}
	if err = n.reload(config); err != nil {
		return err
	}
	n.users.forgetUsage()
	if err = writeFileAtomic(path, content, 0o600); err != nil {
		log.Print("cache config: ", err)
	}
	log.Print("applied config rev ", config.Rev, " from master")
	if problems := n.problems(); len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// revoke stops every inbound and drops every user, and removes the cached
// config so a restart does not bring them back: the master has disowned
// this node, and users disabled since can no longer be pushed to it.
func (n *node) revoke(path string) {
	if err := n.reload(&Config{}); err != nil {
		log.Print("revoke: ", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Print("revoke: ", err)
	}
	log.Print("master: token rejected for ", revokeAfter, "; stopped serving. Reinstall the node with a new token to bring it back.")
}

// writeFileAtomic replaces path with content: a new, uniquely named file in
// the same directory (never an existing file or link someone left there),
// flushed to disk before it takes the name, so a crash leaves either the old
// file or the new one, never a truncated one.
func writeFileAtomic(path string, content []byte, perm os.FileMode) error {
	return replaceFile(path, content, perm, true)
}

// replaceFile is writeFileAtomic; without durable it skips the two fsyncs,
// for files that need not survive a crash (status.json).
func replaceFile(path string, content []byte, perm os.FileMode, durable bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once renamed
	if err = f.Chmod(perm); err == nil {
		if _, err = f.Write(content); err == nil && durable {
			err = f.Sync()
		}
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if !durable {
		return nil
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

type node struct {
	strict  bool // config file is hand-written, not a master's cache
	mu      sync.Mutex
	running map[string]*runningInbound
	failed  map[string]string // inbounds of the current config that did not start
	users   *registry
	handler *handler
	prober  *prober
	config  atomic.Pointer[Config]
	// masterState is the master connection, for the status file; nil
	// without -master.
	masterState atomic.Pointer[MasterState]
	lastReport  atomic.Int64 // unix seconds of the last report sent
	started     time.Time
}

// rev is the master revision of the running config (0 for a local file).
func (n *node) rev() int64 {
	if c := n.config.Load(); c != nil {
		return c.Rev
	}
	return 0
}

// problems lists inbounds of the current config that failed to start.
func (n *node) problems() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var list []string
	for key, err := range n.failed {
		list = append(list, key+": "+err)
	}
	sort.Strings(list)
	return list
}

type runningInbound struct {
	config InboundConfig
	inbound
}

func (n *node) reloadFile(path string) {
	config, err := loadConfig(path, n.strict)
	if err != nil {
		log.Print("reload: ", err, " (keeping current config)")
		return
	}
	n.users.restoreUsage(config)
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
	n.config.Store(config)
	n.prober.setTargets(config.Probes, config.Route.IPv4Only, time.Duration(config.ProbeInterval))
	n.failed = make(map[string]string)
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
			n.failed[key] = err.Error()
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
