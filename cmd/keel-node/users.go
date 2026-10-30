package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// userState is one user's live counters and open connections on this node.
type userState struct {
	name string
	cfg  UserConfig // guarded by registry.mu

	up   atomic.Int64 // bytes from the client, this period
	down atomic.Int64 // bytes to the client, this period

	blocked atomic.Bool // over quota or expired

	connMu sync.Mutex
	conns  map[io.Closer]struct{}
}

func (u *userState) used() int64 {
	return u.cfg.UsedBase + u.up.Load() + u.down.Load()
}

// maxUserConns caps one user's open connections, streams and UDP sessions
// on this node, so a single user cannot use up its memory or descriptors.
var maxUserConns = 2048

var errTooManyConns = errors.New("too many open connections for this user")

// track registers an open connection so it can be closed when the user is
// removed or runs out of quota. The returned func unregisters it.
func (u *userState) track(conn io.Closer) func() {
	u.connMu.Lock()
	u.conns[conn] = struct{}{}
	u.connMu.Unlock()
	return func() {
		u.connMu.Lock()
		delete(u.conns, conn)
		u.connMu.Unlock()
	}
}

// full reports whether the user may not open another connection.
func (u *userState) full() bool {
	u.connMu.Lock()
	defer u.connMu.Unlock()
	return len(u.conns) >= maxUserConns
}

func (u *userState) closeAll() int {
	u.connMu.Lock()
	conns := u.conns
	u.conns = make(map[io.Closer]struct{})
	u.connMu.Unlock()
	for conn := range conns {
		conn.Close()
	}
	return len(conns)
}

// registry holds every configured user, enforces quota and expiry locally
// (so limits still apply while the master is unreachable), and persists the
// counters so a restart does not reset them.
type registry struct {
	mu    sync.RWMutex
	users map[string]*userState

	statePath string
	saveMu    sync.Mutex
	lastSaved []byte // what the last successful save wrote
	// Usage messages (guarded by mu): the config rev they were for, and the
	// used_base they set per user.
	usageRev int64
	base     map[string]int64
	// saved holds counters of users not configured right now: loaded from
	// statePath, or kept when a user is removed, so taking a user off and
	// putting them back within a period does not reset what they used.
	saved map[string]savedUsage
}

type savedUsage struct {
	Period string `json:"period"`
	Up     int64  `json:"up"`
	Down   int64  `json:"down"`
}

type usageFile struct {
	Users map[string]savedUsage `json:"users"`
	// The used_base figures of the master's latest usage messages, for the
	// config of rev UsageRev: newer than the ones cached with that config,
	// so a restart without the master keeps limiting by them.
	UsageRev int64            `json:"usage_rev,omitempty"`
	Base     map[string]int64 `json:"base,omitempty"`
}

func newRegistry(statePath string) *registry {
	r := &registry{users: make(map[string]*userState), statePath: statePath, saved: make(map[string]savedUsage)}
	if statePath != "" {
		content, err := os.ReadFile(statePath)
		if err == nil {
			var file usageFile
			if err = json.Unmarshal(content, &file); err != nil {
				log.Print("usage state: ", err)
			}
			if file.Users != nil {
				r.saved = file.Users
			}
			r.usageRev, r.base = file.UsageRev, file.Base
		} else if !os.IsNotExist(err) {
			log.Print("usage state: ", err)
		}
	}
	return r
}

// apply replaces the user list. Existing users keep their counters unless
// their period changed; removed users are disconnected.
func (r *registry) apply(users []UserConfig) {
	r.mu.Lock()
	next := make(map[string]*userState, len(users))
	for _, cfg := range users {
		u, ok := r.users[cfg.Name]
		if !ok {
			u = &userState{name: cfg.Name, conns: make(map[io.Closer]struct{})}
			if s, ok := r.saved[cfg.Name]; ok && s.Period == cfg.Period {
				u.up.Store(s.Up)
				u.down.Store(s.Down)
			}
			delete(r.saved, cfg.Name)
		} else if u.cfg.Period != cfg.Period {
			u.up.Store(0)
			u.down.Store(0)
		}
		// Never count less than the master already has from this node: a
		// crash before the last save must not hand the user free traffic.
		if lost := cfg.UsedSelf - u.up.Load() - u.down.Load(); lost > 0 {
			u.up.Add(lost)
		}
		u.cfg = cfg
		next[cfg.Name] = u
	}
	var removed []*userState
	for name, u := range r.users {
		if _, ok := next[name]; !ok {
			removed = append(removed, u)
			r.saved[name] = savedUsage{Period: u.cfg.Period, Up: u.up.Load(), Down: u.down.Load()}
		}
	}
	r.users = next
	r.mu.Unlock()
	for _, u := range removed {
		if n := u.closeAll(); n > 0 {
			log.Printf("user %s removed, closed %d connections", u.name, n)
		}
	}
	r.check(time.Now())
}

// usageUpdate is one usage message from the master: new used_base and
// used_self figures for some users of the config of rev. The connection
// delivers them in order, after the config they are for.
type usageUpdate struct {
	rev   int64
	users map[string][2]int64 // name -> {used_base, used_self}
}

// applyUsage takes a usage message if it is for the config running now
// (rev); one for another config is dropped. As with a config, used_self only
// ever raises a user's counters, and users not in the config are ignored.
func (r *registry) applyUsage(rev int64, u usageUpdate) bool {
	if rev == 0 || u.rev != rev {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if u.rev != r.usageRev {
		r.usageRev, r.base = u.rev, nil
	}
	for name, figures := range u.users {
		user := r.users[name]
		if user == nil {
			continue
		}
		user.cfg.UsedBase, user.cfg.UsedSelf = figures[0], figures[1]
		if lost := figures[1] - user.up.Load() - user.down.Load(); lost > 0 {
			user.up.Add(lost)
		}
		if r.base == nil {
			r.base = make(map[string]int64)
		}
		r.base[name] = figures[0]
	}
	return true
}

// restoreUsage updates a config read back from disk with the used_base
// figures that usage messages brought for it since it was cached.
func (r *registry) restoreUsage(config *Config) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if config.Rev == 0 || config.Rev != r.usageRev {
		return
	}
	for i := range config.Users {
		if base, ok := r.base[config.Users[i].Name]; ok {
			config.Users[i].UsedBase = base
		}
	}
}

// forgetUsage drops the usage messages' figures: a config just came from the
// master, with figures as new as any.
func (r *registry) forgetUsage() {
	r.mu.Lock()
	r.usageRev, r.base = 0, nil
	r.mu.Unlock()
}

// lookup returns the user if it exists and may still connect.
func (r *registry) lookup(name string) *userState {
	r.mu.RLock()
	u := r.users[name]
	r.mu.RUnlock()
	if u == nil || u.blocked.Load() {
		return nil
	}
	return u
}

// check re-evaluates quota and expiry, disconnects users that just ran out,
// and reports whether the set of blocked users changed.
func (r *registry) check(now time.Time) bool {
	r.mu.RLock()
	var newlyBlocked []*userState
	changed := false
	for _, u := range r.users {
		over := u.cfg.QuotaBytes > 0 && u.used() >= u.cfg.QuotaBytes
		expired := u.cfg.ExpireAt > 0 && now.Unix() >= u.cfg.ExpireAt
		block := over || expired
		if u.blocked.Swap(block) != block {
			changed = true
			if block {
				newlyBlocked = append(newlyBlocked, u)
				reason := "quota used up"
				if expired {
					reason = "expired"
				}
				log.Printf("user %s blocked: %s", u.name, reason)
			} else {
				log.Printf("user %s unblocked", u.name)
			}
		}
	}
	r.mu.RUnlock()
	for _, u := range newlyBlocked {
		u.closeAll()
	}
	return changed
}

// active returns the configs of users that may connect, sorted by name.
func (r *registry) active() []UserConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	users := make([]UserConfig, 0, len(r.users))
	for _, u := range r.users {
		if !u.blocked.Load() {
			users = append(users, u.cfg)
		}
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	return users
}

// UserUsage is one user's traffic for the current period on this node.
type UserUsage struct {
	Name    string `json:"name"`
	Period  string `json:"period"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
	Conns   int    `json:"conns"`
	Blocked bool   `json:"blocked"`
}

func (r *registry) usage() []UserUsage {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]UserUsage, 0, len(r.users))
	for _, u := range r.users {
		u.connMu.Lock()
		conns := len(u.conns)
		u.connMu.Unlock()
		list = append(list, UserUsage{
			Name: u.name, Period: u.cfg.Period,
			Up: u.up.Load(), Down: u.down.Load(),
			Conns: conns, Blocked: u.blocked.Load(),
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

// save writes the counters to statePath atomically.
func (r *registry) save() error {
	if r.statePath == "" {
		return nil
	}
	file := usageFile{Users: make(map[string]savedUsage)}
	r.mu.RLock()
	for name, s := range r.saved {
		file.Users[name] = s
	}
	if len(r.base) > 0 {
		file.UsageRev = r.usageRev
		file.Base = make(map[string]int64, len(r.base))
		for name, b := range r.base {
			file.Base[name] = b
		}
	}
	r.mu.RUnlock()
	for _, u := range r.usage() {
		file.Users[u.Name] = savedUsage{Period: u.Period, Up: u.Up, Down: u.Down}
	}
	content, err := json.Marshal(file)
	if err != nil {
		return err
	}
	// Saved every 2 s; an idle node would otherwise write and fsync the
	// same file over and over.
	r.saveMu.Lock()
	defer r.saveMu.Unlock()
	if bytes.Equal(content, r.lastSaved) {
		return nil
	}
	if err = writeFileAtomic(r.statePath, content, 0o600); err != nil {
		return err
	}
	r.lastSaved = content
	return nil
}
