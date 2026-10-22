package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
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
	saved     map[string]savedUsage // loaded from statePath, consumed by apply
}

type savedUsage struct {
	Period string `json:"period"`
	Up     int64  `json:"up"`
	Down   int64  `json:"down"`
}

type usageFile struct {
	Users map[string]savedUsage `json:"users"`
}

func newRegistry(statePath string) *registry {
	r := &registry{users: make(map[string]*userState), statePath: statePath}
	if statePath != "" {
		content, err := os.ReadFile(statePath)
		if err == nil {
			var file usageFile
			if err = json.Unmarshal(content, &file); err != nil {
				log.Print("usage state: ", err)
			}
			r.saved = file.Users
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
		} else if u.cfg.Period != cfg.Period {
			u.up.Store(0)
			u.down.Store(0)
		}
		u.cfg = cfg
		next[cfg.Name] = u
	}
	var removed []*userState
	for name, u := range r.users {
		if _, ok := next[name]; !ok {
			removed = append(removed, u)
		}
	}
	r.users = next
	r.saved = nil
	r.mu.Unlock()
	for _, u := range removed {
		if n := u.closeAll(); n > 0 {
			log.Printf("user %s removed, closed %d connections", u.name, n)
		}
	}
	r.check(time.Now())
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
	for _, u := range r.usage() {
		file.Users[u.Name] = savedUsage{Period: u.Period, Up: u.Up, Down: u.Down}
	}
	content, err := json.Marshal(file)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(r.statePath), 0o700); err != nil {
		return err
	}
	tmp := r.statePath + ".tmp"
	if err = os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.statePath)
}
