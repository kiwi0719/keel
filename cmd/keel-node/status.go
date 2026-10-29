package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"runtime/debug"
	"sort"
	"time"
)

const statusInterval = 5 * time.Second

// NodeStatus is written to status.json next to the config every
// statusInterval for `agent` (see agent.go). It holds no secrets.
type NodeStatus struct {
	Version   string           `json:"version"`
	Built     string           `json:"built,omitempty"` // commit time, RFC 3339
	Protocols string           `json:"protocols"`
	PID       int              `json:"pid"`
	Started   int64            `json:"started"`
	Updated   int64            `json:"updated"`
	RSS       uint64           `json:"rss"`
	Master    *MasterState     `json:"master,omitempty"`
	ConfigRev int64            `json:"config_rev"`
	Inbounds  []InboundStatus  `json:"inbounds"`
	Outbounds []OutboundStatus `json:"outbounds,omitempty"`
	Certs     []CertStatus     `json:"certs,omitempty"`
	Users     int              `json:"users"`
	Blocked   int              `json:"blocked"`
	Conns     int              `json:"conns"`
	Probes    []ProbeResult    `json:"probes,omitempty"`
}

// MasterState is the connection to the master.
type MasterState struct {
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Connected   bool   `json:"connected"`
	Since       int64  `json:"since"` // when it connected or last failed
	Error       string `json:"error,omitempty"`
	LastReport  int64  `json:"last_report,omitempty"`
}

type InboundStatus struct {
	Type        string   `json:"type"`
	Listen      string   `json:"listen"`
	Running     bool     `json:"running"`
	Error       string   `json:"error,omitempty"`
	ServerName  string   `json:"server_name,omitempty"`  // anytls
	ServerNames []string `json:"server_names,omitempty"` // reality
	ACME        bool     `json:"acme,omitempty"`
}

func (n *node) status(master, fingerprint string) NodeStatus {
	s := NodeStatus{
		Version: version, Built: buildTime(), Protocols: builtProtocols(),
		PID: os.Getpid(), Started: n.started.Unix(), Updated: time.Now().Unix(),
		ConfigRev: n.rev(), Certs: certStatuses(), Probes: n.prober.latest(),
		Inbounds: []InboundStatus{},
	}
	s.RSS = readKeyValues("/proc/self/status")["VmRSS"] * 1024
	if master != "" {
		state := MasterState{URL: master, Error: "connecting"}
		if p := n.masterState.Load(); p != nil {
			state = *p
		}
		state.URL, state.Fingerprint, state.LastReport = master, fingerprint, n.lastReport.Load()
		s.Master = &state
	}
	if r := currentRouter.Load(); r != nil {
		s.Outbounds = r.outboundStatus()
	}
	if c := n.config.Load(); c != nil {
		n.mu.Lock()
		for _, in := range c.Inbounds {
			status := InboundStatus{Type: in.Type, Listen: in.Listen, ServerName: in.ServerName, ACME: in.ACME != nil}
			if in.Reality != nil {
				status.ServerNames = in.Reality.ServerNames
			}
			_, status.Running = n.running[in.ID()]
			status.Error = n.failed[in.ID()]
			s.Inbounds = append(s.Inbounds, status)
		}
		n.mu.Unlock()
		sort.SliceStable(s.Inbounds, func(i, j int) bool { return s.Inbounds[i].Listen < s.Inbounds[j].Listen })
	}
	for _, u := range n.users.usage() {
		s.Users++
		s.Conns += u.Conns
		if u.Blocked {
			s.Blocked++
		}
	}
	return s
}

func (n *node) writeStatus(ctx context.Context, path, master, fingerprint string) {
	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()
	for {
		content, _ := json.MarshalIndent(n.status(master, fingerprint), "", "  ")
		// Rewritten every few seconds and only read by `agent`: no fsync.
		if err := replaceFile(path, content, 0o644, false); err != nil {
			log.Print("status: ", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "+dirty"
			}
		}
	}
	if len(rev) < 7 {
		return "dev"
	}
	return rev[:7] + dirty
}

// buildTime is the commit time of the source the binary was built from.
func buildTime() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.time" {
				return s.Value
			}
		}
	}
	return ""
}
