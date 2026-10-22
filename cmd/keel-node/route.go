package main

import (
	"bufio"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// domainList is a set of domain rules used to steer destinations between the
// SOCKS5 upstream and direct dialing (socks_domains / direct_domains).
//
// File format, one entry per line ('#' starts a comment):
//
//	example.com       matches example.com and any subdomain
//	=api.example.com  matches that exact name only
//	~emby             matches any name containing "emby"
//
// The file is re-read automatically when its modification time changes.
type domainList struct {
	path string

	mu       sync.Mutex
	suffix   map[string]bool
	exact    map[string]bool
	keywords []string
	modTime  time.Time
	checked  time.Time
}

const domainListRecheck = time.Minute

func newDomainList(path string) *domainList {
	l := &domainList{path: path}
	l.mu.Lock()
	l.reloadLocked(true)
	l.mu.Unlock()
	return l
}

func (l *domainList) reloadLocked(force bool) {
	l.checked = time.Now()
	info, err := os.Stat(l.path)
	if err != nil {
		if force {
			log.Print("domain list: ", err)
		}
		return
	}
	if !force && info.ModTime().Equal(l.modTime) {
		return
	}
	f, err := os.Open(l.path)
	if err != nil {
		log.Print("domain list: ", err)
		return
	}
	defer f.Close()
	suffix, exact := map[string]bool{}, map[string]bool{}
	var keywords []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "="):
			exact[strings.TrimSuffix(line[1:], ".")] = true
		case strings.HasPrefix(line, "~"):
			keywords = append(keywords, line[1:])
		default:
			suffix[strings.TrimSuffix(strings.TrimPrefix(line, "."), ".")] = true
		}
	}
	l.suffix, l.exact, l.keywords, l.modTime = suffix, exact, keywords, info.ModTime()
	log.Printf("domain list: loaded %d suffix + %d exact + %d keyword entries from %s", len(suffix), len(exact), len(keywords), l.path)
}

// match reports whether destination's domain is on the list. IP destinations
// never match (clients normally send domain names, which is what we route on).
func (l *domainList) match(destination M.Socksaddr) bool {
	if !destination.IsFqdn() {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(destination.Fqdn, "."))
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.checked) > domainListRecheck {
		l.reloadLocked(false)
	}
	if l.exact[name] {
		return true
	}
	for _, k := range l.keywords {
		if strings.Contains(name, k) {
			return true
		}
	}
	for d := name; d != ""; {
		if l.suffix[d] {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return false
}

// viaUpstream decides whether a destination should use the SOCKS5 upstream:
// direct_domains always wins, then socks_domains (if set) limits the upstream
// to its entries; otherwise everything goes through the upstream.
func (o *outbound) viaUpstream(destination M.Socksaddr) bool {
	if o.upstream == nil {
		return false
	}
	if o.directDomains != nil && o.directDomains.match(destination) {
		return false
	}
	if o.upstreamDomains != nil {
		return o.upstreamDomains.match(destination)
	}
	return true
}
