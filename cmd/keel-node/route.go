package main

import (
	"bufio"
	"io"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// ruleList is a set of destinations used by one routing rule.
//
// Format, one entry per line ('#' starts a comment):
//
//	example.com       matches example.com and any subdomain
//	=api.example.com  matches that exact name only
//	~emby             matches any name containing "emby"
//	91.108.4.0/22     matches IP destinations in that range
//
// Entries come from a file, which is re-read automatically when its
// modification time changes, and/or from an inline list in the config.
type ruleList struct {
	path   string
	inline []string

	mu       sync.Mutex
	suffix   map[string]bool
	exact    map[string]bool
	keywords []string
	prefixes []netip.Prefix
	modTime  time.Time
	checked  time.Time
}

const ruleListRecheck = time.Minute

func newRuleList(path string, inline []string) *ruleList {
	l := &ruleList{path: path, inline: inline}
	l.mu.Lock()
	l.reloadLocked(true)
	l.mu.Unlock()
	return l
}

func (l *ruleList) reloadLocked(force bool) {
	l.checked = time.Now()
	var file io.Reader
	var modTime time.Time
	if l.path != "" {
		info, err := os.Stat(l.path)
		if err != nil {
			if force {
				log.Print("rule list: ", err)
			}
			return
		}
		if !force && info.ModTime().Equal(l.modTime) {
			return
		}
		f, err := os.Open(l.path)
		if err != nil {
			log.Print("rule list: ", err)
			return
		}
		defer f.Close()
		file, modTime = f, info.ModTime()
	} else if !force {
		return
	}
	suffix, exact := map[string]bool{}, map[string]bool{}
	var keywords []string
	var prefixes []netip.Prefix
	add := func(line string) {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			return
		}
		switch {
		case strings.HasPrefix(line, "="):
			exact[strings.TrimSuffix(line[1:], ".")] = true
		case strings.HasPrefix(line, "~"):
			keywords = append(keywords, line[1:])
		default:
			if prefix, err := netip.ParsePrefix(line); err == nil {
				prefixes = append(prefixes, prefix.Masked())
			} else if addr, err := netip.ParseAddr(line); err == nil {
				prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			} else {
				suffix[strings.TrimSuffix(strings.TrimPrefix(line, "."), ".")] = true
			}
		}
	}
	for _, line := range l.inline {
		add(line)
	}
	if file != nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			add(scanner.Text())
		}
	}
	l.suffix, l.exact, l.keywords, l.prefixes, l.modTime = suffix, exact, keywords, prefixes, modTime
	if l.path != "" {
		log.Printf("rule list: loaded %d suffix + %d exact + %d keyword + %d ip entries from %s", len(suffix), len(exact), len(keywords), len(prefixes), l.path)
	}
}

// match reports whether destination is on the list. Domain entries match
// domain destinations, IP entries match IP destinations.
func (l *ruleList) match(destination M.Socksaddr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.path != "" && time.Since(l.checked) > ruleListRecheck {
		l.reloadLocked(false)
	}
	if !destination.IsFqdn() {
		addr := destination.Addr.Unmap()
		for _, prefix := range l.prefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(destination.Fqdn, "."))
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

// sameSource reports whether l was built from the same file and inline
// entries, so a reload can keep it instead of re-reading the file.
func (l *ruleList) sameSource(path string, inline []string) bool {
	if l.path != path || len(l.inline) != len(inline) {
		return false
	}
	for i := range inline {
		if l.inline[i] != inline[i] {
			return false
		}
	}
	return true
}
