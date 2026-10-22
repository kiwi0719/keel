package main

import (
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
)

// allowList is the set of source addresses inbounds accept (Config.AllowFrom).
// A nil list accepts everyone.
type allowList []netip.Prefix

var currentAllow atomic.Pointer[allowList]

func parseAllowList(items []string) (*allowList, error) {
	if len(items) == 0 {
		return nil, nil
	}
	list := make(allowList, 0, len(items))
	for _, s := range items {
		s = strings.TrimSpace(s)
		if !strings.Contains(s, "/") {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("allow_from %q: not an IP or CIDR", s)
			}
			s = netip.PrefixFrom(addr, addr.BitLen()).String()
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("allow_from %q: not an IP or CIDR", s)
		}
		list = append(list, p.Masked())
	}
	return &list, nil
}

// allowed reports whether a connection or packet from addr may be served.
func allowed(addr netip.Addr) bool {
	list := currentAllow.Load()
	if list == nil {
		return true
	}
	addr = addr.Unmap()
	for _, p := range *list {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
