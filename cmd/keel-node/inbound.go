package main

import (
	"errors"
	"log"
	"net"
	"sort"
	"strings"
)

// inbound is one running listener of one protocol.
type inbound interface {
	// updateUsers replaces the users allowed on this listener without
	// touching established connections.
	updateUsers(users []UserConfig) error
	// close stops accepting; established connections keep running.
	close() error
}

type protocolFactory func(config InboundConfig, h *handler) (inbound, error)

// protocols holds the protocols built into this binary; each proto_*.go file
// registers itself under its build tag.
var protocols = map[string]protocolFactory{}

func builtProtocols() string {
	names := make([]string, 0, len(protocols))
	for name := range protocols {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

// acceptLoop hands each accepted connection to serve in its own goroutine
// until the listener is closed.
func acceptLoop(listener net.Listener, serve func(net.Conn)) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if !errors.Is(err, net.ErrClosed) {
				log.Print("accept on ", listener.Addr(), ": ", err)
			}
			return
		}
		go serve(conn)
	}
}
