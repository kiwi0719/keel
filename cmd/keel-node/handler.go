package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

var errUserInactive = errors.New("user removed, expired or over quota")

// user returns the authenticated user if it may still use the node. Checked
// per connection, so a multiplexed session (AnyTLS, XUDP) cannot open new
// streams after its user is blocked.
func (h *handler) user(ctx context.Context) *userState {
	name, ok := auth.UserFromContext[string](ctx)
	if !ok {
		return nil
	}
	return h.users.lookup(name)
}

// handler receives every proxied connection from every inbound. The inbound
// has already authenticated the user and put the name in the context.
type handler struct {
	users *registry
}

func (h *handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer recoverConn("handler", conn)
	clearHandshakeDeadline(ctx)
	user := h.user(ctx)
	if user == nil {
		N.CloseOnHandshakeFailure(conn, onClose, errUserInactive)
		return
	}
	if user.full() {
		N.CloseOnHandshakeFailure(conn, onClose, errTooManyConns)
		return
	}
	trackSession(ctx, user)
	untrack := user.track(conn)
	defer untrack()
	defer N.CloseOnHandshakeFailure(conn, onClose, nil)
	defer conn.Close()
	conn = bufio.NewInt64CounterConn(conn, []*atomic.Int64{&user.up}, []*atomic.Int64{&user.down})

	r := currentRouter.Load()
	destination = destination.Unwrap()
	switch destination.Fqdn {
	case uot.MagicAddress:
		request, err := uot.ReadRequest(conn)
		if err != nil {
			N.ReportHandshakeFailure(conn, err)
			return
		}
		r.relayUDP(ctx, user.name, uot.NewConn(conn, *request), conn, request.Destination)
	case uot.LegacyMagicAddress:
		r.relayUDP(ctx, user.name, uot.NewConn(conn, uot.Request{}), conn, M.Socksaddr{})
	default:
		r.relayTCP(ctx, user.name, conn, destination)
	}
}

func (h *handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer recoverConn("handler", conn)
	clearHandshakeDeadline(ctx)
	user := h.user(ctx)
	if user == nil {
		N.CloseOnHandshakeFailure(conn, onClose, errUserInactive)
		return
	}
	if user.full() {
		N.CloseOnHandshakeFailure(conn, onClose, errTooManyConns)
		return
	}
	trackSession(ctx, user)
	untrack := user.track(conn)
	defer untrack()
	defer N.CloseOnHandshakeFailure(conn, onClose, nil)
	defer conn.Close()
	conn = bufio.NewInt64CounterPacketConn(conn, []*atomic.Int64{&user.up}, nil, []*atomic.Int64{&user.down}, nil)
	currentRouter.Load().relayUDP(ctx, user.name, conn, nil, destination.Unwrap())
}
