package main

import (
	"context"
	"io"
	"log"
	"net"
	"runtime/debug"
	"sync"
	"time"
)

// handshakeTimeout bounds how long a client may take, from connecting until
// its first proxied request reaches the handler. Without it a silent client
// holds a goroutine and a file descriptor forever.
const handshakeTimeout = 30 * time.Second

// recoverConn keeps a panic in one connection from killing every listener
// and user on the node. Protocol code runs on client bytes before the user
// is known, so a parser bug must cost one connection, not the process.
func recoverConn(what string, conn io.Closer) {
	if r := recover(); r != nil {
		conn.Close()
		log.Printf("%s: panic: %v\n%s", what, r, debug.Stack())
	}
}

type deadlineKey struct{}

// withHandshakeDeadline sets a deadline on the raw connection and returns a
// context that lets the handler lift it once a request is authenticated.
func withHandshakeDeadline(ctx context.Context, conn net.Conn) context.Context {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	return context.WithValue(ctx, deadlineKey{}, conn)
}

// clearHandshakeDeadline lifts the deadline set by withHandshakeDeadline.
func clearHandshakeDeadline(ctx context.Context) {
	if conn, ok := ctx.Value(deadlineKey{}).(net.Conn); ok {
		conn.SetDeadline(time.Time{})
	}
}

type sessionKey struct{}

// session is one client connection that may carry many proxied streams
// (an AnyTLS session, a VLESS mux connection). It is tracked under its user
// once the first stream arrives, so removing or blocking the user closes the
// whole session, not only the streams open at that moment.
type session struct {
	mu      sync.Mutex
	conn    io.Closer
	untrack func()
}

func withSession(ctx context.Context, conn io.Closer) (context.Context, *session) {
	s := &session{conn: conn}
	return context.WithValue(ctx, sessionKey{}, s), s
}

func trackSession(ctx context.Context, u *userState) {
	s, ok := ctx.Value(sessionKey{}).(*session)
	if !ok {
		return
	}
	s.mu.Lock()
	if s.untrack == nil {
		s.untrack = u.track(s.conn)
	}
	s.mu.Unlock()
}

// end stops tracking the session once its connection is done.
func (s *session) end() {
	s.mu.Lock()
	if s.untrack != nil {
		s.untrack()
	}
	s.mu.Unlock()
}
