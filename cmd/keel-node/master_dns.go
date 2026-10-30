package main

import (
	"context"
	"errors"
	"sync"
)

// masterDNS asks the master to publish or remove the DNS-01 TXT record for
// this node's ACME domain. The master holds the Cloudflare token and only
// touches _acme-challenge.<this node's AnyTLS name>, so a compromised node
// cannot edit anything else in the zone.
var masterDNS = &dnsRequester{pending: make(map[int64]chan string)}

type dnsRequester struct {
	mu      sync.Mutex
	send    func(any) error // nil while the master is not connected
	next    int64
	pending map[int64]chan string
}

type acmeDNSMessage struct {
	Type   string `json:"type"`
	ID     int64  `json:"id"`
	Op     string `json:"op"` // "set" or "clear"
	Domain string `json:"domain"`
	Value  string `json:"value,omitempty"`
}

var errNoMaster = errors.New("acme dns: not connected to the master")

// attach is called when a session starts, detach when it ends.
func (d *dnsRequester) attach(send func(any) error) {
	d.mu.Lock()
	d.send = send
	d.mu.Unlock()
}

func (d *dnsRequester) detach() {
	d.mu.Lock()
	d.send = nil
	for id, ch := range d.pending {
		ch <- errNoMaster.Error()
		delete(d.pending, id)
	}
	d.mu.Unlock()
}

// call sends one request and waits for the master's answer.
func (d *dnsRequester) call(ctx context.Context, op, domain, value string) error {
	d.mu.Lock()
	if d.send == nil {
		d.mu.Unlock()
		return errNoMaster
	}
	d.next++
	id, send := d.next, d.send
	ch := make(chan string, 1)
	d.pending[id] = ch
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.pending, id)
		d.mu.Unlock()
	}()
	if err := send(acmeDNSMessage{Type: "acme_dns", ID: id, Op: op, Domain: domain, Value: value}); err != nil {
		return err
	}
	select {
	case msg := <-ch:
		if msg != "" {
			return errors.New("acme dns: " + msg)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// done delivers the master's answer to a request.
func (d *dnsRequester) done(id int64, errMsg string) {
	d.mu.Lock()
	ch := d.pending[id]
	delete(d.pending, id)
	d.mu.Unlock()
	if ch != nil {
		ch <- errMsg
	}
}
