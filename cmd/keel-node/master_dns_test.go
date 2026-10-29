package main

import (
	"context"
	"testing"
	"time"
)

func TestMasterDNSRoundTrip(t *testing.T) {
	d := &dnsRequester{pending: make(map[int64]chan string)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := d.call(ctx, "set", "a.example.com", "v"); err != errNoMaster {
		t.Fatalf("without a master: %v", err)
	}
	var got acmeDNSMessage
	d.attach(func(v any) error {
		got = v.(acmeDNSMessage)
		go d.done(got.ID, "")
		return nil
	})
	if err := d.call(ctx, "set", "a.example.com", "v"); err != nil || got.Op != "set" || got.Domain != "a.example.com" {
		t.Fatalf("set: %v %+v", err, got)
	}
	d.attach(func(v any) error {
		go d.done(v.(acmeDNSMessage).ID, "refused")
		return nil
	})
	if err := d.call(ctx, "set", "b.example.com", "v"); err == nil {
		t.Fatal("a refusal from the master must fail the challenge")
	}
}
