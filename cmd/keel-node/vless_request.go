//go:build vless

package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// checkVLESSRequest reads the start of a VLESS request (version, UUID and the
// addons block) and rejects addons whose field lengths run past the block.
// sing-vmess parses the addons before it looks at the UUID and allocates
// whatever length a field claims, so a crafted request would panic the node
// for anyone holding the Reality parameters, not only valid users. It
// returns the bytes read, to be replayed in front of the connection.
func checkVLESSRequest(conn net.Conn) ([]byte, error) {
	head := make([]byte, 18) // version, UUID, addons length
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	addons := make([]byte, head[17])
	if _, err := io.ReadFull(conn, addons); err != nil {
		return nil, err
	}
	if err := checkAddons(addons); err != nil {
		return nil, err
	}
	return append(head, addons...), nil
}

var errBadAddons = errors.New("malformed vless addons")

// checkAddons accepts only length-delimited protobuf fields that fit.
func checkAddons(b []byte) error {
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 || tag&7 != 2 {
			return errBadAddons
		}
		b = b[n:]
		size, n := binary.Uvarint(b)
		if n <= 0 || size > uint64(len(b)-n) {
			return errBadAddons
		}
		b = b[n+int(size):]
	}
	return nil
}
