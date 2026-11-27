// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestSambaTransportVerifiesOwnedListenerAndDrainsClients(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.21")
	encoded := fmt.Sprintf("%08X", binary.NativeEndian.Uint32(address.AsSlice()))
	row := func(local string, port int, state string, inode uint64) string {
		return fmt.Sprintf("0: %s:%04X 00000000:0000 %s 0:0 0:0 0 0 0 %d\n", local, port, state, inode)
	}
	owned := map[uint64]struct{}{5: {}, 6: {}}
	listener := row(encoded, 445, "0A", 5)
	for _, test := range []struct {
		name, table, rows string
		listener          uint64
		idle              bool
		err               error
	}{
		{"owned IPv4", "tcp", listener, 5, true, nil},
		{"live connection", "tcp", listener + row(encoded, 445, "01", 7), 5, false, nil},
		{"expired connection", "tcp", listener + row(encoded, 445, "06", 0), 5, true, nil},
		{"unrelated port", "tcp", row(encoded, 446, "0A", 7), 0, true, nil},
		{"occupied", "tcp", row(encoded, 445, "0A", 7), 0, false, ErrBusy},
		{"wildcard", "tcp", row("00000000", 445, "0A", 5), 0, false, ErrBusy},
		{"double listen", "tcp", listener + row(encoded, 445, "0A", 6), 0, false, ErrBusy},
		{"IPv6 listener", "tcp6", listener, 0, false, ErrBusy},
		{"UDP listener", "udp", listener, 0, false, ErrBusy},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := strings.NewReader("  sl local_address rem_address st\n" + test.rows)
			inode, idle, err := scanSambaTransport(context.Background(), source, test.table, address, owned)
			if inode != test.listener || idle != test.idle || !errors.Is(err, test.err) {
				t.Fatalf("listener=%d idle=%t error=%v", inode, idle, err)
			}
		})
	}
}
