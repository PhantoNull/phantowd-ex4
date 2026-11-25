// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"strings"
	"testing"
)

func TestMountTransportObservations(t *testing.T) {
	const (
		header      = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
		ownedMount  = "0: 00000000:4E50 00000000:0000 0A 0:0 0:0 0 0 0 51\n"
		foreign     = "1: 0100007F:4E50 00000000:0000 0A 0:0 0:0 0 0 0 52\n"
		otherPort   = "0: 00000000:4E51 00000000:0000 0A 0:0 0:0 0 0 0 51\n"
		udpMount    = "0: 0100007F:4E50 00000000:0000 07 0:0 0:0 0 0 0 52\n"
		timeWait    = "0: 0100007F:4E50 0100007F:4100 06 0:0 0:0 0 0 0 0\n"
		kernelOther = "0: 00000000:0241 00000000:0000 0A 0:0 0:0 0 0 0 0\n"
	)
	for _, tc := range []struct {
		name, rows  string
		udp, active bool
		found, fail bool
	}{
		{name: "active owned", rows: ownedMount, active: true, found: true},
		{name: "mix with foreign listener", rows: ownedMount + foreign, active: true, fail: true},
		{name: "unexpected owned port", rows: ownedMount + otherPort, active: true, fail: true},
		{name: "stopped occupied TCP", rows: foreign, fail: true},
		{name: "stopped occupied UDP", rows: udpMount, udp: true, fail: true},
		{name: "active occupied UDP", rows: udpMount, udp: true, active: true, fail: true},
		{name: "stopped TIME_WAIT", rows: timeWait},
		{name: "unrelated kernel listener", rows: kernelOther},
		{name: "incomplete record", rows: "0: 00000000:4E50 00000000:0000 0A\n", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var owned map[uint64]struct{}
			if tc.active {
				owned = map[uint64]struct{}{51: {}}
			}
			found, err := scanMountTransport(context.Background(), strings.NewReader(header+tc.rows), owned, tc.udp)
			if found != tc.found || (err != nil) != tc.fail {
				t.Fatalf("socket observation = %t, %v", found, err)
			}
		})
	}
}
