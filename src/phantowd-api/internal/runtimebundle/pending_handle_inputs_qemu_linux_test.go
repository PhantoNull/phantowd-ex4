//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import "testing"

func TestPendingObserverDependencyRequiresOneExactFixedModule(t *testing.T) {
	for _, test := range []struct {
		needed         []string
		present, valid bool
	}{
		{[]string{"libsmbclient.so.0", "libc.so.6"}, false, true},
		{[]string{"libsmbclient.so.0", pendingClientObserverSONAMEQEMU, "libc.so.6"}, true, true},
		{[]string{"libsmbclient.so.0"}, true, false},
		{[]string{pendingClientObserverSONAMEQEMU}, false, false},
		{[]string{pendingClientObserverSONAMEQEMU, pendingClientObserverSONAMEQEMU}, true, false},
		{[]string{"/tmp/observer.so"}, true, false},
	} {
		if err := pendingObserverDependencyQEMU(test.needed, test.present); (err == nil) != test.valid {
			t.Fatal(test, err)
		}
	}
}
