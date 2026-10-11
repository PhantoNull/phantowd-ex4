//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPendingConnectionStatAndPrivilegeRefusals(t *testing.T) {
	fields := append([]string{"S", "123", "124"}, strings.Fields(strings.Repeat("0 ", 16))...)
	fields = append(fields, "456")
	stat := "124 (comm has ) delimiters) " + strings.Join(fields, " ")
	want := pendingProcGenerationQEMU{pid: 124, parent: 123, group: 124, start: 456}
	if got, err := pendingProcStatQEMU([]byte(stat)); err != nil || got != want {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"", "124 (comm) Z 123 124", strings.Replace(stat, "124 (", "0124 (", 1), strings.Replace(stat, "S 123", "Z 123", 1), strings.Replace(stat, "S 123", "S 0", 1), strings.Replace(stat, "456", "0", 1), stat + strings.Repeat(" ", 4096)} {
		if got, err := pendingProcStatQEMU([]byte(bad)); err == nil || got != (pendingProcGenerationQEMU{}) {
			t.Fatal("bad generation accepted", got, err)
		}
	}
	status := "Uid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\nGroups:\t\nNoNewPrivs:\t1\n"
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		status += key + ":\t0000000000000000\n"
	}
	if err := pendingClientStatusQEMU([]byte(status)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{status + "Uid:\t65534 65534 65534 65534\n", strings.Replace(status, "Groups:\t", "Groups:\t1", 1), strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), strings.Replace(status, "CapEff:\t0000000000000000", "CapEff:\t0000000000000001", 1), strings.Replace(status, "65534", "0", 1), ""} {
		if pendingClientStatusQEMU([]byte(bad)) == nil {
			t.Fatal("privileged/partial/duplicate status accepted")
		}
	}
	for _, bad := range []string{"socket:[]", "socket:[0]", "socket:[01]", "socket:[4294967296]", "socket:[1]extra", "pipe:[1]"} {
		if _, err := pendingSocketLinkQEMU(bad); err == nil {
			t.Fatal("bad socket link accepted")
		}
	}
	if got, err := pendingSocketLinkQEMU("socket:[4294967295]"); err != nil || got != ^uint32(0) {
		t.Fatal(got, err)
	}
}

func TestPendingConnectionPairRequiresUniquePrincipalCensuses(t *testing.T) {
	rows := pendingTCPPairRowsQEMU()
	got, err := matchPendingProcessPairQEMU(context.Background(), rows, []uint32{11}, []uint32{12})
	if err != nil || got.client != rows[1] || got.server != rows[3] {
		t.Fatal(err)
	}
	for _, censuses := range [][2][]uint32{{nil, {12}}, {{11}, nil}, {{11, 11}, {12}}, {{11, 21}, {12}}, {{11}, {12, 22}}, {{11}, {22}}, {{12}, {11}}, {{0, 11}, {12}}} {
		if got, err := matchPendingProcessPairQEMU(context.Background(), rows, censuses[0], censuses[1]); err == nil || got != (pendingTCPPairQEMU{}) {
			t.Fatal("ambiguous/missing/cross process census accepted", err)
		}
	}
	for _, index := range []int{1, 3} {
		changed := slices.Clone(rows)
		changed[index].uid++
		if _, err := matchPendingProcessPairQEMU(context.Background(), changed, []uint32{11}, []uint32{12}); err == nil {
			t.Fatal("foreign principal accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := matchPendingProcessPairQEMU(ctx, rows, []uint32{11}, []uint32{12}); !errors.Is(err, context.Canceled) || got != (pendingTCPPairQEMU{}) {
		t.Fatal(err)
	}
}

func TestPendingConnectionRealProcReferencesAndRefusalRelease(t *testing.T) {
	// Actual kernel references only, NOT an admitted PendingClient or Samba peer.
	fd, err := unix.Open("/proc/self", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	caller := os.NewFile(uintptr(fd), "test-own-proc")
	proc, err := retainPendingProcQEMU(caller)
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	if err := caller.Close(); err != nil {
		t.Fatal(err)
	}
	stat, err := pendingProcGenerationReadQEMU(proc)
	if err != nil || stat.pid != os.Getpid() {
		t.Fatal(stat, err)
	}
	namespace, err := pendingNamespaceQEMU(proc, "net")
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	if err := samePendingNamespaceQEMU(namespace, proc, "net"); err != nil {
		t.Fatal(err)
	}
	if _, err := pendingProcessSocketsQEMU(context.Background(), proc); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, err := pendingProcessSocketsQEMU(ctx, proc); rows != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(rows, err)
	}
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	refused, err := retainPendingProcQEMU(file)
	if err == nil || refused == nil {
		t.Fatal("non-proc input accepted/discarded", err)
	}
	if err := refused.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := namespace.Stat(); err != nil {
		t.Fatal("independent namespace lost")
	}
	if err := namespace.Close(); err != nil {
		t.Fatal(err)
	}
	if samePendingNamespaceQEMU(namespace, proc, "net") == nil {
		t.Fatal("closed namespace accepted")
	}
	if stat.start == 0 {
		t.Fatal("incomplete identity")
	}
}

func TestPendingConnectionLifecycleRejectsMissingCopyBusyAndCanceled(t *testing.T) {
	var absent *PendingClientQEMU
	if absent.BindConnectionQEMU(context.Background(), nil) == nil || absent.RecheckConnectionQEMU(context.Background()) == nil {
		t.Fatal("absent accepted")
	}
	c := &PendingClientQEMU{gate: make(chan struct{}, 1)}
	c.self = c
	copy := *c
	if copy.BindConnectionQEMU(context.Background(), nil) == nil || copy.RecheckConnectionQEMU(context.Background()) == nil {
		t.Fatal("copy accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(c.BindConnectionQEMU(ctx, nil), context.Canceled) || c.connection != nil || c.review {
		t.Fatal("pre-admission cancellation mutated owner")
	}
	c.gate <- struct{}{}
	if !errors.Is(c.BindConnectionQEMU(context.Background(), nil), ErrBusy) || !errors.Is(c.RecheckConnectionQEMU(context.Background()), ErrBusy) {
		t.Fatal("busy admitted")
	}
	<-c.gate
	if c.BindConnectionQEMU(context.Background(), nil) == nil || c.RecheckConnectionQEMU(context.Background()) == nil || c.connection != nil {
		t.Fatal("unstarted admitted")
	}
	c.closed = true
	if c.BindConnectionQEMU(context.Background(), nil) == nil || c.RecheckConnectionQEMU(context.Background()) == nil {
		t.Fatal("closed admitted")
	}
}
