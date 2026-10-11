//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNativeObserverDaemonRefusesHostWithoutConsumingCallers(t *testing.T) {
	if model, _ := os.ReadFile("/sys/firmware/devicetree/base/model"); string(model) == "ARM Versatile PB\x00" {
		t.Skip("host refusal; separate explicit guest proves execution")
	}
	caller, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	spec := MemberSpec{Name: "native-samba-observer", Process: Spec{
		Executable: nativeObserverDaemonBootstrapQEMU, RunAs: &Credentials{UID: 0, GID: 0},
	}}
	for range 16 {
		owned, err := NewNativeObserverDaemonQEMU(spec, caller,
			[5]*os.File{caller, caller, caller, caller, caller}, [7]*os.File{caller, caller, caller, caller, caller, caller, caller},
			[2]*os.File{caller, caller}, caller)
		if owned != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("host obtained observer process authority:", err)
		}
		if _, err := caller.Stat(); err != nil {
			t.Fatal("refusal consumed caller:", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("host refusal leaked descriptors:", err)
	}
}

func TestNativeObserverSambaDaemonQEMU(t *testing.T) {
	model, _ := os.ReadFile("/sys/firmware/devicetree/base/model")
	commandLine, _ := os.ReadFile("/proc/cmdline")
	if string(model) != "ARM Versatile PB\x00" ||
		!strings.Contains(" "+strings.TrimSpace(string(commandLine))+" ", " phantowd_observer_daemon_fixture=1 ") {
		t.Skip("only the dedicated disposable ARM926 guest")
	}
	releaseOriginals := true
	open := func(path string, flags int) *os.File {
		t.Helper()
		fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal("fixture input:", err)
		}
		file := os.NewFile(uintptr(fd), "original-observer-fixture-input")
		t.Cleanup(func() {
			if releaseOriginals {
				file.Close()
			}
		})
		return file
	}
	config := [5]*os.File{
		open("/run/phantowd-native-samba-root/etc", unix.O_RDONLY|unix.O_DIRECTORY),
		open("/run/phantowd-native-samba-root/etc/passwd", unix.O_RDONLY),
		open("/run/phantowd-native-samba-root/etc/group", unix.O_RDONLY),
		open("/run/phantowd-native-samba-root/etc/nsswitch.conf", unix.O_RDONLY),
		open("/run/phantowd-native-samba-root/etc/samba/smb.conf", unix.O_RDONLY),
	}
	var state [7]*os.File
	for i, role := range []string{"", "/private", "/lock", "/state", "/cache", "/pid", "/rpc"} {
		state[i] = open("/run/phantowd-native-samba-state"+role, unix.O_RDONLY|unix.O_DIRECTORY)
	}
	roots := [2]*os.File{open("/run/observer-readonly", unix.O_PATH|unix.O_DIRECTORY),
		open("/run/observer-writable", unix.O_PATH|unix.O_DIRECTORY)}
	program := open(nativeObserverDaemonBootstrapQEMU, unix.O_RDONLY)
	actualSmbd := open("/run/phantowd-samba-code/usr/sbin/smbd", unix.O_RDONLY)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	receiver := os.NewFile(uintptr(pair[0]), "original-observer-fixture-receiver")
	sender := os.NewFile(uintptr(pair[1]), "original-observer-fixture-sender")
	t.Cleanup(func() {
		if releaseOriginals {
			receiver.Close()
			sender.Close()
		}
	})
	if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		t.Fatal(err)
	}
	identity, err := snapshotNativeObserverSenderQEMU(sender)
	if err != nil {
		t.Fatal(err)
	}
	var owned *NativeObserverDaemonQEMU
	var probeFailure error
	spec := MemberSpec{Name: "native-samba-observer", Process: Spec{
		Executable: nativeObserverDaemonBootstrapQEMU, RunAs: &Credentials{UID: 0, GID: 0},
		ReadyTimeout: 12 * time.Second, ProbeInterval: 200 * time.Millisecond, StopTimeout: 4 * time.Second,
		Ready: func(ctx context.Context) (ready bool, probeErr error) {
			defer func() {
				if probeErr != nil {
					probeFailure = probeErr
				}
			}()
			if owned == nil || owned.owned.set.members[0].owner.current == nil {
				return false, ErrInvalid
			}
			pid := owned.owned.set.members[0].owner.current.pid
			actual, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/exe")
			expected, expectedErr := actualSmbd.Stat()
			if err != nil || expectedErr != nil || !os.SameFile(actual, expected) {
				return false, nil
			}
			link, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/fd/3")
			if err != nil || link != fmt.Sprintf("socket:[%d]", identity.inode) {
				probeFailure = fmt.Errorf("original daemon endpoint: link=%q error=%v", link, err)
				return false, probeFailure
			}
			dialer := net.Dialer{Timeout: 200 * time.Millisecond}
			connection, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:1445")
			if err != nil {
				return false, nil
			}
			defer connection.Close()
			deadline := time.Now().Add(2 * time.Second)
			if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
				deadline = limit
			}
			if err := connection.SetDeadline(deadline); err != nil {
				return false, err
			}
			// Fixed SMB2 NEGOTIATE for dialect3.02. No authentication, tree,
			// file OPEN, data write or observer frame is requested.
			var request [106]byte
			request[3] = 102
			copy(request[4:8], []byte{0xfe, 'S', 'M', 'B'})
			request[8] = 64
			request[18] = 1  // CreditRequest
			request[68] = 36 // Negotiate StructureSize
			request[70] = 1  // DialectCount
			request[72] = 1  // Signing enabled
			copy(request[80:96], []byte("qemu-observer-01"))
			request[104] = 2
			request[105] = 3
			if n, err := connection.Write(request[:]); err != nil || n != len(request) {
				return false, fmt.Errorf("fixed negotiation request: sent=%d error=%v", n, err)
			}
			var header [4]byte
			if _, err := io.ReadFull(connection, header[:]); err != nil {
				return false, err
			}
			length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
			if header[0] != 0 || length < 128 || length > 4096 {
				if header[0] == 0 && length == 73 {
					var refused [73]byte
					_, readErr := io.ReadFull(connection, refused[:])
					return false, fmt.Errorf("fixed negotiation error response: header=%x status=%x read=%v", header, refused[8:12], readErr)
				}
				return false, fmt.Errorf("fixed negotiation response framing: header=%x length=%d", header, length)
			}
			response := make([]byte, length)
			if _, err := io.ReadFull(connection, response); err != nil {
				return false, err
			}
			if string(response[:4]) != "\xfeSMB" || response[4] != 64 ||
				response[8] != 0 || response[9] != 0 || response[10] != 0 || response[11] != 0 ||
				response[12] != 0 || response[13] != 0 || response[16]&1 != 1 ||
				response[64] != 65 || response[68] != 2 || response[69] != 3 {
				return false, fmt.Errorf("fixed negotiation response refused: %x", response[:70])
			}
			return true, nil
		},
	}}
	for _, mutation := range []struct {
		name string
		edit func(*MemberSpec, *[5]*os.File, *[7]*os.File, *[2]*os.File, **os.File)
	}{
		{"wrong name", func(s *MemberSpec, _ *[5]*os.File, _ *[7]*os.File, _ *[2]*os.File, _ **os.File) { s.Name = "foreign" }},
		{"wrong program", func(s *MemberSpec, _ *[5]*os.File, _ *[7]*os.File, _ *[2]*os.File, _ **os.File) {
			s.Process.Executable = "/usr/sbin/smbd"
		}},
		{"arguments", func(s *MemberSpec, _ *[5]*os.File, _ *[7]*os.File, _ *[2]*os.File, _ **os.File) {
			s.Process.Args = []string{"foreign"}
		}},
		{"missing credentials", func(s *MemberSpec, _ *[5]*os.File, _ *[7]*os.File, _ *[2]*os.File, _ **os.File) {
			s.Process.RunAs = nil
		}},
		{"supplementary group", func(s *MemberSpec, _ *[5]*os.File, _ *[7]*os.File, _ *[2]*os.File, _ **os.File) {
			s.Process.RunAs = &Credentials{SupplementaryGIDs: []uint32{1}}
		}},
		{"missing probe", func(s *MemberSpec, _ *[5]*os.File, _ *[7]*os.File, _ *[2]*os.File, _ **os.File) {
			s.Process.Ready = nil
		}},
		{"duplicate config", func(_ *MemberSpec, c *[5]*os.File, _ *[7]*os.File, _ *[2]*os.File, _ **os.File) { c[2] = c[1] }},
		{"duplicate state", func(_ *MemberSpec, _ *[5]*os.File, s *[7]*os.File, _ *[2]*os.File, _ **os.File) { s[6] = s[5] }},
		{"missing share", func(_ *MemberSpec, _ *[5]*os.File, _ *[7]*os.File, r *[2]*os.File, _ **os.File) { r[1] = nil }},
		{"wrong share role", func(_ *MemberSpec, _ *[5]*os.File, _ *[7]*os.File, r *[2]*os.File, _ **os.File) {
			r[0], r[1] = r[1], r[0]
		}},
		{"receiver role", func(_ *MemberSpec, _ *[5]*os.File, _ *[7]*os.File, _ *[2]*os.File, s **os.File) { *s = receiver }},
		{"missing sender", func(_ *MemberSpec, _ *[5]*os.File, _ *[7]*os.File, _ *[2]*os.File, s **os.File) { *s = nil }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			candidate, configs, states, shares, endpoint := spec, config, state, roots, sender
			mutation.edit(&candidate, &configs, &states, &shares, &endpoint)
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			for range 3 {
				refused, err := NewNativeObserverDaemonQEMU(candidate, program, configs, states, shares, endpoint)
				if refused != nil || !errors.Is(err, ErrInvalid) {
					t.Fatal("foreign constructor obtained authority:", err)
				}
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(after) != len(before) {
				t.Fatal("partial construction leaked references:", err)
			}
			if final, err := snapshotNativeObserverSenderQEMU(sender); err != nil || final != identity {
				t.Fatal("constructor refusal consumed original endpoint:", err)
			}
		})
	}
	owned, err = NewNativeObserverDaemonQEMU(spec, program, config, state, roots, sender)
	if err != nil {
		t.Fatal("observer construction:", err)
	}
	t.Cleanup(func() {
		_, stopErr := owned.Stop(context.Background())
		closeErr := owned.Close()
		if closeErr != nil || owned.owned.set.members[0].owner.current != nil {
			releaseOriginals = false
			t.Error("fixture retains original inputs after uncertain disposal:", stopErr, closeErr)
		}
	})
	started, err := owned.Start(context.Background())
	if err != nil || started.State != StateReady {
		t.Fatal("actual smbd negotiation:", err, probeFailure, string(owned.owned.set.members[0].owner.Diagnostics()))
	}
	if err := owned.CheckBootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := owned.Close(); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatal("live daemon released original inputs:", err)
	}
	stopped, err := owned.Stop(context.Background())
	if err != nil || stopped.State != StateStopped || stopped.Members[0].Process.PID != 0 {
		t.Fatal("daemon group not settled:", err)
	}
	for _, pin := range owned.owned.pins {
		if _, err := pin.Stat(); err != nil {
			t.Fatal("owned original lost before Close:", err)
		}
	}
	final, err := snapshotNativeObserverSenderQEMU(sender)
	if err != nil || final != identity {
		t.Fatal("private stop consumed or changed original sender:", err)
	}
	if _, err := receiver.Stat(); err != nil {
		t.Fatal("original receiver lost:", err)
	}
	if _, err := owned.Start(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("stopped observer restarted:", err)
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owned.Close(); err != nil {
		t.Fatal("repeat close:", err)
	}
	if _, err := sender.Stat(); err != nil {
		t.Fatal("owned release consumed original caller:", err)
	}
	fmt.Println("PHANTOWD_SERVER_OBSERVER_DAEMON_PROOF actual_smbd=true negotiate_smb302=true endpoint_retained=true stop_before_release=true restart_refused=true scope=qemu-only")
	// A fresh single-use adapter proves a concrete live-channel fault, without
	// restarting the settled original adapter or borrowing its process authority.
	owned, err = NewNativeObserverDaemonQEMU(spec, program, config, state, roots, sender)
	if err != nil {
		t.Fatal("fresh drift fixture:", err)
	}
	if started, err := owned.Start(context.Background()); err != nil || started.State != StateReady {
		t.Fatal("actual drift fixture did not negotiate:", started, err)
	}
	if healthy, err := owned.Observe(context.Background()); err != nil || healthy.State != StateReady {
		t.Fatal("actual healthy observation:", healthy, err)
	}
	if err := unix.SetsockoptInt(pair[1], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		t.Fatal(err)
	}
	fault, err := owned.Observe(context.Background())
	if !errors.Is(err, ErrReviewRequired) || fault.State != StateReviewRequired ||
		fault.Members[0].Process.PID != 0 || fault.Generation != 1 {
		t.Fatal("actual daemon endpoint fault not settled:", fault, err)
	}
	for _, pin := range append([]*os.File{receiver, sender}, owned.owned.pins...) {
		if _, err := pin.Stat(); err != nil {
			t.Fatal("actual fault released original references:", err)
		}
	}
	if err := unix.SetsockoptInt(pair[1], unix.SOL_SOCKET, unix.SO_PASSCRED, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := owned.Observe(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("actual restoration cleared review:", err)
	}
	if _, err := owned.Start(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("actual restoration allowed restart:", err)
	}
	if err := owned.Close(); err != nil {
		t.Fatal("actual verified fault settlement release:", err)
	}
	fmt.Println("PHANTOWD_SERVER_OBSERVER_DAEMON_DRIFT_PROOF actual_smbd=true original_endpoint_drift=true stop_verified=true originals_retained=true restoration_refused=true scope=qemu-only")
}

func TestNativeObserverFailedStartupImmediatelyPreservesReviewAndOriginal(t *testing.T) {
	file, err := os.Open("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	set, err := NewPinnedSet([]MemberSpec{{Name: "fixture", Process: Spec{
		Executable: "/fixed/fixture", Args: []string{"60"},
		Ready:        func(context.Context) (bool, error) { return false, ErrReviewRequired },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	}}}, []*os.File{file})
	if err != nil {
		t.Fatal(err)
	}
	owner := &NativeObserverDaemonQEMU{owned: set}
	t.Cleanup(func() { owner.Stop(context.Background()); owner.Close() })
	observed, err := owner.Start(context.Background())
	if !errors.Is(err, ErrReviewRequired) || observed.State != StateReviewRequired ||
		observed.Members[0].Process.PID != 0 || observed.Generation != 0 {
		t.Fatal("failed startup did not immediately retain reviewed authority:", observed, err)
	}
	if _, err := set.pins[0].Stat(); err != nil {
		t.Fatal("failed startup released original code:", err)
	}
	if _, err := owner.Start(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("failed startup allowed retry:", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal("verified stopped original could not be released:", err)
	}
}

func TestNativeObserverLiveEndpointDriftStopsWithoutReleasingOrRestarting(t *testing.T) {
	for _, operation := range []string{"observe", "explicit-stop"} {
		t.Run(operation, func(t *testing.T) { nativeObserverLiveEndpointDriftCase(t, operation) })
	}
}

func nativeObserverLiveEndpointDriftCase(t *testing.T, operation string) {
	file, err := os.Open("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	receiver := os.NewFile(uintptr(pair[0]), "fixture-original-receiver")
	sender := os.NewFile(uintptr(pair[1]), "fixture-original-sender")
	defer receiver.Close()
	defer sender.Close()
	pin, identity, err := duplicateNativeObserverSenderQEMU(sender)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewPinnedSet([]MemberSpec{{Name: "fixture", Process: Spec{
		Executable: "/fixed/fixture", Args: []string{"60"},
		Ready:        func(context.Context) (bool, error) { return true, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	}}}, []*os.File{file})
	if err != nil {
		pin.Close()
		t.Fatal(err)
	}
	set.pins = append(set.pins, pin)
	owner := &NativeObserverDaemonQEMU{owned: set, check: func() error {
		observed, err := snapshotNativeObserverSenderQEMU(pin)
		if err != nil || observed != identity {
			return ErrReviewRequired
		}
		return nil
	}}
	t.Cleanup(func() { owner.Stop(context.Background()); owner.Close() })
	started, err := owner.Start(context.Background())
	if err != nil || started.State != StateReady {
		t.Fatal("real owned child did not start:", started, err)
	}
	if healthy, err := owner.Observe(context.Background()); err != nil ||
		healthy.State != StateReady || healthy.Members[0].Process.PID != started.Members[0].Process.PID {
		t.Fatal("healthy observation changed original child:", healthy, err)
	}
	if err := unix.SetsockoptInt(pair[1], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		t.Fatal(err)
	}
	var observed SetSnapshot
	if operation == "explicit-stop" {
		stopCtx, cancel := context.WithCancel(context.Background())
		cancel()
		observed, err = owner.Stop(stopCtx)
	} else {
		observed, err = owner.Observe(context.Background())
	}
	if !errors.Is(err, ErrReviewRequired) || observed.State != StateReviewRequired ||
		observed.Members[0].Process.PID != 0 || observed.Generation != started.Generation {
		t.Fatal("live endpoint drift was not contained:", observed, err)
	}
	for _, original := range append([]*os.File{receiver, sender}, set.pins...) {
		if _, err := original.Stat(); err != nil {
			t.Fatal("drift released original authority:", err)
		}
	}
	if err := unix.SetsockoptInt(pair[1], unix.SOL_SOCKET, unix.SO_PASSCRED, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Observe(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("restoration cleared review:", err)
	}
	if _, err := owner.Start(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("restoration permitted restart:", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal("verified stopped group prevented explicit release:", err)
	}
}
