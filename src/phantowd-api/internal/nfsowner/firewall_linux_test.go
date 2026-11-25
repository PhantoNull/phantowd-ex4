// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// Run with support/test-nfs-firewall.sh in two disposable network namespaces.
func TestNFSFirewallKernel(t *testing.T) {
	path := os.Getenv("PHANTOWD_NFT_FIXTURE")
	if path == "" {
		t.Skip("isolated packet fixture was not requested")
	}
	peer := os.Getenv("PHANTOWD_NFT_PEER_PID")
	pid, err := strconv.Atoi(peer)
	if err != nil || pid <= 0 {
		t.Fatal("missing separate peer network namespace")
	}
	selfNS, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	peerNS, err := os.Stat("/proc/" + peer + "/ns/net")
	if err != nil || os.SameFile(selfNS, peerNS) {
		t.Fatal("peer shares the test process network namespace")
	}
	device, err := net.InterfaceByName("pwnfs")
	if err != nil {
		t.Fatal(err)
	}
	code, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer code.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	domain := func(ctx context.Context) error {
		current, err := os.Stat("/proc/thread-self/ns/net")
		if err != nil || !os.SameFile(current, selfNS) {
			return ErrState
		}
		return ctx.Err()
	}
	newGuard := func() *nfsFirewall {
		f, err := newNFSFirewall(ctx, domain, netip.MustParseAddr("192.0.2.1"), device.Index,
			[]netip.Prefix{netip.MustParsePrefix("192.0.2.2/32"), netip.MustParsePrefix("198.51.100.0/29"),
				netip.MustParsePrefix("192.0.2.2/32")}, code)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	f := newGuard()
	defer func() {
		if f.code != nil {
			_ = f.code.Close()
		}
	}()
	if err := f.requireUnclaimed(ctx); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"192.0.2.1", "192.0.2.5"} {
		for _, port := range []int{111, 2049, mountdPort, 30001} {
			listener, err := net.Listen("tcp4", net.JoinHostPort(address, strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
		}
	}
	packet, err := net.ListenPacket("udp4", "192.0.2.1:2049")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if !errors.Is(f.requireUnclaimed(ctx), ErrState) {
		t.Fatal("occupied service ports passed production preflight")
	}
	peerCommand := func(args ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, "/usr/bin/nsenter", append([]string{"-t", peer, "-n", "--"}, args...)...)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	probe := func(local, remote, expectation string) {
		t.Helper()
		peerCommand(os.Args[0], "-test.run=^TestNFSFirewallFixturePeer$", "--", local, remote, expectation)
	}

	// Reachability before the filter distinguishes filtering from no route.
	probe("192.0.2.3", "192.0.2.1:2049", "connected")
	probe("192.0.2.2", "192.0.2.5:2049", "connected")
	if err := f.start(ctx); err != nil {
		t.Fatalf("install and read back real nftables: %v", err)
	}
	if err := f.check(ctx); err != nil {
		t.Fatal(err)
	}
	for _, port := range []string{"111", "2049", "20048"} {
		probe("192.0.2.2", "192.0.2.1:"+port, "connected")
		probe("192.0.2.3", "192.0.2.1:"+port, "blocked")
	}
	probe("192.0.2.2", "192.0.2.5:2049", "blocked")
	probe("192.0.2.3", "192.0.2.1:30001", "connected")
	probe("192.0.2.2", "192.0.2.1:2049", "udp")
	if err := packet.SetReadDeadline(time.Now().Add(350 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [32]byte
	_, _, err = packet.ReadFrom(b[:])
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("UDP available on guarded service port: %v", err)
	}
	if conn, err := net.DialTimeout("tcp4", "192.0.2.1:111", time.Second); err != nil {
		t.Fatalf("local rpcinfo path was blocked: %v", err)
	} else {
		conn.Close()
	}
	// The source belongs to an allowed prefix, but arrives through another
	// interface. The unrelated port proves this path is still reachable.
	peerCommand("/usr/sbin/ip", "route", "replace", "192.0.2.1/32", "via", "198.51.100.1", "dev", "pwother")
	probe("198.51.100.2", "192.0.2.1:30001", "connected")
	probe("198.51.100.2", "192.0.2.1:2049", "blocked")
	peerCommand("/usr/sbin/ip", "route", "del", "192.0.2.1/32")
	if err := f.close(ctx); err != nil {
		t.Fatal(err)
	}
	probe("192.0.2.3", "192.0.2.1:2049", "connected")

	f = newGuard()
	if err := f.start(ctx); err != nil {
		t.Fatal(err)
	}
	other := newGuard()
	defer other.code.Close()
	if !errors.Is(other.start(ctx), ErrState) {
		t.Fatal("second owner adopted or replaced the live table")
	}
	if _, err := f.run(ctx, "", "add", "rule", "inet", nfsTable, nfsInput, "counter"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(f.check(ctx), ErrReviewRequired) || !errors.Is(f.close(ctx), ErrReviewRequired) {
		t.Fatal("changed kernel rules did not retain review")
	}
	if _, err := f.run(ctx, "", "list", "table", "inet", nfsTable); err != nil {
		t.Fatal("uncertain close removed the table")
	}
}

func TestNFSFirewallFixturePeer(t *testing.T) {
	if os.Getenv("PHANTOWD_NFT_FIXTURE") == "" {
		t.Skip("isolated packet fixture was not requested")
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		t.Skip("not the peer process")
	}
	if len(args) != 3 {
		t.Fatal("malformed fixture request")
	}
	if args[2] == "udp" {
		remote, err := net.ResolveUDPAddr("udp4", args[1])
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(args[0])}, remote)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("fixture packet")); err != nil {
			t.Fatal(err)
		}
		return
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(args[0])}, Timeout: 350 * time.Millisecond}
	conn, err := dialer.Dial("tcp4", args[1])
	if err == nil {
		conn.Close()
	}
	switch args[2] {
	case "connected":
		if err != nil {
			t.Fatal(err)
		}
	case "blocked":
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("expected input drop, got %v", err)
		}
	default:
		t.Fatal("unknown fixture expectation")
	}
}
