// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nftguard"
)

// Run with support/test-nfs-firewall.sh.
func TestSambaFirewallKernel(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	domain := func(ctx context.Context) error {
		current, err := os.Stat("/proc/thread-self/ns/net")
		if err != nil || !os.SameFile(current, selfNS) {
			return nftguard.ErrState
		}
		return ctx.Err()
	}
	newGuard := func() *nftguard.Samba {
		t.Helper()
		guard, err := nftguard.NewSamba(ctx, domain, netip.MustParseAddr("192.0.2.1"), device.Index, code)
		if err != nil {
			t.Fatal(err)
		}
		return guard
	}
	peerCommand := func(args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/usr/bin/nsenter", append([]string{"-t", peer, "-n", "--"}, args...)...)
	}
	probe := func(local, remote, expectation string) {
		t.Helper()
		cmd := peerCommand(os.Args[0], "-test.run=^TestNFSFirewallFixturePeer$", "--", local, remote, expectation)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s to %s expected %s: %v %s", local, remote, expectation, err, out)
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{Port: 445})
	must(err)
	defer listener.Close()
	probe("192.0.2.2", "192.0.2.1:445", "connected")
	probe("198.51.100.2", "198.51.100.1:445", "connected")
	guard := newGuard()
	must(guard.Stage(ctx))
	probe("192.0.2.2", "192.0.2.1:445", "blocked")
	other := newGuard()
	if !errors.Is(other.Stage(ctx), nftguard.ErrState) {
		t.Fatal("another owner adopted the staged table")
	}
	must(other.Close(ctx))
	must(guard.Publish(ctx))
	probe("192.0.2.2", "192.0.2.5:445", "blocked")
	probe("198.51.100.2", "198.51.100.1:445", "blocked")
	if out, err := peerCommand("/usr/sbin/ip", "route", "replace", "192.0.2.1/32", "via", "198.51.100.1", "dev", "pwother").CombinedOutput(); err != nil {
		t.Fatalf("force nonapproved ingress: %v %s", err, out)
	}
	probe("198.51.100.2", "192.0.2.1:445", "blocked")
	if out, err := peerCommand("/usr/sbin/ip", "route", "del", "192.0.2.1/32").CombinedOutput(); err != nil {
		t.Fatalf("restore approved ingress: %v %s", err, out)
	}

	// Discard the successful baseline probes from the listener backlog.
	must(listener.Close())
	listener, err = net.ListenTCP("tcp4", &net.TCPAddr{Port: 445})
	must(err)
	defer listener.Close()
	stream := peerCommand(os.Args[0], "-test.run=^TestSambaFirewallFixtureStream$")
	stream.Env = append(os.Environ(), "PHANTOWD_SMB_STREAM_PEER=1")
	stream.Stdout, stream.Stderr = os.Stdout, os.Stderr
	control, err := stream.StdinPipe()
	must(err)
	must(stream.Start())
	defer func() {
		_ = control.Close()
		_ = stream.Process.Kill()
		_ = stream.Wait()
	}()
	must(listener.SetDeadline(time.Now().Add(2 * time.Second)))
	conn, err := listener.AcceptTCP()
	must(err)
	defer conn.Close()
	must(guard.Fence(ctx))
	must(guard.CheckFenced(ctx))
	probe("192.0.2.2", "192.0.2.1:445", "blocked")
	must(control.Close())
	must(conn.SetDeadline(time.Now().Add(2 * time.Second)))
	var data [1]byte
	_, err = io.ReadFull(conn, data[:])
	must(err)
	if data[0] != 42 {
		t.Fatalf("established stream lost data after fence: %v", data)
	}
	must(stream.Wait())
	must(conn.Close())
	must(listener.Close())
	must(guard.Close(ctx))

	guard = newGuard()
	must(guard.Stage(ctx))
	if out, err := exec.CommandContext(ctx, path, "add", "rule", "inet", "phantowd_smb", "input", "counter").CombinedOutput(); err != nil {
		t.Fatalf("simulate rule drift: %v %s", err, out)
	}
	if !errors.Is(guard.Publish(ctx), nftguard.ErrReviewRequired) || !errors.Is(guard.Close(ctx), nftguard.ErrReviewRequired) {
		t.Fatal("rule drift did not preserve hold for review")
	}
	must(exec.CommandContext(ctx, path, "list", "table", "inet", "phantowd_smb").Run())
}

func TestSambaFirewallFixtureStream(t *testing.T) {
	if os.Getenv("PHANTOWD_SMB_STREAM_PEER") != "1" {
		t.Skip("not the isolated peer process")
	}
	conn, err := net.DialTimeout("tcp4", "192.0.2.1:445", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
}
