//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

const (
	peerNFSPayload     = "remote-owner-nfs3-tcp-write\n"
	peerNFSServer      = "192.0.2.1"
	peerNFSAllowed     = "192.0.2.2"
	peerNFSDenied      = "192.0.2.3"
	peerNFSControl     = peerNFSServer + ":30001"
	peerNFSSource      = peerNFSServer + ":" + ownerNFSRoot
	peerNFSClientMount = "/run/nfs-peer-client"
)

func runQEMUNFSPeer(mode string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	filter, err := peerNFSFilterMode()
	if err != nil {
		return err
	}
	if mode == "peer-server" {
		return serveQEMUManagedNFS(ctx, filter)
	}
	if !nfskernel.PeerClientQEMU() {
		return errors.New("separate NFS client requires fixed QEMU role")
	}
	return useQEMUManagedNFS(ctx, filter)
}

func peerNFSFilterMode() (string, error) {
	command, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	var filter string
	for _, flag := range strings.Fields(string(command)) {
		value, found := strings.CutPrefix(flag, "phantowd_nfs_peer_filter=")
		if !found {
			continue
		}
		if filter != "" || value != "nftables" && value != "export-policy" {
			return "", errors.New("ambiguous peer NFS filter mode")
		}
		filter = value
	}
	if filter == "" {
		return "", errors.New("missing peer NFS filter mode")
	}
	return filter, nil
}

func serveQEMUManagedNFS(ctx context.Context, filter string) (result error) {
	if !nfskernel.PeerServerQEMU() {
		return nfskernel.ErrRefused
	}
	device, err := peerNFSInterface("52:54:00:12:34:01", peerNFSServer)
	if err != nil {
		return err
	}
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	var nft *os.File
	if filter == "nftables" {
		nft, err = os.Open("/usr/sbin/nft")
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, nft.Close()) }()
	}
	removeConfig, err := nfsowner.InstallManagedStateConfigQEMU(ctx)
	if err != nil {
		return err
	}
	err = mountowner.WithQEMUMountedSet(smbFixtureAnchor, func(set *mountowner.MountedVolumeSet) (result error) {
		b := &ownerNFSQEMU{storage: set, phase: "peer-sources"}
		var owner *nfsowner.Owner
		defer func() {
			if result != nil {
				result = &ownerNFSReview{backend: b, owner: owner, cause: result, contextDone: ctx.Err() != nil}
			}
		}()
		if err := b.prepareFixtureSources(ctx, peerNFSAllowed+"/32", "rw"); err != nil {
			return err
		}
		b.inputs, _, err = nfsowner.PrepareInputs(ctx, b.policyLease, b.identityLease, set, 0)
		if err != nil {
			return err
		}
		quiescent := true
		checkQuiescence := func(ctx context.Context) error {
			if !quiescent {
				return errors.New("remote client unmount is unconfirmed")
			}
			return ctx.Err()
		}
		b.phase = "peer-runtime"
		owner, err = withQEMUNFSGrants(netip.MustParseAddr(peerNFSServer), checkQuiescence, func(grants nfsowner.LinuxServiceGrants) (*nfsowner.Owner, error) {
			if unexpected, err := nfsowner.NewManagedLinux(ctx, b.inputs, grants); unexpected != nil || !errors.Is(err, nfsowner.ErrInvalid) {
				return unexpected, errors.Join(errors.New("production NFS admitted a missing firewall grant"), err)
			}
			if filter == "export-policy" {
				return nfsowner.NewManagedLinuxQEMU(ctx, b.inputs, grants)
			}
			grants.NFTables, grants.IngressIndex = nft, device.Index
			return nfsowner.NewManagedLinux(ctx, b.inputs, grants)
		})
		if err != nil {
			return err
		}
		if err := owner.Start(ctx); err != nil {
			return err
		}
		quiescent = false
		deadline, _ := ctx.Deadline()
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(peerNFSServer), Port: 30001})
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, listener.Close()) }()
		if err := listener.SetDeadline(deadline); err != nil {
			return err
		}
		b.phase = "peer-denied-client"
		probe, err := acceptNFSPeer(listener, peerNFSDenied, deadline)
		if err != nil {
			return err
		}
		if err := errors.Join(writePeerNFSMessage(probe, "ready\n"), probe.Close()); err != nil {
			return err
		}
		b.phase = "peer-allowed-client"
		conn, err := acceptNFSPeer(listener, peerNFSAllowed, deadline)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, conn.Close()) }()
		if filter == "nftables" {
			b.phase = "peer-packet-filter"
			if err := verifyPeerNFSUDPDrop(conn); err != nil {
				return err
			}
		}
		b.phase = "peer-allowed-mount"
		if err := readPeerNFSMessage(conn, "mounted\n"); err != nil {
			return err
		}
		if err := nfsowner.CheckManagedTablesQEMU(ctx, ownerNFSRoot, peerNFSAllowed); err != nil {
			return err
		}
		if err := owner.Check(ctx); err != nil {
			return err
		}
		if err := writePeerNFSMessage(conn, "write\n"); err != nil {
			return err
		}
		if err := readPeerNFSMessage(conn, "unmounted\n"); err != nil {
			return err
		}
		quiescent = true
		b.phase = "peer-verify-server-write"
		path := ownerNFSRoot + "/peer-write"
		data, err := os.ReadFile(path)
		if err != nil || string(data) != peerNFSPayload {
			return errors.New("remote write differs at server")
		}
		var info syscall.Stat_t
		if err := syscall.Stat(path, &info); err != nil || info.Uid != b.uid || info.Gid != b.gid {
			return errors.New("remote root write did not retain the policy anonymous identity")
		}
		b.phase = "peer-teardown"
		if err := owner.Stop(ctx); err != nil {
			return err
		}
		if err := owner.Close(ctx); err != nil {
			return err
		}
		if err := nfsowner.CheckManagedStateReapedQEMU(); err != nil {
			return err
		}
		if err := b.releaseFixtureClaims(ctx); err != nil {
			return err
		}
		if err := errors.Join(b.identity.Close(), b.policyOwner.Close()); err != nil {
			return err
		}
		return writePeerNFSMessage(conn, "verified\n")
	})
	if err != nil {
		return err
	}
	if err := removeConfig(); err != nil {
		return err
	}
	fmt.Printf("PHANTOWD_NFS_PEER_SERVER_READY kernel_backend=true activation=true managed=true remote_bytes=true mapped_identity=true tables=private filter=%s teardown=clean scope=isolated-two-guest-only\n", filter)
	return nil
}

func useQEMUManagedNFS(ctx context.Context, filter string) error {
	const mac = "52:54:00:12:34:02"
	device, err := peerNFSInterface(mac, peerNFSDenied)
	if err != nil {
		return err
	}
	probe, err := dialNFSPeer(ctx)
	if err != nil {
		return err
	}
	if err := errors.Join(readPeerNFSMessage(probe, "ready\n"), probe.Close()); err != nil {
		return err
	}
	if err := os.Mkdir(peerNFSClientMount, 0700); err != nil {
		return err
	}
	mount := func() ([]byte, error) {
		return peerNFSCommand(ctx, "/bin/mount", "-t", "nfs", "-o",
			"vers=3,proto=tcp,mountproto=tcp,nolock,soft,timeo=5,retrans=1", peerNFSSource, peerNFSClientMount)
	}
	if filter == "nftables" {
		if err := checkPeerNFSTCP(ctx, false); err != nil {
			return err
		}
	} else {
		out, err := mount()
		message := strings.ToLower(string(out))
		if err == nil || !strings.Contains(message, "access denied by server") && !strings.Contains(message, "permission denied") {
			return fmt.Errorf("unlisted peer did not receive an NFS access refusal: %v %s", err, out)
		}
	}
	if err := checkPeerNFSMount(false); err != nil {
		return err
	}
	if _, err := peerNFSCommand(ctx, "/sbin/ifconfig", device.Name, peerNFSAllowed, "netmask", "255.255.255.248", "up"); err != nil {
		return err
	}
	if _, err := peerNFSInterface(mac, peerNFSAllowed); err != nil {
		return err
	}
	conn, err := dialNFSPeer(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if filter == "nftables" {
		if err := checkPeerNFSTCP(ctx, true); err != nil {
			return err
		}
		if err := probePeerNFSUDP(ctx, conn); err != nil {
			return err
		}
	}
	if _, err := mount(); err != nil {
		return err
	}
	if err := checkPeerNFSMount(true); err != nil {
		return err
	}
	if err := writePeerNFSMessage(conn, "mounted\n"); err != nil {
		return err
	}
	if err := readPeerNFSMessage(conn, "write\n"); err != nil {
		return err
	}
	data, err := os.ReadFile(peerNFSClientMount + "/marker")
	if err != nil || string(data) != "owner-derived-nfs\n" {
		return errors.New("remote marker differs")
	}
	path := peerNFSClientMount + "/peer-write"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.WriteString(peerNFSPayload)
	syncErr, closeErr := f.Sync(), f.Close()
	if n != len(peerNFSPayload) || errors.Join(writeErr, syncErr, closeErr) != nil {
		return errors.New("remote write completion uncertain")
	}
	data, err = os.ReadFile(path)
	if err != nil || string(data) != peerNFSPayload {
		return errors.New("remote client readback differs")
	}
	if _, err := peerNFSCommand(ctx, "/bin/umount", peerNFSClientMount); err != nil {
		return err
	}
	if err := checkPeerNFSMount(false); err != nil {
		return err
	}
	if err := writePeerNFSMessage(conn, "unmounted\n"); err != nil {
		return err
	}
	if err := readPeerNFSMessage(conn, "verified\n"); err != nil {
		return err
	}
	fmt.Printf("PHANTOWD_NFS_PEER_CLIENT_READY protocol=nfs3 transport=tcp denied_source=true filter=%s read=true write=true fsync=true unmount=clean scope=isolated-two-guest-only\n", filter)
	return nil
}

func peerNFSInterface(mac, address string) (*net.Interface, error) {
	devices, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, device := range devices {
		if device.HardwareAddr.String() != mac {
			continue
		}
		addrs, err := device.Addrs()
		if err != nil {
			return nil, err
		}
		var ipv4 []string
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil {
				return nil, err
			}
			if prefix.Addr().Is4() {
				ipv4 = append(ipv4, prefix.String())
			}
		}
		if len(ipv4) == 1 && ipv4[0] == address+"/29" {
			return &device, nil
		}
	}
	return nil, errors.New("unexpected peer interface address")
}

func checkPeerNFSTCP(ctx context.Context, allowed bool) error {
	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	for _, port := range []string{"111", "2049", "20048"} {
		conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(peerNFSServer, port))
		if allowed {
			if err != nil {
				return fmt.Errorf("admitted TCP port %s: %w", port, err)
			}
			if err := conn.Close(); err != nil {
				return err
			}
			continue
		}
		if err == nil {
			return errors.Join(fmt.Errorf("unlisted peer reached TCP port %s", port), conn.Close())
		}
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() || ctx.Err() != nil {
			return fmt.Errorf("TCP port %s did not show packet drop: %w", port, err)
		}
	}
	return nil
}

func verifyPeerNFSUDPDrop(control net.Conn) (result error) {
	address := net.ParseIP(peerNFSServer)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: address, Port: 2049})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, listener.Close()) }()
	witness, err := net.ListenUDP("udp4", &net.UDPAddr{IP: address, Port: 30002})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, witness.Close()) }()
	if err := writePeerNFSMessage(control, "udp-ready\n"); err != nil {
		return err
	}
	if err := readPeerNFSMessage(control, "udp-sent\n"); err != nil {
		return err
	}
	if err := witness.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	var b [32]byte
	size, remote, err := witness.ReadFromUDP(b[:])
	if err != nil || remote.IP.String() != peerNFSAllowed || string(b[:size]) != "test" {
		return errors.Join(errors.New("UDP witness did not reach the unrelated port"), err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		return err
	}
	_, _, err = listener.ReadFromUDP(b[:])
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		return errors.Join(errors.New("UDP reached the filtered NFS port"), err)
	}
	return writePeerNFSMessage(control, "udp-blocked\n")
}

func probePeerNFSUDP(ctx context.Context, control net.Conn) error {
	if err := readPeerNFSMessage(control, "udp-ready\n"); err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: time.Second}
	for _, port := range []string{"2049", "30002"} {
		conn, err := dialer.DialContext(ctx, "udp4", net.JoinHostPort(peerNFSServer, port))
		if err != nil {
			return err
		}
		if err := errors.Join(writePeerNFSMessage(conn, "test"), conn.Close()); err != nil {
			return err
		}
	}
	if err := writePeerNFSMessage(control, "udp-sent\n"); err != nil {
		return err
	}
	return readPeerNFSMessage(control, "udp-blocked\n")
}

func acceptNFSPeer(listener *net.TCPListener, address string, deadline time.Time) (*net.TCPConn, error) {
	conn, err := listener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	if !conn.RemoteAddr().(*net.TCPAddr).IP.Equal(net.ParseIP(address)) {
		return nil, errors.Join(errors.New("unexpected peer control source"), conn.Close())
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	return conn, nil
}

func dialNFSPeer(ctx context.Context) (net.Conn, error) {
	for {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", peerNFSControl)
		if err == nil {
			deadline, _ := ctx.Deadline()
			if err := conn.SetDeadline(deadline); err != nil {
				return nil, errors.Join(err, conn.Close())
			}
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func writePeerNFSMessage(conn net.Conn, expect string) error {
	n, err := io.WriteString(conn, expect)
	if err != nil || n != len(expect) {
		return errors.Join(errors.New("incomplete peer control write"), err)
	}
	return nil
}

func readPeerNFSMessage(conn net.Conn, expect string) error {
	message := make([]byte, len(expect))
	if _, err := io.ReadFull(conn, message); err != nil || string(message) != expect {
		return errors.Join(errors.New("unexpected peer control message"), err)
	}
	return nil
}

func peerNFSCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	bounded, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	out, err := exec.CommandContext(bounded, name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("peer %s: %w: %s", name, err, out)
	}
	return out, nil
}

func checkPeerNFSMount(want bool) error {
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) != 6 || f[1] != peerNFSClientMount {
			continue
		}
		options := "," + f[3] + ","
		if found || f[0] != peerNFSSource || f[2] != "nfs" ||
			!strings.Contains(options, ",vers=3,") || !strings.Contains(options, ",proto=tcp,") ||
			!strings.Contains(options, ",mountproto=tcp,") {
			return errors.New("unexpected remote mount at the fixture path")
		}
		found = true
	}
	if found != want {
		return errors.New("remote NFSv3/TCP mount observation differs")
	}
	return nil
}
