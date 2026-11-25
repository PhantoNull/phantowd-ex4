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
	if mode == "peer-server" {
		return serveQEMUManagedNFS(ctx)
	}
	if !nfskernel.PeerClientQEMU() {
		return errors.New("separate NFS client requires fixed QEMU role")
	}
	return useQEMUManagedNFS(ctx)
}

func serveQEMUManagedNFS(ctx context.Context) error {
	if !nfskernel.PeerServerQEMU() {
		return nfskernel.ErrRefused
	}
	if _, err := peerNFSInterface("52:54:00:12:34:01", peerNFSServer); err != nil {
		return err
	}
	if err := guardQEMUDataVolume(); err != nil {
		return err
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
	fmt.Println("PHANTOWD_NFS_PEER_SERVER_READY kernel_backend=true activation=true managed=true remote_bytes=true mapped_identity=true tables=private teardown=clean scope=isolated-two-guest-only")
	return nil
}

func useQEMUManagedNFS(ctx context.Context) error {
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
	out, err := mount()
	message := strings.ToLower(string(out))
	if err == nil || !strings.Contains(message, "access denied by server") && !strings.Contains(message, "permission denied") {
		return fmt.Errorf("unlisted peer did not receive an NFS access refusal: %v %s", err, out)
	}
	if err := checkPeerNFSMount(false); err != nil {
		return err
	}
	if _, err := peerNFSCommand(ctx, "/sbin/ifconfig", device, peerNFSAllowed, "netmask", "255.255.255.248", "up"); err != nil {
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
	fmt.Println("PHANTOWD_NFS_PEER_CLIENT_READY protocol=nfs3 transport=tcp denied_source=true read=true write=true fsync=true unmount=clean scope=isolated-two-guest-only")
	return nil
}

func peerNFSInterface(mac, address string) (string, error) {
	devices, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, device := range devices {
		if device.HardwareAddr.String() != mac {
			continue
		}
		addrs, err := device.Addrs()
		if err != nil {
			return "", err
		}
		var ipv4 []string
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil {
				return "", err
			}
			if prefix.Addr().Is4() {
				ipv4 = append(ipv4, prefix.String())
			}
		}
		if len(ipv4) == 1 && ipv4[0] == address+"/29" {
			return device.Name, nil
		}
	}
	return "", errors.New("unexpected peer interface address")
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
