// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

//go:build linux && qemu

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	rc0NFSServer    = "192.0.2.1"
	rc0NFSAllowed   = "192.0.2.2"
	rc0NFSDenied    = "192.0.2.3"
	rc0NFSControl   = rc0NFSServer + ":30001"
	rc0NFSExport    = "fixture-export"
	rc0NFSClientDir = "/run/rc0-nfs-client"
	rc0NFSGreeting  = "original RC0 export\n"
	rc0NFSReply     = "RC0 peer write\n"
)

func nfsServer(ctx context.Context, credentials []byte) error {
	nic, err := nfsInterface("52:54:00:12:34:01")
	if err != nil {
		return err
	}
	if err := setNFSIPv4(ctx, nic, rc0NFSServer); err != nil {
		return err
	}
	uid, gid, err := nfsAnonymousIdentity()
	if err != nil {
		return err
	}
	volume := fmt.Sprintf(`"volumes":[{"id":"boot-data","filesystem_uuid":%q}]`, storageUUID)
	export := fmt.Sprintf(`"exports":[{"id":"bbbbbbbb-cccc-dddd-eeee-ffffffffffff","volume_id":"boot-data","relative_path":%q,"clients":[{"network":%q,"access":"rw","squash":"all","anonymous_uid":%d,"anonymous_gid":%d,"security":"sys"}]}]`,
		rc0NFSExport, rc0NFSAllowed+"/32", uid, gid)
	confirmed := strings.Replace(policy, `"volumes":[]`, volume, 1)
	confirmed = strings.Replace(confirmed, `"exports":[]`, export, 1)
	if err := seed(ctx, credentials, confirmed, false); err != nil {
		return fmt.Errorf("NFS state provisioning: %w", err)
	}
	if err := os.WriteFile(proof, []byte(confirmed), 0600); err != nil {
		return err
	}
	dir := storageSource + "/" + rc0NFSExport
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/marker", []byte(rc0NFSGreeting), 0644); err != nil {
		return err
	}
	if err := prepareStorageApproval(nic.Index); err != nil {
		return err
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(rc0NFSServer), Port: 30001})
	if err != nil {
		return err
	}
	defer listener.Close()
	deadline, _ := ctx.Deadline()
	if err := listener.SetDeadline(deadline); err != nil {
		return err
	}
	if err := publishInitGrant(ctx, proof, func(plan *bootPlan) {
		plan.PolicySHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(confirmed)))
	}); err != nil {
		return fmt.Errorf("publish NFS boot grant: %w", err)
	}
	fmt.Println("PHANTOWD_RC0_NFS_GRANT policy=confirmed storage=approved ingress=selected")
	if err := runInitHook(ctx, "start"); err != nil {
		return fmt.Errorf("RC0 NFS startup: %w", err)
	}
	if err := nfsCommand(ctx, "/usr/sbin/nft", "-j", "list", "table", "inet", "phantowd_nfs"); err != nil {
		return err
	}
	if err := errors.Join(checkBootStorage(true), checkPersistentServiceLocks(true)); err != nil {
		return err
	}
	if err := announceNFSPeer(listener, rc0NFSDenied, deadline); err != nil {
		return err
	}
	client, err := acceptNFSTestPeer(listener, rc0NFSAllowed, deadline)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := readNFSTestMessage(client, "mounted\n"); err != nil {
		return err
	}
	var exit *exec.ExitError
	if err := runInitHook(ctx, "stop"); !errors.As(err, &exit) || ctx.Err() != nil {
		return errors.New("ordinary stop accepted a live NFS client")
	}
	if _, err := observeHTTPS(ctx, credentials); err != nil {
		return fmt.Errorf("management unavailable after refused stop: %w", err)
	}
	if err := errors.Join(checkBootStorage(true), checkPersistentServiceLocks(true)); err != nil {
		return err
	}
	if _, err := io.WriteString(client, "write\n"); err != nil {
		return err
	}
	if err := readNFSTestMessage(client, "unmounted\n"); err != nil {
		return err
	}
	if err := verifyNFSWrite(dir+"/reply", uid, gid); err != nil {
		return err
	}
	if err := nfsCommand(ctx, api, "--rc0-boot-service=stop-nfs-drained"); err != nil {
		return err
	}
	if err := errors.Join(verifyNFSRelease(ctx), checkBootStorage(false), checkPersistentServiceLocks(false)); err != nil {
		return err
	}
	if err := withdrawInitGrant(ctx); err != nil {
		return err
	}
	if _, err := io.WriteString(client, "verified\n"); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_RC0_NFS_SERVER boot=init nftables=verified mounted_stop=refused https=preserved write=verified squash=verified drain=confirmed release=verified")
	return nil
}

func nfsAnonymousIdentity() (int, int, error) {
	account, err := user.Lookup("phantowd")
	if err != nil {
		return 0, 0, err
	}
	uid, userErr := strconv.Atoi(account.Uid)
	gid, groupErr := strconv.Atoi(account.Gid)
	if userErr != nil || groupErr != nil || uid <= 0 || gid <= 0 {
		return 0, 0, errors.New("fixture anonymous identity invalid")
	}
	return uid, gid, nil
}

func verifyNFSWrite(path string, uid, gid int) error {
	data, err := os.ReadFile(path)
	if err != nil || string(data) != rc0NFSReply {
		return errors.Join(errors.New("remote NFS write missing from the original volume"), err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil || st.Uid != uint32(uid) || st.Gid != uint32(gid) {
		return errors.Join(errors.New("remote NFS write did not use the confirmed anonymous identity"), err)
	}
	return nil
}

func verifyNFSRelease(ctx context.Context) error {
	threads, err := os.ReadFile("/proc/fs/nfsd/threads")
	if err != nil || strings.TrimSpace(string(threads)) != "0" {
		return errors.Join(errors.New("NFSD threads remain after confirmed stop"), err)
	}
	for _, role := range []string{"/run/phantowd-nfs-state", "/run/rpcbind.sock", "/run/rpcbind.lock", control} {
		if _, err := os.Lstat(role); !os.IsNotExist(err) {
			return fmt.Errorf("NFS shutdown retained %s", role)
		}
	}
	tables, err := exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "list", "tables").CombinedOutput()
	if err != nil || strings.Contains(string(tables), `"phantowd_nfs"`) {
		return fmt.Errorf("NFS packet filter remained after shutdown: %s %w", tables, err)
	}
	return runtimeAbsent()
}

func nfsClient(ctx context.Context) error {
	nic, err := nfsInterface("52:54:00:12:34:02")
	if err != nil {
		return err
	}
	if err := setNFSIPv4(ctx, nic, rc0NFSDenied); err != nil {
		return err
	}
	probe, err := dialNFSTestPeer(ctx)
	if err != nil {
		return err
	}
	if err := errors.Join(readNFSTestMessage(probe, "ready\n"), probe.Close()); err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: 800 * time.Millisecond}
	target := rc0NFSServer + ":2049"
	nfs, err := dialer.DialContext(ctx, "tcp4", target)
	if err == nil {
		nfs.Close()
		return errors.New("nftables admitted the unlisted peer")
	}
	var timedOut net.Error
	if !errors.As(err, &timedOut) || !timedOut.Timeout() || ctx.Err() != nil {
		return fmt.Errorf("unlisted peer did not receive a silent drop: %w", err)
	}
	if err := setNFSIPv4(ctx, nic, rc0NFSAllowed); err != nil {
		return err
	}
	control, err := dialNFSTestPeer(ctx)
	if err != nil {
		return err
	}
	defer control.Close()
	if err := os.Mkdir(rc0NFSClientDir, 0700); err != nil {
		return err
	}
	if err := nfsCommand(ctx, "/bin/mount", "-t", "nfs", "-o",
		"vers=3,proto=tcp,mountproto=tcp,nolock,soft,timeo=5,retrans=1",
		rc0NFSServer+":"+storageTarget+"/"+rc0NFSExport, rc0NFSClientDir); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(rc0NFSClientDir, &fs); err != nil || fs.Type != unix.NFS_SUPER_MAGIC {
		return errors.Join(errors.New("client did not mount an NFS filesystem"), err)
	}
	if data, err := os.ReadFile(rc0NFSClientDir + "/marker"); err != nil || string(data) != rc0NFSGreeting {
		return errors.Join(errors.New("remote export did not return the original marker"), err)
	}
	if _, err := io.WriteString(control, "mounted\n"); err != nil {
		return err
	}
	if err := readNFSTestMessage(control, "write\n"); err != nil {
		return err
	}
	file, err := os.OpenFile(rc0NFSClientDir+"/reply", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = io.WriteString(file, rc0NFSReply)
	if err := errors.Join(err, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := unix.Unmount(rc0NFSClientDir, 0); err != nil {
		return err
	}
	if _, err := io.WriteString(control, "unmounted\n"); err != nil {
		return err
	}
	if err := readNFSTestMessage(control, "verified\n"); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_RC0_NFS_CLIENT transport=nfs3-tcp unlisted=dropped read=verified fsync=verified unmount=verified")
	return nil
}

func nfsInterface(mac string) (net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}
	for _, nic := range interfaces {
		if nic.HardwareAddr.String() == mac {
			return nic, nil
		}
	}
	return net.Interface{}, errors.New("isolated NFS fixture interface absent")
}

func setNFSIPv4(ctx context.Context, nic net.Interface, addr string) error {
	return nfsCommand(ctx, "/sbin/ifconfig", nic.Name, addr, "netmask", "255.255.255.248", "up")
}

func nfsCommand(ctx context.Context, path string, args ...string) error {
	output, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", path, err, output)
	}
	return nil
}

func announceNFSPeer(listener *net.TCPListener, address string, deadline time.Time) error {
	conn, err := acceptNFSTestPeer(listener, address, deadline)
	if err != nil {
		return err
	}
	_, err = io.WriteString(conn, "ready\n")
	return errors.Join(err, conn.Close())
}

func acceptNFSTestPeer(listener *net.TCPListener, address string, deadline time.Time) (*net.TCPConn, error) {
	conn, err := listener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	if !conn.RemoteAddr().(*net.TCPAddr).IP.Equal(net.ParseIP(address)) {
		return nil, errors.Join(errors.New("unexpected NFS test peer address"), conn.Close())
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	return conn, nil
}

func dialNFSTestPeer(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	for {
		conn, err := dialer.DialContext(ctx, "tcp4", rc0NFSControl)
		if err == nil {
			deadline, _ := ctx.Deadline()
			if err := conn.SetDeadline(deadline); err != nil {
				return nil, errors.Join(err, conn.Close())
			}
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("NFS peer control unavailable: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func readNFSTestMessage(conn net.Conn, expected string) error {
	message := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, message); err != nil {
		return err
	}
	if string(message) != expected {
		return fmt.Errorf("unexpected NFS test peer reply %q", message)
	}
	return nil
}
