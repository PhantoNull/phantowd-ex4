// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

//go:build linux && qemu

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

const (
	smbID      = "fixture-writer"
	smbName    = "rc0writer"
	smbShare   = "RCDocuments"
	smbFolder  = "documents"
	smbMarker  = "RC0 original SMB share\n"
	smbPayload = "RC0 authenticated SMB write\n"
)

func seedSMBUnixIdentity(ctx context.Context) (result error) {
	inventory := func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	}
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	native, err := identityowner.OpenProvisioned(directory, inventory)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, native.Close()) }()
	account, err := native.Reserve(ctx, 1, smbID, smbName)
	if err != nil {
		return err
	}
	if account.UID != 23000 || account.GID != 23000 {
		return errors.New("fixture Unix identity differs")
	}
	operation := native.Operation(smbID)
	for attempt := 0; attempt < 2; attempt++ {
		journal, err := operation.Load(ctx)
		if err != nil {
			return err
		}
		if err := operation.Step(ctx, journal.Revision); err != nil {
			return err
		}
	}
	return nil
}

func configureSMBAccount(ctx context.Context, action string, secret []byte) error {
	cmd := exec.CommandContext(ctx, api, "--configure-rc0-samba-account="+action, "--rc0-samba-identity-id="+smbID)
	return provision(ctx, cmd, root, secret)
}

func seedSMBAccount(ctx context.Context, secret []byte) error {
	if err := seedSMBUnixIdentity(ctx); err != nil {
		return err
	}
	if err := configureSMBAccount(ctx, "enable", nil); err == nil || ctx.Err() != nil {
		return errors.New("Samba enabled an account before credential setup")
	}
	if err := configureSMBAccount(ctx, "create-disabled", nil); err != nil {
		return fmt.Errorf("create disabled account: %w", err)
	}
	if err := configureSMBAccount(ctx, "set-password", secret); err != nil {
		return fmt.Errorf("set initial password: %w", err)
	}
	if err := configureSMBAccount(ctx, "set-password", []byte("unexpected replacement password")); err == nil || ctx.Err() != nil {
		return errors.New("initial Samba password action accepted a replacement")
	}
	if err := configureSMBAccount(ctx, "enable", nil); err != nil {
		return fmt.Errorf("enable provisioned account: %w", err)
	}
	return nil
}

func smbServer(ctx context.Context, credentials, secret []byte, phase string) error {
	nic, err := nfsInterface("52:54:00:12:34:01")
	if err != nil {
		return err
	}
	if err := setNFSIPv4(ctx, nic, rc0NFSServer); err != nil {
		return err
	}
	volumes := fmt.Sprintf(`"volumes":[{"id":"boot-data","filesystem_uuid":%q}]`, storageUUID)
	users := fmt.Sprintf(`"users":[{"id":%q,"name":%q}]`, smbID, smbName)
	shares := fmt.Sprintf(`"shares":[{"id":"rc0-documents","name":%q,"volume_id":"boot-data","relative_path":%q,"grants":[{"user_id":%q,"access":"rw"}]}]`,
		smbShare, smbFolder, smbID)
	confirmed := strings.NewReplacer(`"volumes":[]`, volumes, `"users":[]`, users, `"shares":[]`, shares).Replace(policy)
	if err := seed(ctx, credentials, confirmed, false); err != nil {
		return fmt.Errorf("SMB state preparation: %w", err)
	}
	if err := seedSMBAccount(ctx, secret); err != nil {
		return fmt.Errorf("SMB account preparation: %w", err)
	}
	dir := storageSource + "/" + smbFolder
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err := os.Chown(dir, 23000, 23000); err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/marker", []byte(smbMarker), 0644); err != nil {
		return err
	}
	if err := errors.Join(os.WriteFile(proof, []byte(confirmed), 0600), prepareNetworkStorageApproval("smb", nic.Index)); err != nil {
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
		return fmt.Errorf("SMB grant publication: %w", err)
	}
	if err := runInitHook(ctx, "start"); err != nil {
		return fmt.Errorf("SMB normal startup: %w", err)
	}
	if err := configureSMBAccount(ctx, "enable", nil); err == nil || ctx.Err() != nil {
		return errors.New("offline Samba configuration accepted a live state mount")
	}
	fmt.Println("PHANTOWD_RC0_SMB_ENROLLMENT cli=verified early_enable=refused replacement=refused live_state=refused")
	if err := errors.Join(checkBootStorage(true), checkPersistentServiceLocks(true)); err != nil {
		return err
	}
	peer, err := acceptNFSTestPeer(listener, rc0NFSAllowed, deadline)
	if err != nil {
		return err
	}
	defer peer.Close()
	if _, err := io.WriteString(peer, "ready\n"); err != nil {
		return err
	}
	if err := waitSMBContents(ctx, dir+"/written", smbPayload); err != nil {
		return fmt.Errorf("SMB write missed original storage: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Stat(dir+"/written", &st); err != nil || st.Uid != 23000 || st.Gid != 23000 {
		return errors.Join(errors.New("SMB write missed its Unix identity"), err)
	}
	if _, err := io.WriteString(peer, "written\n"); err != nil {
		return err
	}
	if err := readNFSTestMessage(peer, "held\n"); err != nil {
		return err
	}
	if phase == "smb-loss-server" {
		return smbLossServer(ctx, credentials, peer)
	}
	if err := readSMBStopReply(ctx, 'B'); err != nil {
		return err
	}
	if _, err := observeHTTPS(ctx, credentials); err != nil {
		return fmt.Errorf("HTTPS after SMB drain refusal: %w", err)
	}
	if _, err := io.WriteString(peer, "fenced\n"); err != nil {
		return err
	}
	if err := readNFSTestMessage(peer, "closed\n"); err != nil {
		return err
	}
	if phase == "smb-legacy-server" {
		if err := readSMBStopReply(ctx, 'B'); err != nil {
			return err
		}
		if _, err := observeHTTPS(ctx, credentials); err != nil {
			return err
		}
		fmt.Println("PHANTOWD_RC0_SMB_LEGACY_SERVER boot=init storage=approved busy_stop=refused https=preserved unqualified=refused")
	} else {
		if err := runInitHook(ctx, "stop"); err != nil {
			return err
		}
		tables, err := exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "list", "tables").Output()
		if err != nil || bytes.Contains(tables, []byte(`"phantowd_smb"`)) {
			return errors.Join(errors.New("SMB table retained after clean stop"), err)
		}
		if err := errors.Join(runtimeAbsent(), checkBootStorage(false), checkPersistentServiceLocks(false)); err != nil {
			return err
		}
		if err := withdrawInitGrant(ctx); err != nil {
			return err
		}
		fmt.Println("PHANTOWD_RC0_SMB_SERVER boot=init storage=approved busy_stop=refused https=preserved drain=verified release=verified")
	}
	_, err = io.WriteString(peer, "verified\n")
	return err
}

func readSMBStopReply(ctx context.Context, expected byte) error {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", control+"/stop")
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "S"); err != nil {
		return err
	}
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != expected {
		return fmt.Errorf("SMB stop returned %q, expected %q", reply[0], expected)
	}
	return nil
}

func smbClient(ctx context.Context, loss bool) error {
	nic, err := nfsInterface("52:54:00:12:34:02")
	if err != nil {
		return err
	}
	if err := setNFSIPv4(ctx, nic, rc0NFSAllowed); err != nil {
		return err
	}
	peer, err := dialNFSTestPeer(ctx)
	if err != nil {
		return err
	}
	defer peer.Close()
	if err := readNFSTestMessage(peer, "ready\n"); err != nil {
		return err
	}
	secret, err := os.ReadFile("/rc0-fixture/password")
	if err != nil {
		return err
	}
	auth := fmt.Appendf(nil, "username = %s\npassword = %s\n", smbName, bytes.TrimSpace(secret))
	defer clear(auth)
	const file = "/run/rc0-smb-auth"
	if err := os.WriteFile(file, auth, 0600); err != nil {
		return err
	}
	defer os.Remove(file)
	if err := os.WriteFile("/run/rc0-smb-payload", []byte(smbPayload), 0600); err != nil {
		return err
	}
	client := exec.CommandContext(ctx, "/usr/bin/smbclient", "-A", file, "-m", "SMB3", "//"+rc0NFSServer+"/"+smbShare)
	client.Stdout, client.Stderr = os.Stdout, os.Stderr
	input, err := client.StdinPipe()
	if err != nil {
		return err
	}
	if err := client.Start(); err != nil {
		return err
	}
	defer func() {
		_ = input.Close()
		_ = client.Process.Kill()
		_ = client.Wait()
	}()
	if _, err := io.WriteString(input, "put /run/rc0-smb-payload written\n"); err != nil {
		return err
	}
	if err := readNFSTestMessage(peer, "written\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(input, "get marker /run/rc0-smb-original\n"); err != nil {
		return err
	}
	if err := waitSMBContents(ctx, "/run/rc0-smb-original", smbMarker); err != nil {
		return err
	}
	if _, err := io.WriteString(peer, "held\n"); err != nil {
		return err
	}
	if loss {
		return smbLossClient(ctx, peer)
	}
	if err := readNFSTestMessage(peer, "fenced\n"); err != nil {
		return err
	}
	if err := requireSMBConnectionDrop(ctx); err != nil {
		return err
	}
	if _, err := io.WriteString(input, "get marker /run/rc0-smb-fenced\n"); err != nil {
		return err
	}
	if err := waitSMBContents(ctx, "/run/rc0-smb-fenced", smbMarker); err != nil {
		return err
	}
	if _, err := io.WriteString(input, "quit\n"); err != nil {
		return err
	}
	if err := errors.Join(input.Close(), client.Wait()); err != nil {
		return err
	}
	if _, err := io.WriteString(peer, "closed\n"); err != nil {
		return err
	}
	if err := readNFSTestMessage(peer, "verified\n"); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_RC0_SMB_CLIENT read=verified write=verified authenticated=verified new_connection=dropped fenced_read=verified")
	return nil
}

func requireSMBConnectionDrop(ctx context.Context) error {
	dialer := net.Dialer{Timeout: 800 * time.Millisecond}
	peer, err := dialer.DialContext(ctx, "tcp4", rc0NFSServer+":445")
	if err == nil {
		peer.Close()
		return errors.New("new SMB connection reached a blocked service")
	}
	var timeout net.Error
	if ctx.Err() != nil || !errors.As(err, &timeout) || !timeout.Timeout() {
		return fmt.Errorf("blocked SMB connection was not dropped: %w", err)
	}
	return nil
}

func waitSMBContents(ctx context.Context, path, contents string) error {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		data, err := os.ReadFile(path)
		if err == nil && string(data) == contents {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("SMB did not reach the expected file contents: %w", ctx.Err())
		case <-tick.C:
		}
	}
}
