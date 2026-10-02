//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/smbconfig"
)

const smbFixtureRoot = "/run/phantowd-smb-policy-test"
const smbFixtureAnchor = "/srv/phantowd/volumes/" + qemuNFSVolumeID

func qemuSMBPolicy() (smbconfig.Preview, error) {
	config := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "qemu-only", FilesystemUUID: qemuNFSVolumeUUID}},
		Users:   []shareconfig.User{{ID: "writer", Name: "qpwriter"}, {ID: "reader", Name: "qpreader"}, {ID: "outsider", Name: "qpoutsider"}},
		Shares: []shareconfig.Share{
			{ID: "shared", Name: "PolicyShare", VolumeID: "qemu-only", RelativePath: "smb-policy-shared", Grants: []shareconfig.Grant{{UserID: "writer", Access: "rw"}, {UserID: "reader", Access: "ro"}}},
			{ID: "blocked", Name: "UnixDenied", VolumeID: "qemu-only", RelativePath: "smb-policy-denied", Grants: []shareconfig.Grant{{UserID: "writer", Access: "rw"}}},
		}}
	return smbconfig.Build(config)
}

// This guard is deliberately fixture-specific, not a product volume resolver.
func guardQEMUDataVolume() error {
	if runtime.GOARCH != "arm" || strings.Split(buildARMLevel(), ",")[0] != "5" || os.Geteuid() != 0 {
		return errors.New("SMB fixture requires root inside ARMv5 QEMU")
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("SMB fixture requires Versatile PB")
	}
	if err := verifyQEMUNFSDevice(os.DirFS("/sys")); err != nil {
		return err
	}
	// The NFS harness already mounted the fresh test disk. Require the exact
	// kernel node to back this mount, not a directory on the guest system disk.
	device, err := os.ReadFile("/sys/class/block/sdb/dev")
	if err != nil {
		return err
	}
	mounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
	if err != nil {
		return err
	}
	for _, mount := range mounts.Mounts {
		if mount.MountPoint == smbFixtureAnchor && fmt.Sprintf("%d:%d", mount.DeviceMajor, mount.DeviceMinor) == strings.TrimSpace(string(device)) && !mount.ReadOnly && (mount.Filesystem == "ext2" || mount.Filesystem == "ext4") {
			return nil
		}
	}
	return errors.New("SMB fixture disposable data volume is not mounted")
}

func smbFixtureCommand(input string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return smbFixtureCommandContext(ctx, input, name, args...)
}

func smbFixtureCommandContext(ctx context.Context, input string, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("SMB fixture command context missing")
	}
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.Stdin = strings.NewReader(input)
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return nil, errors.New("SMB fixture command timed out")
	}
	return output, err
}

func runQEMUSMBTest() (result error) {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	preview, err := qemuSMBPolicy()
	if err != nil {
		return err
	}
	if err := os.Mkdir(smbFixtureRoot, 0700); err != nil {
		return err
	}
	// Kept for diagnostics until this disposable guest exits. No recursive
	// deletion, production account provisioning or product-config mutation.
	for _, name := range []string{"private", "lock", "state", "cache", "pid", "rpc"} {
		if err := os.Mkdir(filepath.Join(smbFixtureRoot, name), 0700); err != nil {
			return err
		}
	}
	config := "[global]\nserver role = standalone server\nsecurity = user\nmap to guest = Never\ninterfaces = 127.0.0.1\nbind interfaces only = yes\nsmb ports = 1445\nserver min protocol = SMB3_00\nserver max protocol = SMB3_11\nload printers = no\nprinting = bsd\nprintcap name = /dev/null\n"
	for key, directory := range map[string]string{"private dir": "private", "lock directory": "lock", "state directory": "state", "cache directory": "cache", "pid directory": "pid", "ncalrpc dir": "rpc"} {
		config += key + " = " + smbFixtureRoot + "/" + directory + "\n"
	}
	config += "passdb backend = tdbsam:" + smbFixtureRoot + "/private/passdb.tdb\n" + preview.Sections
	configPath := smbFixtureRoot + "/smb.conf"
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return err
	}
	if output, err := smbFixtureCommand("", "/usr/bin/testparm", "-s", configPath); err != nil {
		return fmt.Errorf("SMB fixture parser failed: %s", output)
	}
	if output, err := smbFixtureCommand("", "/usr/sbin/addgroup", "-g", "1800", "qpgroup"); err != nil {
		return fmt.Errorf("SMB fixture group failed: %s", output)
	}
	users := []string{}
	defer func() {
		for _, user := range users {
			if _, err := smbFixtureCommand("", "/usr/sbin/deluser", user); err != nil {
				result = errors.Join(result, errors.New("SMB fixture user cleanup failed"))
			}
		}
		if _, err := smbFixtureCommand("", "/usr/sbin/delgroup", "qpgroup"); err != nil {
			result = errors.Join(result, errors.New("SMB fixture group cleanup failed"))
		}
	}()
	for i, user := range []string{"qpwriter", "qpreader", "qpoutsider"} {
		if output, err := smbFixtureCommand("", "/usr/sbin/adduser", "-D", "-H", "-s", "/sbin/nologin", "-G", "qpgroup", "-u", fmt.Sprint(1801+i), user); err != nil {
			return fmt.Errorf("SMB fixture user failed: %s", output)
		}
		users = append(users, user)
		// Public test credential only; stdin/private auth files, never argv.
		const password = "disposable-qemu-fixture-only"
		if output, err := smbFixtureCommand(password+"\n"+password+"\n", "/usr/bin/smbpasswd", "-s", "-a", "-c", configPath, user); err != nil {
			return fmt.Errorf("SMB fixture passdb failed: %s", output)
		}
		if err := os.WriteFile(smbFixtureRoot+"/"+user+".auth", []byte("username = "+user+"\npassword = "+password+"\n"), 0600); err != nil {
			return err
		}
	}
	if err := os.WriteFile(smbFixtureRoot+"/qpwrong.auth", []byte("username = qpwriter\npassword = deliberately-wrong-fixture-value\n"), 0600); err != nil {
		return err
	}
	shared, denied := smbFixtureAnchor+"/smb-policy-shared", smbFixtureAnchor+"/smb-policy-denied"
	if err := os.Mkdir(shared, 0770); err != nil {
		return err
	}
	if err := os.Chown(shared, 1801, 1800); err != nil {
		return err
	}
	if err := os.Chmod(shared, 0770); err != nil {
		return err
	}
	if err := os.Mkdir(denied, 0700); err != nil {
		return err
	}
	if err := os.Symlink("/etc/passwd", shared+"/escape"); err != nil {
		return err
	}
	payload := []byte("phantowd-smb-generated-policy-v1\n")
	if err := os.WriteFile(smbFixtureRoot+"/upload", payload, 0600); err != nil {
		return err
	}
	clientWithContext := func(ctx context.Context, user, share, operation string) ([]byte, error) {
		return smbFixtureCommandContext(ctx, "", "/usr/bin/smbclient", "-t", "2", "-m", "SMB3_11", "-p", "1445", "-A", smbFixtureRoot+"/"+user+".auth", "//127.0.0.1/"+share, "-c", operation)
	}
	client := func(user, share, operation string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return clientWithContext(ctx, user, share, operation)
	}
	owner := processowner.New()
	if _, err := owner.Start(context.Background(), processowner.Spec{
		Executable: "/usr/sbin/smbd",
		Args:       []string{"-F", "--no-process-group", "-s", configPath},
		Ready: func(ctx context.Context) (bool, error) {
			_, err := clientWithContext(ctx, "qpwriter", "PolicyShare", "ls")
			return err == nil, nil
		},
		ReadyTimeout: 5 * time.Second, ProbeInterval: 200 * time.Millisecond, StopTimeout: 3 * time.Second,
	}); err != nil {
		return fmt.Errorf("SMB fixture did not become ready: %s", string(owner.Diagnostics()))
	}
	ownerStopped := false
	defer func() {
		// Only the process group started by this fixture is owned; the stock
		// guest smbd is never discovered, adopted or signalled.
		if ownerStopped {
			return
		}
		if _, err := owner.Stop(context.Background()); err != nil {
			result = errors.Join(result, errors.New("SMB fixture daemon stop requires review"))
		}
	}()
	var output []byte
	output, err = client("qpwriter", "PolicyShare", "ls")
	if err != nil {
		return fmt.Errorf("SMB fixture not ready: %s", output)
	}
	// Refuse any listener on this test port other than IPv4 loopback.
	for _, name := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if err := checkSMBFixtureListeners(string(data)); err != nil {
			return err
		}
	}
	if output, err := client("qpwriter", "PolicyShare", "put "+smbFixtureRoot+"/upload created"); err != nil {
		return fmt.Errorf("SMB writer rejected: %s", output)
	}
	content, err := os.ReadFile(shared + "/created")
	if err != nil || !bytes.Equal(content, payload) {
		return errors.New("SMB writer content mismatch")
	}
	info, err := os.Lstat(shared + "/created")
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("SMB writer file missing")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 1801 || stat.Gid != 1800 || info.Mode().Perm()&0007 != 0 {
		return errors.New("SMB writer Unix ownership/mode mismatch")
	}
	if output, err := client("qpreader", "PolicyShare", "get created "+smbFixtureRoot+"/download"); err != nil {
		return fmt.Errorf("SMB reader rejected: %s", output)
	}
	content, err = os.ReadFile(smbFixtureRoot + "/download")
	if err != nil || !bytes.Equal(content, payload) {
		return errors.New("SMB reader content mismatch")
	}
	for _, test := range []struct{ user, share, operation, code string }{
		{"qpwrong", "PolicyShare", "ls", "NT_STATUS_LOGON_FAILURE"},
		{"qpreader", "PolicyShare", "put " + smbFixtureRoot + "/upload denied-write", "NT_STATUS_ACCESS_DENIED"},
		{"qpoutsider", "PolicyShare", "ls", "NT_STATUS_ACCESS_DENIED"},
		{"qpwriter", "UnixDenied", "put " + smbFixtureRoot + "/upload denied-write", "NT_STATUS_ACCESS_DENIED"},
		// The pinned Samba returns the specific SMB2 symbolic-link error,
		// not OBJECT_NAME_NOT_FOUND. Require failed client exit AND this code;
		// the downloaded-file absence check below also remains mandatory.
		{"qpwriter", "PolicyShare", "get escape " + smbFixtureRoot + "/escape-download", "NT_STATUS_STOPPED_ON_SYMLINK"},
	} {
		output, err := client(test.user, test.share, test.operation)
		if !smbFixtureDenied(output, err, test.code) {
			return fmt.Errorf("SMB denial not verified (%s/%s): %s (%v)", test.user, test.share, output, err)
		}
	}
	for _, name := range []string{shared + "/denied-write", denied + "/denied-write", smbFixtureRoot + "/escape-download"} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("SMB denial left an unexpected file")
		}
	}
	// These are new connections, not revocation of already authenticated
	// sessions. Keep the daemon alive throughout: no restart may hide caching.
	unchanged := make(map[string][]byte)
	for _, path := range []string{"/etc/passwd", "/etc/group", "/etc/shadow", configPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		unchanged[path] = data
	}
	const rotatedPassword = "rotated-disposable-qemu-fixture-only"
	if output, err := smbFixtureCommand(rotatedPassword+"\n"+rotatedPassword+"\n", "/usr/bin/smbpasswd", "-s", "-c", configPath, "qpwriter"); err != nil {
		return fmt.Errorf("SMB fixture password rotation failed: %s (%v)", output, err)
	}
	if err := os.WriteFile(smbFixtureRoot+"/qprotated.auth", []byte("username = qpwriter\npassword = "+rotatedPassword+"\n"), 0600); err != nil {
		return err
	}
	output, err = client("qpwriter", "PolicyShare", "ls")
	if !smbFixtureDenied(output, err, "NT_STATUS_LOGON_FAILURE") {
		return fmt.Errorf("SMB old password not refused: %s (%v)", output, err)
	}
	if output, err := client("qprotated", "PolicyShare", "get created "+smbFixtureRoot+"/rotated-download"); err != nil {
		return fmt.Errorf("SMB rotated credential rejected: %s (%v)", output, err)
	}
	if err := exerciseQEMUSMBSessionRevocation(configPath, smbFixtureRoot+"/qprotated.auth", smbFixtureRoot+"/qpreader.auth", shared, smbFixtureRoot+"/upload", payload); err != nil {
		return err
	}
	// A separate new reader connection must remain usable after the targeted
	// session shutdown of the disabled writer.
	if output, err := client("qpreader", "PolicyShare", "get created "+smbFixtureRoot+"/unaffected-download"); err != nil {
		return fmt.Errorf("SMB unrelated reader affected by disable: %s (%v)", output, err)
	}
	if output, err := smbFixtureCommand("", "/usr/bin/smbpasswd", "-e", "-c", configPath, "qpwriter"); err != nil {
		return fmt.Errorf("SMB fixture enable failed: %s (%v)", output, err)
	}
	output, err = client("qpwriter", "PolicyShare", "ls")
	if !smbFixtureDenied(output, err, "NT_STATUS_LOGON_FAILURE") {
		return fmt.Errorf("SMB enable restored obsolete password: %s (%v)", output, err)
	}
	if output, err := client("qprotated", "PolicyShare", "put "+smbFixtureRoot+"/upload reenabled"); err != nil {
		return fmt.Errorf("SMB reenabled writer rejected: %s (%v)", output, err)
	}
	for _, path := range []string{shared + "/created", shared + "/reenabled"} {
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, payload) {
			return errors.New("SMB credential lifecycle changed data")
		}
		current, err := os.Lstat(path)
		if err != nil || !current.Mode().IsRegular() {
			return errors.New("SMB credential lifecycle file missing")
		}
		currentStat, ok := current.Sys().(*syscall.Stat_t)
		if !ok || currentStat.Uid != 1801 || currentStat.Gid != 1800 || current.Mode().Perm()&0007 != 0 {
			return errors.New("SMB credential lifecycle ownership/mode mismatch")
		}
		if path == shared+"/created" && (!os.SameFile(info, current) || current.Mode() != info.Mode()) {
			return errors.New("SMB credential lifecycle replaced original inode or permissions")
		}
	}
	for _, name := range []string{"rotated-download", "unaffected-download"} {
		data, err := os.ReadFile(smbFixtureRoot + "/" + name)
		if err != nil || !bytes.Equal(data, payload) {
			return errors.New("SMB credential lifecycle download mismatch")
		}
	}
	for path, before := range unchanged {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			return errors.New("SMB credential lifecycle changed Unix identity or share configuration")
		}
	}
	fmt.Println("PHANTOWD_SMB_CREDENTIALS_READY rotated=true old_password_denied=true disabled_denied=true reenabled=true unix_identity_unchanged=true data_preserved=true scope=new-qemu-connections-only")
	if err := exerciseQEMUBootIdentityOwnerService(); err != nil {
		return err
	}
	if err := exerciseQEMUUnixIdentity(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_UNIX_IDENTITY_READY exclusions=true partial_detected=true exact_binding=true conflict_refused=true cleanup_verified=true scope=local-qemu-files-only")
	fmt.Println("PHANTOWD_IDENTITY_PROVISION_READY durable_intents=true confirmed_group_reopened=true unix_confirmed=true scope=isolated-qemu-backend-only")
	fmt.Println("PHANTOWD_IDENTITY_EXEC_READY binary=pinned-busybox typed_commands=true unix_login_locked=true nologin=true home_created=false scope=isolated-qemu-only")
	fmt.Println("PHANTOWD_IDENTITY_CHANNEL_READY peer_uid=65534 server_uid=0 journaled_steps=true stale_replay_denied=true scope=isolated-qemu-only")
	fmt.Println("PHANTOWD_IDENTITY_OWNER_READY lease_exclusive=true pending_blocks_reservation=true after_reopen=true scope=isolated-qemu-only")
	// The identity/passdb integration above shares this disposable smbd instance.
	// Stop the fixture-owned process group only after all such observations finish.
	if _, err := owner.Stop(context.Background()); err != nil {
		return errors.New("SMB fixture daemon stop requires review")
	}
	ownerStopped = true
	fmt.Println("PHANTOWD_SMB_POLICY_IO_READY generated=true writer_uid=1801 reader_ro=true outsider_denied=true unix_denied=true symlink_denied=true process_owner=started-ready-stopped scope=qemu-fixture-only")
	if err := exerciseQEMUProcessOwnerUnexpectedExit(owner); err != nil {
		return err
	}
	if err := exerciseQEMUProcessOwnerForcedStop(); err != nil {
		return err
	}
	if err := exerciseQEMUProcessOwnerFailedStartCleanup(); err != nil {
		return err
	}
	return nil
}

// Exercise the process-owner quarantine path with a disposable, controlled
// child. The production-facing SMB fixture above separately owns a real smbd;
// this child makes the unexpected-exit boundary deterministic without
// signalling any guest service outside its private process group.
func exerciseQEMUProcessOwnerUnexpectedExit(owner *processowner.Owner) (result error) {
	readyPath := filepath.Join(smbFixtureRoot, "process-owner-ready")
	exitPath := filepath.Join(smbFixtureRoot, "process-owner-exit")
	for _, path := range []string{readyPath, exitPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	defer os.Remove(readyPath)
	defer os.Remove(exitPath)

	cleanupNeeded := false
	defer func() {
		if !cleanupNeeded {
			return
		}
		_ = os.WriteFile(exitPath, []byte("exit"), 0600)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := owner.Stop(ctx)
		if err != nil && !errors.Is(err, processowner.ErrReviewRequired) {
			result = errors.Join(result, fmt.Errorf("controlled process cleanup failed: %w", err))
		}
	}()

	const child = `printf ready > "$1"; while [ ! -e "$2" ]; do :; done; exit 23`
	started, err := owner.Start(context.Background(), processowner.Spec{
		Executable: "/bin/busybox",
		Args:       []string{"sh", "-c", child, "phantowd-process-owner", readyPath, exitPath},
		Ready: func(ctx context.Context) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			_, err := os.Stat(readyPath)
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return err == nil, err
		},
		ReadyTimeout: 3 * time.Second, ProbeInterval: 20 * time.Millisecond,
		StopTimeout: time.Second,
	})
	if err != nil {
		return fmt.Errorf("controlled process did not become ready: %w", err)
	}
	cleanupNeeded = true
	if started.State != processowner.StateReady || started.Generation != 2 || started.PID <= 1 {
		return fmt.Errorf("controlled process readiness was not recorded: %+v", started)
	}
	if err := os.WriteFile(exitPath, []byte("exit"), 0600); err != nil {
		return err
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		observed, observeErr := owner.Observe(context.Background())
		if errors.Is(observeErr, processowner.ErrReviewRequired) {
			if observed.State != processowner.StateReviewRequired ||
				observed.Generation != started.Generation || observed.PID != started.PID {
				return fmt.Errorf("unexpected exit produced the wrong review state: %+v", observed)
			}
			break
		}
		if observeErr != nil {
			return fmt.Errorf("observe controlled process exit: %w", observeErr)
		}
		if time.Now().After(deadline) {
			return errors.New("process owner did not quarantine the unexpected exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := owner.Start(context.Background(), processowner.Spec{}); !errors.Is(err, processowner.ErrReviewRequired) {
		return fmt.Errorf("process owner restarted after an unexpected exit: %v", err)
	}
	stopped, stopErr := owner.Stop(context.Background())
	if !errors.Is(stopErr, processowner.ErrReviewRequired) ||
		stopped.State != processowner.StateReviewRequired ||
		stopped.Generation != started.Generation || stopped.PID != 0 {
		return fmt.Errorf("unexpected-exit cleanup lost review state: snapshot=%+v err=%v", stopped, stopErr)
	}
	if err := syscall.Kill(-started.PID, 0); !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("unexpected-exit process group remains or is uncertain: %v", err)
	}
	cleanupNeeded = false
	fmt.Println("PHANTOWD_PROCESS_OWNER_REVIEW_READY unexpected_exit=true review_required=true restart_blocked=true group_reaped=true scope=qemu-fixture-only")
	return nil
}

// Verify that the Owner escalates a bounded stop when its private child ignores
// SIGTERM. The child is intentionally synthetic; no guest service is signalled.
func exerciseQEMUProcessOwnerForcedStop() (result error) {
	readyPath := filepath.Join(smbFixtureRoot, "process-owner-ignore-term-ready")
	if err := os.Remove(readyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	defer os.Remove(readyPath)

	owner := processowner.New()
	cleanupNeeded := false
	defer func() {
		if !cleanupNeeded {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := owner.Stop(ctx)
		if err != nil && !errors.Is(err, processowner.ErrReviewRequired) {
			result = errors.Join(result, fmt.Errorf("forced-stop child cleanup failed: %w", err))
		}
	}()

	const child = `trap '' TERM; printf ready > "$1"; while :; do :; done`
	started, err := owner.Start(context.Background(), processowner.Spec{
		Executable: "/bin/busybox",
		Args:       []string{"sh", "-c", child, "phantowd-process-owner", readyPath},
		Ready: func(ctx context.Context) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			_, err := os.Stat(readyPath)
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return err == nil, err
		},
		ReadyTimeout: 3 * time.Second, ProbeInterval: 20 * time.Millisecond,
		StopTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("SIGTERM-ignoring child did not become ready: %w", err)
	}
	cleanupNeeded = true
	if started.State != processowner.StateReady || started.Generation != 1 || started.PID <= 1 {
		return fmt.Errorf("SIGTERM-ignoring child readiness was not recorded: %+v", started)
	}

	stopped, stopErr := owner.Stop(context.Background())
	if !errors.Is(stopErr, processowner.ErrReviewRequired) ||
		stopped.State != processowner.StateReviewRequired ||
		stopped.Generation != started.Generation || stopped.PID != started.PID {
		return fmt.Errorf("forced termination was not quarantined: snapshot=%+v err=%v", stopped, stopErr)
	}
	if err := syscall.Kill(-started.PID, 0); !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("forced-stop process group remains or is uncertain: %v", err)
	}
	if _, err := owner.Start(context.Background(), processowner.Spec{}); !errors.Is(err, processowner.ErrReviewRequired) {
		return fmt.Errorf("process owner restarted after forced termination: %v", err)
	}
	cleanupNeeded = false
	fmt.Println("PHANTOWD_PROCESS_OWNER_FORCE_STOP_READY sigterm_ignored=true forced_termination=true review_required=true restart_blocked=true group_reaped=true scope=qemu-fixture-only")
	return nil
}

// Verify that a forced cleanup while readiness never succeeds remains
// quarantined when a caller later asks to stop again. This catches review
// state being lost merely because a second observation finds the group gone.
func exerciseQEMUProcessOwnerFailedStartCleanup() (result error) {
	readyPath := filepath.Join(smbFixtureRoot, "process-owner-failed-start-ready")
	if err := os.Remove(readyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	defer os.Remove(readyPath)

	owner := processowner.New()
	started, startErr := owner.Start(context.Background(), processowner.Spec{
		Executable: "/bin/busybox",
		Args: []string{"sh", "-c", `trap '' TERM; printf ready > "$1"; while :; do :; done`,
			"phantowd-process-owner", readyPath},
		Ready: func(ctx context.Context) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			_, err := os.Stat(readyPath)
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return false, err
		},
		ReadyTimeout: 250 * time.Millisecond, ProbeInterval: 20 * time.Millisecond,
		StopTimeout: 50 * time.Millisecond,
	})
	if !errors.Is(startErr, processowner.ErrNotReady) ||
		!errors.Is(startErr, processowner.ErrReviewRequired) ||
		started.State != processowner.StateReviewRequired || started.Generation != 0 || started.PID <= 1 {
		return fmt.Errorf("failed start did not quarantine forced cleanup: snapshot=%+v err=%v", started, startErr)
	}

	stopped, stopErr := owner.Stop(context.Background())
	if !errors.Is(stopErr, processowner.ErrReviewRequired) ||
		stopped.State != processowner.StateReviewRequired || stopped.Generation != 0 || stopped.PID != 0 {
		return fmt.Errorf("a later stop cleared failed-start review state: snapshot=%+v err=%v", stopped, stopErr)
	}
	if err := syscall.Kill(-started.PID, 0); !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("failed-start process group remains or is uncertain: %v", err)
	}
	if _, err := owner.Start(context.Background(), processowner.Spec{}); !errors.Is(err, processowner.ErrReviewRequired) {
		return fmt.Errorf("process owner restarted after failed-start cleanup: %v", err)
	}
	fmt.Println("PHANTOWD_PROCESS_OWNER_FAILED_START_REVIEW_READY failed_start=true forced_cleanup=true review_persistent=true restart_blocked=true group_reaped=true scope=qemu-fixture-only")
	return nil
}

// A transport error, timeout or successful exit containing an error-looking
// string is not evidence that Samba enforced an authentication/access rule.
func smbFixtureDenied(output []byte, err error, code string) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && strings.Contains(string(output), code)
}

func checkSMBFixtureListeners(table string) error {
	for _, line := range strings.Split(table, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 3 && fields[3] == "0A" && strings.HasSuffix(fields[1], ":05A5") && fields[1] != "0100007F:05A5" {
			return fmt.Errorf("SMB fixture listener is not IPv4 loopback-only: %s", fields[1])
		}
	}
	return nil
}
