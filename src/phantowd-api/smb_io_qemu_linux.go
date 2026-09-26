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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/smbconfig"
)

const smbFixtureRoot = "/run/phantowd-smb-policy-test"
const smbFixtureAnchor = "/srv/phantowd/volumes/" + qemuNFSVolumeUUID

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
	log, err := os.OpenFile(smbFixtureRoot+"/smbd.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	daemon := exec.Command("/usr/sbin/smbd", "-F", "--no-process-group", "-s", configPath)
	daemon.Stdout, daemon.Stderr = log, log
	daemon.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := daemon.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- daemon.Wait() }()
	defer func() {
		// Signal only the process group created by this fixture, not the stock
		// guest smbd or any host daemon. Reap before the NFS harness unmounts.
		_ = syscall.Kill(-daemon.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-daemon.Process.Pid, syscall.SIGKILL)
			<-done
			result = errors.Join(result, errors.New("SMB fixture daemon needed forced termination"))
		}
	}()
	client := func(user, share, operation string) ([]byte, error) {
		return smbFixtureCommand("", "/usr/bin/smbclient", "-t", "2", "-m", "SMB3_11", "-p", "1445", "-A", smbFixtureRoot+"/"+user+".auth", "//127.0.0.1/"+share, "-c", operation)
	}
	var output []byte
	for attempt := 0; attempt < 10; attempt++ {
		output, err = client("qpwriter", "PolicyShare", "ls")
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
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
	if output, err := smbFixtureCommand("", "/usr/bin/smbpasswd", "-d", "-c", configPath, "qpwriter"); err != nil {
		return fmt.Errorf("SMB fixture disable failed: %s (%v)", output, err)
	}
	output, err = client("qprotated", "PolicyShare", "put "+smbFixtureRoot+"/upload disabled-write")
	if !smbFixtureDenied(output, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return fmt.Errorf("SMB disabled credential not refused: %s (%v)", output, err)
	}
	if _, err := os.Lstat(shared + "/disabled-write"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("SMB disabled account left an unexpected file")
	}
	// An unrelated user must remain usable while the writer is disabled.
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
	fmt.Println("PHANTOWD_SMB_POLICY_IO_READY generated=true writer_uid=1801 reader_ro=true outsider_denied=true unix_denied=true symlink_denied=true scope=qemu-fixture-only")
	if err := exerciseQEMUUnixIdentity(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_UNIX_IDENTITY_READY exclusions=true partial_detected=true exact_binding=true conflict_refused=true cleanup_verified=true scope=local-qemu-files-only")
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
