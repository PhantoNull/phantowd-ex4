//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
	"golang.org/x/sys/unix"
)

const smbRebootRoot = qemuStateAnchor + "/smb-reboot"
const smbRebootRuntime = "/run/phantowd-smb-reboot"
const smbRebootData = "/run/phantowd-smb-reboot-data"
const smbRebootOld = "public-qemu-reboot-old-password"
const smbRebootNew = "public-qemu-reboot-rotated-password"
const smbRebootPayload = "persistent-qemu-account-data\n"

var smbRebootAccount = serviceaccounts.Account{ID: "reboot-user", Name: "qpreboot", UID: 21000, GID: 21000, State: serviceaccounts.Disabled}

type smbRebootEvidence struct {
	Unix  map[string][32]byte `json:"unix"`
	Inode uint64              `json:"inode"`
}

// Only the dedicated, NIC-less, two-boot fixture may call this function. It
// binds a copy of the guest /etc, never the host's or a physical appliance's.
// The second boot must not recreate users or reset credentials.
func exerciseQEMUSMBReboot(phase string) (result error) {
	if phase != "seed" && phase != "verify" {
		return errors.New("unknown SMB reboot phase")
	}
	if err := runQEMUNFSTest("verify-disk"); err != nil {
		return err
	}
	// The outer harness has qualified and mounted this exact disposable disk.
	device, err := os.ReadFile("/sys/class/block/sdb/dev")
	if err != nil {
		return err
	}
	mounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
	if err != nil {
		return err
	}
	found := false
	for _, m := range mounts.Mounts {
		if m.MountPoint == qemuStateAnchor && !m.ReadOnly && m.Filesystem == "ext4" && fmt.Sprintf("%d:%d", m.DeviceMajor, m.DeviceMinor) == strings.TrimSpace(string(device)) {
			found = true
		}
	}
	if !found {
		return errors.New("SMB reboot fixture state mount missing")
	}
	before, err := unixidentity.ReadLocal("/etc", 0)
	if err != nil {
		return err
	}
	if status, err := before.Assess(smbRebootAccount); err != nil || status != unixidentity.Absent {
		return errors.New("SMB reboot fixture requires fresh guest Unix state")
	}
	if phase == "seed" {
		for _, path := range []string{smbRebootRoot, smbRebootRoot + "/ledger", smbRebootRoot + "/private", smbRebootRoot + "/state", smbRebootRoot + "/data"} {
			if err := os.Mkdir(path, 0700); err != nil {
				return err
			}
		}
		if _, err := smbFixtureCommand("", "/bin/cp", "-a", "/etc", smbRebootRoot+"/etc"); err != nil {
			return errors.New("guest-only etc copy failed")
		}
	}
	if err := unix.Mount(smbRebootRoot+"/etc", "/etc", "", unix.MS_BIND, ""); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Unmount("/etc", 0)) }()
	ledger, err := serviceaccountstore.Open(smbRebootRoot + "/ledger")
	if err != nil {
		return err
	}
	defer ledger.Close()
	if phase == "seed" {
		exclusions, err := before.Reservations()
		if err != nil {
			return err
		}
		if err := ledger.Initialize(21000, 21000); err != nil {
			return err
		}
		if err := ledger.Create(1, smbRebootAccount.ID, smbRebootAccount.Name, exclusions); err != nil {
			return err
		}
		if _, err := smbFixtureCommand("", "/usr/sbin/addgroup", "-g", "21000", smbRebootAccount.Name); err != nil {
			return errors.New("reboot group creation failed")
		}
		if _, err := smbFixtureCommand("", "/usr/sbin/adduser", "-D", "-H", "-s", "/sbin/nologin", "-G", smbRebootAccount.Name, "-u", "21000", smbRebootAccount.Name); err != nil {
			return errors.New("reboot user creation failed")
		}
	}
	r, err := ledger.Load()
	if err != nil || r.Revision != 2 || len(r.Accounts) != 1 || r.Accounts[0] != smbRebootAccount {
		return errors.New("reboot identity ledger mismatch")
	}
	observed, err := unixidentity.ReadLocal("/etc", 0)
	if err != nil {
		return err
	}
	if status, err := observed.Assess(r.Accounts[0]); err != nil || status != unixidentity.Observed {
		return errors.New("reboot Unix identity mismatch")
	}
	for _, path := range []string{smbRebootRuntime, smbRebootRuntime + "/lock", smbRebootRuntime + "/cache", smbRebootRuntime + "/pid", smbRebootRuntime + "/rpc", smbRebootData} {
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
	}
	config := "[global]\nserver role = standalone server\nsecurity = user\nmap to guest = Never\ninterfaces = 127.0.0.1\nbind interfaces only = yes\nsmb ports = 1445\nserver min protocol = SMB3_00\nserver max protocol = SMB3_11\nload printers = no\nprinting = bsd\nprintcap name = /dev/null\n"
	for key, path := range map[string]string{"private dir": smbRebootRoot + "/private", "state directory": smbRebootRoot + "/state", "lock directory": smbRebootRuntime + "/lock", "cache directory": smbRebootRuntime + "/cache", "pid directory": smbRebootRuntime + "/pid", "ncalrpc dir": smbRebootRuntime + "/rpc"} {
		config += key + " = " + path + "\n"
	}
	config += "passdb backend = tdbsam:" + smbRebootRoot + "/private/passdb.tdb\n[Reboot]\npath = " + smbRebootData + "\nvalid users = qpreboot\nread only = no\nguest ok = no\nfollow symlinks = no\nwide links = no\ncreate mask = 0600\ndirectory mask = 0700\n"
	configPath := smbRebootRuntime + "/smb.conf"
	if err := writeQEMUStateFixture(configPath, []byte(config)); err != nil {
		return err
	}
	if _, err := smbFixtureCommand("", "/usr/bin/testparm", "-s", configPath); err != nil {
		return errors.New("reboot Samba config rejected")
	}
	if phase == "seed" {
		for _, password := range []string{smbRebootOld, smbRebootNew} {
			args := []string{"-s", "-c", configPath}
			if password == smbRebootOld {
				args = append(args, "-a")
			}
			args = append(args, smbRebootAccount.Name)
			if _, err := smbFixtureCommand(password+"\n"+password+"\n", "/usr/bin/smbpasswd", args...); err != nil {
				return errors.New("reboot credential setup failed")
			}
		}
		if _, err := smbFixtureCommand("", "/usr/bin/smbpasswd", "-d", "-c", configPath, smbRebootAccount.Name); err != nil {
			return errors.New("reboot account disable failed")
		}
		if err := os.Chown(smbRebootRoot+"/data", 21000, 21000); err != nil {
			return err
		}
		if err := writeQEMUStateFixture(smbRebootRoot+"/data/original", []byte(smbRebootPayload)); err != nil {
			return err
		}
		if err := os.Chown(smbRebootRoot+"/data/original", 21000, 21000); err != nil {
			return err
		}
	}
	evidence, err := observeSMBRebootEvidence()
	if err != nil {
		return err
	}
	if phase == "seed" {
		data, err := json.Marshal(evidence)
		if err != nil {
			return err
		}
		if err := writeQEMUStateFixture(smbRebootRoot+"/evidence.json", data); err != nil {
			return err
		}
	} else {
		data, err := os.ReadFile(smbRebootRoot + "/evidence.json")
		if err != nil {
			return err
		}
		current, err := json.Marshal(evidence)
		if err != nil || !bytes.Equal(current, data) {
			return errors.New("Unix state or original file changed across boot")
		}
	}
	if err := unix.Mount(smbRebootRoot+"/data", smbRebootData, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Unmount(smbRebootData, 0)) }()
	if err := exerciseSMBRebootConnections(configPath, phase); err != nil {
		return err
	}
	after, err := observeSMBRebootEvidence()
	if err != nil {
		return err
	}
	a, _ := json.Marshal(after)
	b, _ := json.Marshal(evidence)
	if !bytes.Equal(a, b) {
		return errors.New("SMB reboot access changed Unix identity or original data")
	}
	if phase == "verify" {
		if err := ledger.SetState(2, smbRebootAccount.ID, serviceaccounts.Enabled); err != nil {
			return err
		}
	}
	if err := ledger.Close(); err != nil {
		return err
	}
	// Flush this generated guest volume only, after smbd has stopped. This is
	// a clean-shutdown test, not a power-loss or database-corruption recovery test.
	f, err := os.Open(smbRebootRoot)
	if err != nil {
		return err
	}
	err = unix.Syncfs(int(f.Fd()))
	return errors.Join(err, f.Close())
}

func observeSMBRebootEvidence() (smbRebootEvidence, error) {
	e := smbRebootEvidence{Unix: map[string][32]byte{}}
	for _, path := range []string{"/etc/passwd", "/etc/group", "/etc/shadow"} {
		data, err := os.ReadFile(path)
		if err != nil {
			return e, err
		}
		e.Unix[path] = sha256.Sum256(data) // Never log or export password-bearing bytes.
	}
	data, err := os.ReadFile(smbRebootRoot + "/data/original")
	if err != nil || string(data) != smbRebootPayload {
		return e, errors.New("reboot data content mismatch")
	}
	var st unix.Stat_t
	if unix.Lstat(smbRebootRoot+"/data/original", &st) != nil || st.Mode != unix.S_IFREG|0600 || st.Uid != 21000 || st.Gid != 21000 {
		return e, errors.New("reboot data identity mismatch")
	}
	e.Inode = st.Ino
	return e, nil
}

func exerciseSMBRebootConnections(configPath, phase string) (result error) {
	for name, password := range map[string]string{"old": smbRebootOld, "new": smbRebootNew} {
		if err := writeQEMUStateFixture(smbRebootRuntime+"/"+name+".auth", []byte("username = qpreboot\npassword = "+password+"\n")); err != nil {
			return err
		}
	}
	log, err := os.OpenFile(smbRebootRuntime+"/smbd.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
		_ = syscall.Kill(-daemon.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-daemon.Process.Pid, syscall.SIGKILL)
			<-done
			result = errors.Join(result, errors.New("reboot Samba needed forced termination"))
		}
	}()
	client := func(auth, operation string) ([]byte, error) {
		return smbFixtureCommand("", "/usr/bin/smbclient", "-t", "2", "-m", "SMB3_11", "-p", "1445", "-A", smbRebootRuntime+"/"+auth+".auth", "//127.0.0.1/Reboot", "-c", operation)
	}
	var output []byte
	for attempt := 0; attempt < 10; attempt++ {
		output, err = client("new", "ls")
		if smbFixtureDenied(output, err, "NT_STATUS_ACCOUNT_DISABLED") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !smbFixtureDenied(output, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return fmt.Errorf("persisted disabled account not refused: %s (%v)", output, err)
	}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := checkSMBFixtureListeners(string(data)); err != nil {
			return err
		}
	}
	if phase == "seed" {
		return nil
	}
	// Only an explicit action in this fixed test enables the retained account.
	// No -a/password command is allowed in the verify phase.
	if _, err := smbFixtureCommand("", "/usr/bin/smbpasswd", "-e", "-c", configPath, smbRebootAccount.Name); err != nil {
		return errors.New("persisted account enable failed")
	}
	output, err = client("old", "ls")
	if !smbFixtureDenied(output, err, "NT_STATUS_LOGON_FAILURE") {
		return errors.New("obsolete password accepted after reboot")
	}
	if output, err := client("new", "get original "+smbRebootRuntime+"/download"); err != nil {
		return fmt.Errorf("retained password read failed: %s (%v)", output, err)
	}
	data, err := os.ReadFile(smbRebootRuntime + "/download")
	if err != nil || string(data) != smbRebootPayload {
		return errors.New("postboot download mismatch")
	}
	if output, err := client("new", "put "+smbRebootRuntime+"/download after-reboot"); err != nil {
		return fmt.Errorf("postboot write failed: %s (%v)", output, err)
	}
	var st unix.Stat_t
	if unix.Lstat(smbRebootRoot+"/data/after-reboot", &st) != nil || st.Mode != unix.S_IFREG|0600 || st.Uid != 21000 || st.Gid != 21000 {
		return errors.New("postboot write ownership mismatch: " + strconv.FormatUint(uint64(st.Uid), 10))
	}
	data, err = os.ReadFile(smbRebootRoot + "/data/after-reboot")
	if err != nil || string(data) != smbRebootPayload {
		return errors.New("postboot write content mismatch")
	}
	return nil
}
