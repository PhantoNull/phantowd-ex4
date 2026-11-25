// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const config = `[global]
server role = standalone server
security = user
map to guest = Never
interfaces = 127.0.0.1
bind interfaces only = yes
smb ports = 1445
server min protocol = SMB3_00
server max protocol = SMB3_11
server signing = mandatory
load printers = no
printing = bsd
printcap name = /dev/null
disable spoolss = yes
dns proxy = no
name resolve order = host
dos charset = CP850
unix charset = UTF-8
private dir = /state/private
lock directory = /state/lock
state directory = /state/state
cache directory = /state/cache
pid directory = /state/pid
ncalrpc dir = /state/rpc
passdb backend = tdbsam:/state/private/passdb.tdb
log file = /state/log.smbd
[fixture-rw]
path = /shares/writable
read only = no
guest ok = no
valid users = qaprobe
[fixture-ro]
path = /shares/readonly
read only = yes
guest ok = no
valid users = qaprobe
`

const grant = `{"format":"phantowd-rc0-samba-launch-v1","shares":[{"id":"writable","read_only":false},{"id":"readonly","read_only":true}]}`

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func open(path string) *os.File {
	file, err := os.Open(path)
	must(err)
	return file
}

func pin(path string) *os.File {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	must(err)
	return os.NewFile(uintptr(fd), path)
}

func handoff(complete bool) *os.File {
	fd, err := unix.MemfdCreate("fixture-grant", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	must(err)
	file := os.NewFile(uintptr(fd), "fixture-grant")
	_, err = file.WriteString(grant)
	must(err)
	must(file.Chmod(0400))
	if complete {
		_, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL)
		must(err)
	}
	return file
}

func makeCmd(wrongNamespace bool, files ...*os.File) *exec.Cmd {
	cmd := exec.Command("/usr/bin/phantowd-api", "--run-rc0-samba-child")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.ExtraFiles = files
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
	if wrongNamespace {
		cmd.SysProcAttr.Unshareflags = unix.CLONE_NEWNS
	}
	return cmd
}

func expectRefusal(cmd *exec.Cmd) {
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		panic(fmt.Sprintf("unexpected child result: %v", err))
	}
}

func main() {
	const safe = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC
	must(unix.Mount("tmpfs", "/run/config", "tmpfs", safe, "mode=0755,size=1m"))
	must(os.Mkdir("/run/config/samba", 0755))
	for name, value := range map[string]string{
		"samba/smb.conf": config,
		"passwd":         "root:x:0:0:root:/:/bin/false\nqaprobe:x:1701:1701:SMB fixture:/:/bin/false\nnobody:x:65534:65534:nobody:/:/bin/false\n",
		"group":          "root:x:0:\nqaprobe:x:1701:\nnobody:x:65534:\n",
		"nsswitch.conf":  "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n",
	} {
		must(os.WriteFile(filepath.Join("/run/config", name), []byte(value), 0644))
	}
	must(unix.Mount("", "/run/config", "", unix.MS_REMOUNT|unix.MS_RDONLY|safe, ""))
	// The disposable guest seeds the test account with the same NSS records
	// that the child will see. Only these tmpfs files cover the guest's /etc.
	for _, name := range []string{"passwd", "group"} {
		must(unix.Mount(filepath.Join("/run/config", name), filepath.Join("/etc", name), "", unix.MS_BIND, ""))
	}
	for name, spec := range map[string]struct {
		original string
		flags    uintptr
	}{
		"rw": {"/run/data/writable", 0},
		"ro": {"/run/data/readonly", unix.MS_RDONLY},
	} {
		dst := filepath.Join("/run", name)
		must(unix.Mount(spec.original, dst, "", unix.MS_BIND, ""))
		must(unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|safe|spec.flags, ""))
	}
	grantFile := handoff(true)
	unsealed := handoff(false)
	conf, private, state := open("/run/config"), open("/run/data/private"), open("/run/data/state")
	rw, ro := pin("/run/rw"), pin("/run/ro")
	expectRefusal(makeCmd(true, grantFile, conf, private, state, rw, ro))
	expectRefusal(makeCmd(false, unsealed, conf, private, state, rw, ro))
	expectRefusal(makeCmd(false, grantFile, conf, private, private, rw, ro))
	expectRefusal(makeCmd(false, grantFile, conf, private, state, ro, rw))

	for _, path := range []string{"/run/seed-lock", "/run/seed-cache", "/run/seed-state"} {
		must(os.Mkdir(path, 0700))
	}
	seedConfig := `[global]
server role = standalone server
private dir = /run/data/private
state directory = /run/seed-state
lock directory = /run/seed-lock
cache directory = /run/seed-cache
passdb backend = tdbsam:/run/data/private/passdb.tdb
`
	must(os.WriteFile("/run/smb-seed.conf", []byte(seedConfig), 0600))
	var secret [24]byte
	_, err := rand.Read(secret[:])
	must(err)
	password := hex.EncodeToString(secret[:])
	seed := exec.Command("/usr/bin/smbpasswd", "-s", "-a", "-c", "/run/smb-seed.conf", "qaprobe")
	seed.Stdin = strings.NewReader(password + "\n" + password + "\n")
	if output, err := seed.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("seed account: %s %v", output, err))
	}
	must(os.WriteFile("/run/smb-client.auth", []byte("username = qaprobe\npassword = "+password+"\n"), 0600))
	must(os.Chown("/run/data/writable", 1701, 1701))
	must(os.WriteFile("/run/smb-payload", []byte("isolated write\n"), 0600))
	cmd := makeCmd(false, grantFile, conf, private, state, rw, ro)
	must(cmd.Start())
	pid := cmd.Process.Pid
	defer unix.Kill(-pid, unix.SIGKILL)
	waiting := make(chan error, 1)
	go func() { waiting <- cmd.Wait() }()
	ready := false
	for i := 0; i < 120; i++ {
		select {
		case err := <-waiting:
			panic(fmt.Sprintf("smbd before readiness: %v", err))
		default:
		}
		conn, err := net.DialTimeout("tcp4", "127.0.0.1:1445", 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		panic("smbd never ready")
	}
	child := fmt.Sprintf("/proc/%d", pid)
	status, err := os.ReadFile(child + "/status")
	must(err)
	for _, line := range []string{"Name:\tsmbd\n", "CapInh:\t0000000000000000\n", "CapPrm:\t00000000000004db\n", "CapEff:\t00000000000004db\n", "CapBnd:\t00000000000004db\n", "CapAmb:\t0000000000000000\n", "NoNewPrivs:\t1\n"} {
		if !strings.Contains(string(status), line) {
			panic(fmt.Sprintf("missing %q from %s", line, status))
		}
	}
	for location, original := range map[string]string{"/shares/writable": "/run/data/writable", "/shares/readonly": "/run/data/readonly", "/state/private": "/run/data/private", "/state/state": "/run/data/state", "/etc": "/run/config"} {
		dst, err := os.Stat(child + "/root" + location)
		must(err)
		src, err := os.Stat(original)
		must(err)
		if !os.SameFile(src, dst) {
			panic("changed inode at " + location)
		}
	}
	for _, location := range []string{"/proc", "/dev", "/run", "/bin"} {
		if _, err := os.Stat(child + "/root" + location); !os.IsNotExist(err) {
			panic("unexpected root exposure " + location)
		}
	}
	selfNS, err := os.Stat("/proc/self/ns/mnt")
	must(err)
	childNS, err := os.Stat(child + "/ns/mnt")
	must(err)
	if os.SameFile(selfNS, childNS) {
		panic("process did not isolate mounts")
	}
	client := exec.Command("/usr/bin/smbclient", "-N", "-m", "SMB3", "-p", "1445", "//127.0.0.1/fixture-rw", "-c", "ls")
	output, err := client.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "NT_STATUS_ACCESS_DENIED") {
		panic(fmt.Sprintf("anonymous client: %s %v", output, err))
	}

	runClient := func(share, command string) ([]byte, error) {
		return exec.Command("/usr/bin/smbclient", "-A", "/run/smb-client.auth", "-m", "SMB3", "-p", "1445", "//127.0.0.1/"+share, "-c", command).CombinedOutput()
	}
	if output, err := runClient("fixture-rw", "get marker /run/smb-read; put /run/smb-payload uploaded"); err != nil {
		panic(fmt.Sprintf("authorized SMB write: %s %v", output, err))
	}
	for file, expected := range map[string]string{"/run/smb-read": "rw marker\n", "/run/data/writable/uploaded": "isolated write\n"} {
		data, err := os.ReadFile(file)
		must(err)
		if string(data) != expected {
			panic("unexpected share contents " + file)
		}
	}
	var owned unix.Stat_t
	must(unix.Stat("/run/data/writable/uploaded", &owned))
	if owned.Uid != 1701 || owned.Gid != 1701 {
		panic("SMB write did not impersonate the account")
	}
	if output, err := runClient("fixture-ro", "get marker /run/smb-readonly"); err != nil {
		panic(fmt.Sprintf("authorized read-only SMB read: %s %v", output, err))
	}
	if output, err := runClient("fixture-ro", "put /run/smb-payload uploaded"); err == nil || !strings.Contains(string(output), "NT_STATUS_ACCESS_DENIED") {
		panic(fmt.Sprintf("read-only SMB write: %s %v", output, err))
	}
	if _, err := os.Stat("/run/data/readonly/uploaded"); !os.IsNotExist(err) {
		panic("read-only share changed")
	}
	must(unix.Kill(-pid, unix.SIGTERM))
	select {
	case err := <-waiting:
		var exit *exec.ExitError
		if err != nil && (!errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM) {
			panic(err)
		}
	case <-time.After(5 * time.Second):
		panic("smbd did not drain")
	}
	for i := 0; !errors.Is(unix.Kill(-pid, 0), unix.ESRCH); i++ {
		if i == 40 {
			panic("process group remained")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if conn, err := net.DialTimeout("tcp4", "127.0.0.1:1445", 100*time.Millisecond); err == nil {
		conn.Close()
		panic("SMB listener remained")
	}
	for _, basename := range []string{"passdb.tdb", "secrets.tdb"} {
		info, err := os.Stat(filepath.Join("/run/data/private", basename))
		must(err)
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			panic("Samba database was not retained in original private state")
		}
	}
	fmt.Println("PHANTOWD_RC0_SAMBA_CHILD actual_smbd=true original_mounts=verified capabilities=verified anonymous=refused authenticated_rw=verified read_only=verified databases=retained process_group=drained bad_handoffs=refused")
}
