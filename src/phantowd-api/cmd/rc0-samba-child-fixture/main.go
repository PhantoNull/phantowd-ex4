//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

const (
	address        = "192.0.2.21"
	endpoint       = address + ":445"
	fixtureAccount = "qaprobe"
	fixtureID      = 1701
)

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

func unsealedCopy(original *os.File) *os.File {
	fd, err := unix.MemfdCreate("fixture-grant", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	must(err)
	file := os.NewFile(uintptr(fd), "fixture-grant")
	info, err := original.Stat()
	must(err)
	_, err = io.Copy(file, io.NewSectionReader(original, 0, info.Size()))
	must(err)
	must(file.Chmod(0400))
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	candidate := fixtureCandidate()
	owner, err := runtimebundle.StageSambaServiceConfiguration(ctx, candidate, netip.MustParseAddr(address))
	must(err)
	conf, err := owner.DuplicateRoot(ctx)
	must(err)
	configPath := "/proc/self/fd/" + strconv.Itoa(int(conf.Fd()))
	if fd, err := unix.Open(filepath.Join(configPath, "passwd"), unix.O_WRONLY|unix.O_CLOEXEC, 0); !errors.Is(err, unix.EROFS) {
		if err == nil {
			_ = unix.Close(fd)
		}
		panic("protected configuration allowed a write open")
	}
	mountPath, err := os.Readlink(configPath)
	must(err)
	must(unix.Mount("tmpfs", mountPath, "tmpfs", safe, "mode=0755,size=32k"))
	if copy, err := owner.DuplicateRoot(ctx); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		if copy != nil {
			_ = copy.Close()
		}
		panic("covered configuration supplied an input")
	}
	if err := owner.Close(); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		panic("configuration owner touched a replacement mount")
	}
	must(unix.Unmount(mountPath, unix.UMOUNT_NOFOLLOW))
	// Seed the disposable account with the same NSS records as the child.
	for _, name := range []string{"passwd", "group"} {
		must(unix.Mount(filepath.Join(configPath, name), filepath.Join("/etc", name), "", unix.MS_BIND, ""))
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
	grantFile, err := runtimebundle.SealSambaLaunchDeclaration(candidate)
	must(err)
	unsealed := unsealedCopy(grantFile)
	private, state := open("/run/data/private"), open("/run/data/state")
	rw, ro := pin("/run/rw"), pin("/run/ro")
	expectRefusal(makeCmd(true, grantFile, conf, private, state, ro, rw))
	expectRefusal(makeCmd(false, unsealed, conf, private, state, ro, rw))
	expectRefusal(makeCmd(false, grantFile, conf, private, private, ro, rw))
	expectRefusal(makeCmd(false, grantFile, conf, private, state, rw, ro))

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
	_, err = rand.Read(secret[:])
	must(err)
	password := hex.EncodeToString(secret[:])
	seed := exec.Command("/usr/bin/smbpasswd", "-s", "-a", "-c", "/run/smb-seed.conf", fixtureAccount)
	seed.Stdin = strings.NewReader(password + "\n" + password + "\n")
	if output, err := seed.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("seed account: %s %v", output, err))
	}
	must(os.WriteFile("/run/smb-client.auth", []byte("username = "+fixtureAccount+"\npassword = "+password+"\n"), 0600))
	must(os.Chown("/run/data/writable", fixtureID, fixtureID))
	must(os.WriteFile("/run/smb-payload", []byte("isolated write\n"), 0600))
	cmd := makeCmd(false, grantFile, conf, private, state, ro, rw)
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
		conn, err := net.DialTimeout("tcp4", endpoint, 100*time.Millisecond)
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
	if conn, err := net.DialTimeout("tcp4", "127.0.0.1:445", 100*time.Millisecond); err == nil {
		conn.Close()
		panic("SMB listener expanded beyond the confirmed address")
	}
	child := fmt.Sprintf("/proc/%d", pid)
	status, err := os.ReadFile(child + "/status")
	must(err)
	for _, line := range []string{"Name:\tsmbd\n", "CapInh:\t0000000000000000\n", "CapPrm:\t00000000000004db\n", "CapEff:\t00000000000004db\n", "CapBnd:\t00000000000004db\n", "CapAmb:\t0000000000000000\n", "NoNewPrivs:\t1\n"} {
		if !strings.Contains(string(status), line) {
			panic(fmt.Sprintf("missing %q from %s", line, status))
		}
	}
	for location, original := range map[string]string{"/shares/writable": "/run/data/writable", "/shares/readonly": "/run/data/readonly", "/state/private": "/run/data/private", "/state/state": "/run/data/state", "/etc": configPath} {
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
	client := exec.Command("/usr/bin/smbclient", "-N", "-m", "SMB3", "//"+address+"/fixture-rw", "-c", "ls")
	output, err := client.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "NT_STATUS_ACCESS_DENIED") {
		panic(fmt.Sprintf("anonymous client: %s %v", output, err))
	}

	runClient := func(share, command string) ([]byte, error) {
		return exec.Command("/usr/bin/smbclient", "-A", "/run/smb-client.auth", "-m", "SMB3", "//"+address+"/"+share, "-c", command).CombinedOutput()
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
	if owned.Uid != fixtureID || owned.Gid != fixtureID {
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
	if conn, err := net.DialTimeout("tcp4", endpoint, 100*time.Millisecond); err == nil {
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
	for _, name := range []string{"passwd", "group"} {
		must(unix.Unmount(filepath.Join("/etc", name), unix.UMOUNT_NOFOLLOW))
	}
	if err := owner.Close(); !errors.Is(err, unix.EBUSY) {
		panic("configuration mount did not retain its borrowed descriptor")
	}
	must(conf.Close())
	must(owner.Close())
	must(owner.Close())
	if _, err := owner.DuplicateRoot(ctx); err == nil {
		panic("closed configuration still supplied an input")
	}
	fmt.Println("PHANTOWD_RC0_SAMBA_CHILD actual_smbd=true protected_configuration=verified original_mounts=verified capabilities=verified anonymous=refused authenticated_rw=verified read_only=verified databases=retained process_group=drained bad_handoffs=refused")
}

// The fixture constructs the same opaque candidate the product renderer
// receives. All policy, identity observations and volumes here are synthetic.
func fixtureCandidate() fileserviceplan.SambaIsolatedCandidate {
	const uuid = "11111111-2222-3333-4444-555555555555"
	const accountID = "writer"
	registry, err := serviceaccounts.New(fixtureID, fixtureID+10)
	must(err)
	registry, err = registry.Create(registry.Revision, accountID, fixtureAccount,
		serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}})
	must(err)
	registry, err = registry.SetState(registry.Revision, accountID, serviceaccounts.Enabled)
	must(err)
	account := registry.Accounts[0]
	account.State = serviceaccounts.Disabled
	const sid = "S-1-5-21-1-2-3-2000"
	identities := fileserviceplan.IdentitySnapshot{
		Complete: true, Generation: 1, Registry: registry,
		Fingerprint: sha256.Sum256([]byte("synthetic-samba-child-policy")),
		UnixUIDs:    []uint32{account.UID}, UnixGIDs: []uint32{account.GID},
		Samba: []fileserviceplan.SambaIdentity{{
			Journal: smbprovision.Journal{Format: smbprovision.Format, SchemaVersion: 1, Revision: 7,
				NativeRevision: registry.Revision, Account: account, SID: sid, Phase: smbprovision.Enabled},
			Observation: smbprovision.Observation{Present: true, Name: account.Name, UID: account.UID, GID: account.GID, SID: sid},
		}},
	}
	policy := fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1,
		Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
			Volumes: []shareconfig.Volume{{ID: "fixture", FilesystemUUID: uuid}},
			Users:   []shareconfig.User{{ID: accountID, Name: fixtureAccount}},
			Shares: []shareconfig.Share{
				{ID: "writable", Name: "fixture-rw", VolumeID: "fixture", RelativePath: "writable",
					Grants: []shareconfig.Grant{{UserID: accountID, Access: "rw"}}},
				{ID: "readonly", Name: "fixture-ro", VolumeID: "fixture", RelativePath: "readonly",
					Grants: []shareconfig.Grant{{UserID: accountID, Access: "ro"}}},
			}},
		NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1, Exports: []nfsconfig.Export{}},
	}
	storage := fileserviceplan.StorageSnapshot{Complete: true, Generation: 1,
		Volumes: []fileserviceplan.ObservedVolume{{VolumeID: "fixture", FilesystemUUID: uuid,
			MountPath: shareconfig.VolumeMountRoot + "/fixture", Compatibility: fileserviceplan.CompatibilityQualified,
			MountID: 7, DeviceMajor: 8, DeviceMinor: 16}}}
	plan, err := fileserviceplan.Build(policy, 0, identities, storage)
	must(err)
	candidate, err := plan.SambaIsolatedCandidate()
	must(err)
	return candidate
}
