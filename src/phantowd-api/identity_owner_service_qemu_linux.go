//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityrpc"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
)

const (
	qemuOwnerRoot       = "/run/phantowd-identity-owner-fixture"
	qemuOwnerAuthority  = qemuOwnerRoot + "/authority"
	qemuOwnerSocketDir  = "/run/phantowd-identity-owner-channel"
	qemuOwnerSocketPath = qemuOwnerSocketDir + "/channel"
	qemuOwnerSMBConfig  = qemuOwnerRoot + "/smb.conf"
	qemuOwnerAccountID  = "boot-owner"
	qemuOwnerAccount    = "qpboot"
	qemuOwnerFirstUID   = 23000
	qemuOwnerLastUID    = 23010
)

const qemuOwnerSMBConfiguration = "[global]\n" +
	"server role = standalone server\n" +
	"security = user\n" +
	"map to guest = Never\n" +
	"private dir = " + qemuOwnerRoot + "/private\n" +
	"lock directory = " + qemuOwnerRoot + "/lock\n" +
	"state directory = " + qemuOwnerRoot + "/state\n" +
	"cache directory = " + qemuOwnerRoot + "/cache\n" +
	"pid directory = " + qemuOwnerRoot + "/pid\n" +
	"ncalrpc dir = " + qemuOwnerRoot + "/rpc\n" +
	"passdb backend = tdbsam:" + qemuOwnerRoot + "/private/passdb.tdb\n"

// runQEMUIdentityOwnerService is wired only into the disposable ARMv5 QEMU
// image. It deliberately accepts no paths, UID ranges, commands or environment
// configuration from a caller. All authority and Samba fixture state is under
// the guest's volatile /run tree; no NAS, mounted data volume or HTTP handler is
// involved.
func runQEMUIdentityOwnerService() error {
	if err := guardQEMUIdentityOwnerService(); err != nil {
		return err
	}
	apiUID, apiGID, err := qemuIdentityOwnerAPIIdentity()
	if err != nil {
		return err
	}
	if err := prepareQEMUIdentityOwnerRuntime(apiGID); err != nil {
		return errors.New("QEMU identity-owner runtime is unsafe or unavailable")
	}
	if err := initializeQEMUIdentityOwnerRegistry(); err != nil {
		return errors.New("QEMU identity-owner registry initialization failed")
	}
	if err := validateQEMUIdentityOwnerSMBConfig(); err != nil {
		return errors.New("QEMU identity-owner Samba fixture is invalid")
	}
	smbBackend, err := smbexec.New(qemuOwnerSMBConfig)
	if err != nil {
		return errors.New("QEMU identity-owner Samba backend is unavailable")
	}
	inventory := func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	}
	owner, err := identityowner.OpenWithSMBBackend(qemuOwnerAuthority, inventory, smbBackend)
	if err != nil {
		return errors.New("QEMU identity-owner authority could not open")
	}
	defer owner.Close()
	if err := ensureQEMUIdentityOwnerReservation(owner); err != nil {
		return errors.New("QEMU identity-owner fixture reservation is invalid")
	}
	server, err := identityrpc.NewRouterWithSMB(apiUID,
		func(id string) identityrpc.Operation { return owner.Operation(id) },
		func(id string) identityrpc.SMBOperation { return owner.SMB(id) })
	if err != nil {
		return errors.New("QEMU identity-owner router is unavailable")
	}
	listener, err := identityrpc.Listen(qemuOwnerSocketDir, apiGID, server)
	if err != nil {
		return errors.New("QEMU identity-owner protected socket could not open")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- listener.Run(ctx) }()
	fmt.Println("PHANTOWD_IDENTITY_OWNER_SERVICE_READY root=true socket=protected runtime=run scope=qemu-only")
	runErr := <-done
	listenerCloseErr := listener.Close()
	ownerCloseErr := owner.Close()
	if runErr != nil || listenerCloseErr != nil || ownerCloseErr != nil {
		return errors.New("QEMU identity-owner service failed to drain cleanly")
	}
	return nil
}

func guardQEMUIdentityOwnerService() error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || runtime.GOARCH != "arm" || strings.Split(buildARMLevel(), ",")[0] != "5" {
		return errors.New("QEMU identity-owner service requires root on the ARMv5 fixture")
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("QEMU identity-owner service requires the Versatile PB fixture")
	}
	runInfo, err := os.Lstat("/run")
	if err != nil || !runInfo.IsDir() || runInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("QEMU identity-owner service requires the volatile runtime directory")
	}
	stat, ok := runInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("QEMU identity-owner runtime directory is not root-owned")
	}
	return nil
}

func qemuIdentityOwnerAPIIdentity() (uint32, uint32, error) {
	account, err := user.Lookup("phantowd")
	if err != nil {
		return 0, 0, errors.New("QEMU API principal is unavailable")
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || uid > 65534 || gid == 0 || gid > 65534 {
		return 0, 0, errors.New("QEMU API principal is invalid")
	}
	return uint32(uid), uint32(gid), nil
}

func prepareQEMUIdentityOwnerRuntime(apiGID uint32) error {
	for _, path := range []string{qemuOwnerRoot, qemuOwnerAuthority,
		filepath.Join(qemuOwnerAuthority, "registry"), filepath.Join(qemuOwnerAuthority, "operations"),
		filepath.Join(qemuOwnerRoot, "private"), filepath.Join(qemuOwnerRoot, "lock"),
		filepath.Join(qemuOwnerRoot, "state"), filepath.Join(qemuOwnerRoot, "cache"),
		filepath.Join(qemuOwnerRoot, "pid"), filepath.Join(qemuOwnerRoot, "rpc")} {
		if err := ensureQEMUOwnerDirectory(path, 0700, 0); err != nil {
			return err
		}
	}
	if err := ensureQEMUOwnerDirectory(qemuOwnerSocketDir, 0710, apiGID); err != nil {
		return err
	}
	return ensureQEMUOwnerConfig()
}

func ensureQEMUOwnerDirectory(path string, mode os.FileMode, gid uint32) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		if err := os.Chown(path, 0, int(gid)); err != nil {
			return err
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode.Perm() {
		return errors.New("unsafe QEMU identity-owner directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != gid {
		return errors.New("QEMU identity-owner directory ownership mismatch")
	}
	return nil
}

func ensureQEMUOwnerConfig() error {
	info, err := os.Lstat(qemuOwnerSMBConfig)
	if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(qemuOwnerSMBConfig, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			return createErr
		}
		if _, createErr = file.WriteString(qemuOwnerSMBConfiguration); createErr == nil {
			createErr = file.Sync()
		}
		createErr = errors.Join(createErr, file.Close())
		if createErr != nil {
			return createErr
		}
		info, err = os.Lstat(qemuOwnerSMBConfig)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return errors.New("unsafe QEMU identity-owner Samba config")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Size() != int64(len(qemuOwnerSMBConfiguration)) {
		return errors.New("QEMU identity-owner Samba config ownership mismatch")
	}
	contents, err := os.ReadFile(qemuOwnerSMBConfig)
	if err != nil || string(contents) != qemuOwnerSMBConfiguration {
		clear(contents)
		return errors.New("QEMU identity-owner Samba config changed")
	}
	clear(contents)
	return nil
}

func validateQEMUIdentityOwnerSMBConfig() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/testparm", "-s", qemuOwnerSMBConfig)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	clear(output)
	if err != nil || ctx.Err() != nil {
		return errors.New("QEMU identity-owner Samba config did not validate")
	}
	return nil
}

func initializeQEMUIdentityOwnerRegistry() error {
	store, err := serviceaccountstore.Open(filepath.Join(qemuOwnerAuthority, "registry"))
	if err != nil {
		return err
	}
	_, loadErr := store.Load()
	if errors.Is(loadErr, revisionstore.ErrNotInitialized) {
		loadErr = store.Initialize(qemuOwnerFirstUID, qemuOwnerLastUID)
	}
	if loadErr == nil {
		var registryErr error
		registry, err := store.Load()
		if err != nil {
			registryErr = err
		} else if registry.FirstID != qemuOwnerFirstUID || registry.LastID != qemuOwnerLastUID {
			registryErr = errors.New("QEMU identity-owner allocation range changed")
		}
		loadErr = registryErr
	}
	return errors.Join(loadErr, store.Close())
}

func ensureQEMUIdentityOwnerReservation(owner *identityowner.Owner) error {
	ctx := context.Background()
	registry, journals, err := owner.Snapshot(ctx)
	if err != nil || registry.FirstID != qemuOwnerFirstUID || registry.LastID != qemuOwnerLastUID {
		return errors.New("QEMU identity-owner state is unavailable")
	}
	if len(registry.Accounts) == 0 {
		if registry.Revision != 1 || len(journals) != 0 {
			return errors.New("QEMU identity-owner empty state is inconsistent")
		}
		account, err := owner.Reserve(ctx, registry.Revision, qemuOwnerAccountID, qemuOwnerAccount)
		if err != nil || account.UID < qemuOwnerFirstUID || account.UID > qemuOwnerLastUID {
			return errors.New("QEMU identity-owner reservation failed")
		}
		return nil
	}
	if len(registry.Accounts) != 1 || len(journals) != 1 || registry.Revision != 2 {
		return errors.New("QEMU identity-owner fixture has unexpected records")
	}
	account := registry.Accounts[0]
	journal := journals[0]
	if account.ID != qemuOwnerAccountID || account.Name != qemuOwnerAccount ||
		account.UID < qemuOwnerFirstUID || account.UID > qemuOwnerLastUID || journal.Account != account {
		return errors.New("QEMU identity-owner fixture identity changed")
	}
	return nil
}

func qemuIdentityOwnerClientPrincipal(phase string) (uint32, uint32, bool, error) {
	username := ""
	switch phase {
	case "owner-group", "owner-user":
		username = "phantowd"
	case "owner-denied":
		username = "nobody"
	default:
		return 0, 0, false, nil
	}
	account, err := user.Lookup(username)
	if err != nil {
		return 0, 0, false, errors.New("QEMU owner-client principal is unavailable")
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	apiUser, apiGroup, apiErr := qemuIdentityOwnerAPIIdentity()
	if uidErr != nil || gidErr != nil || apiErr != nil || uid == 0 || uid > 65534 || gid == 0 || gid > 65534 {
		return 0, 0, false, errors.New("QEMU owner-client principal is invalid")
	}
	if phase == "owner-denied" {
		// Keep nobody's UID but give the fixture process the socket directory's
		// group so it reaches SO_PEERCRED instead of being stopped by DAC first.
		gid = uint64(apiGroup)
	}
	if phase == "owner-denied" && uint32(uid) == apiUser && uint32(gid) == apiGroup {
		return 0, 0, false, errors.New("QEMU unauthorized test peer aliases the API principal")
	}
	return uint32(uid), uint32(gid), true, nil
}

func runQEMUIdentityOwnerClient(phase string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if phase == "owner-denied" {
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, "unix", qemuOwnerSocketPath)
		if err != nil {
			return errors.New("QEMU owner service socket did not admit the DAC-authorized test peer")
		}
		defer conn.Close()
		_, err = identityrpc.Call(ctx, conn.(*net.UnixConn), identityrpc.Request{
			Version: 1, Action: "status", AccountID: qemuOwnerAccountID,
		})
		if err == nil {
			return errors.New("protected owner service accepted an unauthorized peer")
		}
		if ctx.Err() != nil {
			return errors.New("unauthorized owner peer test timed out")
		}
		return nil
	}
	requests := []struct {
		request identityrpc.Request
		code    string
		rev     uint64
		phase   string
	}{}
	switch phase {
	case "owner-group":
		requests = []struct {
			request identityrpc.Request
			code    string
			rev     uint64
			phase   string
		}{
			{identityrpc.Request{Version: 1, Action: "status", AccountID: qemuOwnerAccountID}, "ok", 1, "reserved"},
			{identityrpc.Request{Version: 1, Action: "step", AccountID: qemuOwnerAccountID, Revision: 1}, "ok", 3, "group-confirmed"},
			{identityrpc.Request{Version: 1, Action: "step", AccountID: qemuOwnerAccountID, Revision: 1}, "conflict", 0, ""},
		}
	case "owner-user":
		requests = []struct {
			request identityrpc.Request
			code    string
			rev     uint64
			phase   string
		}{
			{identityrpc.Request{Version: 1, Action: "status", AccountID: qemuOwnerAccountID}, "ok", 3, "group-confirmed"},
			{identityrpc.Request{Version: 1, Action: "step", AccountID: qemuOwnerAccountID, Revision: 3}, "ok", 5, "unix-confirmed"},
			{identityrpc.Request{Version: 1, Action: "step", AccountID: qemuOwnerAccountID, Revision: 3}, "conflict", 0, ""},
		}
	default:
		return errors.New("invalid QEMU boot owner-client phase")
	}
	for _, test := range requests {
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, "unix", qemuOwnerSocketPath)
		if err != nil {
			return errors.New("QEMU owner-client reconnect failed")
		}
		response, callErr := identityrpc.Call(ctx, conn.(*net.UnixConn), test.request)
		conn.Close()
		if callErr != nil || response.Code != test.code || response.Revision != test.rev || response.Phase != test.phase {
			return errors.New("QEMU owner service response mismatch")
		}
	}
	return nil
}

func exerciseQEMUBootIdentityOwnerService() error {
	if err := guardQEMUIdentityOwnerService(); err != nil {
		return err
	}
	initMarker, err := os.ReadFile("/run/phantowd-identity-owner-init-ready")
	if err != nil || string(initMarker) != "started-by-init\n" {
		return errors.New("root identity-owner service was not started by the QEMU init hook")
	}
	_, apiGID, err := qemuIdentityOwnerAPIIdentity()
	if err != nil {
		return err
	}
	beforePID, err := verifyQEMUIdentityOwnerService(apiGID)
	if err != nil {
		return err
	}
	if err := runQEMUIdentityOwnerServiceClient("owner-denied", "nobody"); err != nil {
		return err
	}
	if err := runQEMUIdentityOwnerServiceClient("owner-group", "phantowd"); err != nil {
		return err
	}
	restart := exec.Command("/etc/init.d/S49phantowd-identity-owner", "restart")
	restart.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	restartOutput, restartErr := restart.CombinedOutput()
	clear(restartOutput)
	if restartErr != nil {
		return errors.New("QEMU identity-owner service restart failed")
	}
	afterPID, err := verifyQEMUIdentityOwnerService(apiGID)
	if err != nil || afterPID == beforePID {
		return errors.New("QEMU identity-owner process was not replaced on restart")
	}
	if err := runQEMUIdentityOwnerServiceClient("owner-user", "phantowd"); err != nil {
		return err
	}
	if err := verifyQEMUIdentityLogin(qemuOwnerAccount); err != nil {
		return errors.New("boot owner service did not create the expected locked identity")
	}
	stop := exec.Command("/etc/init.d/S49phantowd-identity-owner", "stop")
	stop.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	stopOutput, stopErr := stop.CombinedOutput()
	clear(stopOutput)
	if stopErr != nil {
		return errors.New("QEMU identity-owner listener did not drain before authority close")
	}
	if _, err := smbFixtureCommand("", "/usr/sbin/deluser", qemuOwnerAccount); err != nil {
		return errors.New("QEMU boot owner identity cleanup failed")
	}
	if err := verifyQEMUIdentityAbsent(qemuOwnerAccount); err != nil {
		return err
	}
	if _, err := os.Lstat(qemuOwnerSocketPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("QEMU boot owner socket remained after clean stop")
	}
	if _, err := os.Stat("/run/phantowd-identity-owner.pid"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("QEMU boot owner pidfile remained after clean stop")
	}
	fmt.Println("PHANTOWD_IDENTITY_OWNER_BOOT_READY service_uid=0 socket_mode=0620 api_uid=nonroot process_restart=true drained=true runtime=run http=false scope=qemu-only")
	return nil
}

func runQEMUIdentityOwnerServiceClient(phase, username string) error {
	account, err := user.Lookup(username)
	if err != nil {
		return errors.New("QEMU owner-service test principal is unavailable")
	}
	clientUID, clientGID, ownerServiceClient, principalErr := qemuIdentityOwnerClientPrincipal(phase)
	if principalErr != nil || !ownerServiceClient {
		return errors.New("QEMU owner-service test principal is invalid")
	}
	if account.Uid != strconv.FormatUint(uint64(clientUID), 10) {
		return errors.New("QEMU owner-service test principal changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/phantowd-api", "--qemu-identity-client="+phase)
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: clientUID, Gid: clientGID, Groups: []uint32{},
	}, Setpgid: true}
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	clear(output)
	if err != nil || ctx.Err() != nil {
		return errors.New("QEMU owner-service client phase failed")
	}
	return nil
}

func verifyQEMUIdentityOwnerService(apiGID uint32) (int, error) {
	pidData, err := os.ReadFile("/run/phantowd-identity-owner.pid")
	if err != nil {
		return 0, errors.New("QEMU owner-service pidfile is unavailable")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil || pid <= 1 {
		return 0, errors.New("QEMU owner-service pidfile is invalid")
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, errors.New("QEMU owner-service process is unavailable")
	}
	rootUID := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			rootUID = len(fields) >= 2 && fields[1] == "0"
			break
		}
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || !rootUID || !strings.Contains(string(cmdline), "--qemu-identity-owner-service") {
		return 0, errors.New("QEMU owner-service process identity mismatch")
	}
	for path, mode := range map[string]os.FileMode{qemuOwnerSocketDir: 0710, qemuOwnerSocketPath: 0620} {
		info, err := os.Lstat(path)
		if err != nil {
			return 0, errors.New("QEMU owner-service socket path is unavailable")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Gid != apiGID || info.Mode().Perm() != mode.Perm() {
			return 0, errors.New("QEMU owner-service socket permissions mismatch")
		}
		if path == qemuOwnerSocketPath && (info.Mode()&os.ModeSocket == 0 || stat.Nlink != 1) {
			return 0, errors.New("QEMU owner-service endpoint is not a protected socket")
		}
	}
	return pid, nil
}

func verifyQEMUIdentityAbsent(name string) error {
	for _, path := range []string{"/etc/passwd", "/etc/group", "/etc/shadow"} {
		content, err := os.ReadFile(path)
		if err != nil {
			return errors.New("QEMU identity absence could not be verified")
		}
		for _, line := range strings.Split(string(content), "\n") {
			fields := strings.SplitN(line, ":", 2)
			if len(fields) == 2 && fields[0] == name {
				clear(content)
				return errors.New("QEMU boot owner identity remained after cleanup")
			}
		}
		clear(content)
	}
	return nil
}
