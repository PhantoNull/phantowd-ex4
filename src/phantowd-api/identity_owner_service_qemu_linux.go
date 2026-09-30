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
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
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
	"netbios name = PHANTOWDQEMU\n" +
	"security = user\n" +
	"map to guest = Never\n" +
	"private dir = " + qemuOwnerRoot + "\n" +
	"lock directory = " + qemuOwnerRoot + "\n" +
	"state directory = " + qemuOwnerRoot + "\n" +
	"cache directory = " + qemuOwnerRoot + "\n" +
	"pid directory = " + qemuOwnerRoot + "\n" +
	"ncalrpc dir = " + qemuOwnerRoot + "\n" +
	"passdb backend = tdbsam:" + qemuOwnerRoot + "/passdb.tdb\n"

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
	if err := prepareQEMUIdentityOwnerConfig(); err != nil {
		return errors.New("QEMU identity-owner Samba fixture is unsafe or unavailable")
	}
	smbBackend, err := smbexec.New(qemuOwnerSMBConfig)
	if err != nil {
		return errors.New("QEMU identity-owner Samba backend is unavailable")
	}
	if err := prepareQEMUIdentityOwnerRuntime(apiGID); err != nil {
		_ = smbBackend.Close()
		return errors.New("QEMU identity-owner runtime is unsafe or unavailable")
	}
	if err := initializeQEMUIdentityOwnerRegistry(); err != nil {
		_ = smbBackend.Close()
		return errors.New("QEMU identity-owner registry initialization failed")
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
		filepath.Join(qemuOwnerAuthority, "registry"), filepath.Join(qemuOwnerAuthority, "operations")} {
		if err := ensureQEMUOwnerDirectory(path, 0700, 0); err != nil {
			return err
		}
	}
	if err := ensureQEMUOwnerDirectory(qemuOwnerSocketDir, 0710, apiGID); err != nil {
		return err
	}
	return nil
}

// prepareQEMUIdentityOwnerConfig provisions only the disposable fixture's
// fixed config before validation. Owner authority directories are prepared
// only after smbexec.New accepts the pinned config.
func prepareQEMUIdentityOwnerConfig() error {
	if err := ensureQEMUOwnerDirectory(qemuOwnerRoot, 0700, 0); err != nil {
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
	if len(registry.Accounts) != 1 || len(journals) != 1 || registry.Revision < 2 {
		return errors.New("QEMU identity-owner fixture has unexpected records")
	}
	account := registry.Accounts[0]
	journal := journals[0]
	if account.ID != qemuOwnerAccountID || account.Name != qemuOwnerAccount ||
		(account.State != serviceaccounts.Disabled && account.State != serviceaccounts.Enabled) ||
		account.UID < qemuOwnerFirstUID || account.UID > qemuOwnerLastUID ||
		(journal.Phase != identityprovision.GroupConfirmed && journal.Phase != identityprovision.UnixConfirmed) ||
		journal.RegistryRevision != 2 || journal.RegistryRevision > registry.Revision ||
		!sameQEMUAccountIdentity(journal.Account, account) {
		return errors.New("QEMU identity-owner fixture identity changed")
	}
	return nil
}

func sameQEMUAccountIdentity(first, second serviceaccounts.Account) bool {
	return first.ID == second.ID && first.Name == second.Name && first.UID == second.UID && first.GID == second.GID
}

func exerciseQEMUIdentityOwnerDesiredState() error {
	inventory := func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	}
	owner, err := identityowner.Open(qemuOwnerAuthority, inventory)
	if err != nil {
		return errors.New("QEMU identity-owner desired-state authority could not reopen")
	}
	defer owner.Close()
	ctx := context.Background()
	registry, journals, err := owner.Snapshot(ctx)
	if err != nil || registry.Revision != 2 || len(registry.Accounts) != 1 || len(journals) != 1 ||
		registry.Accounts[0].State != serviceaccounts.Disabled || journals[0].Phase != identityprovision.UnixConfirmed ||
		journals[0].RegistryRevision != 2 || !sameQEMUAccountIdentity(registry.Accounts[0], journals[0].Account) {
		return errors.New("QEMU identity-owner desired-state fixture did not start from a confirmed disabled identity")
	}
	if err := owner.SetDesiredState(ctx, registry.Revision, qemuOwnerAccountID, serviceaccounts.Enabled); err != nil {
		return errors.New("QEMU identity-owner desired-state enable failed")
	}
	registry, journals, err = owner.Snapshot(ctx)
	if err != nil || registry.Revision != 3 || len(registry.Accounts) != 1 || len(journals) != 1 ||
		registry.Accounts[0].State != serviceaccounts.Enabled || journals[0].Phase != identityprovision.UnixConfirmed ||
		journals[0].RegistryRevision != 2 || journals[0].Account.State != serviceaccounts.Disabled ||
		!sameQEMUAccountIdentity(registry.Accounts[0], journals[0].Account) {
		return errors.New("QEMU desired-state enable changed the native identity journal")
	}
	if err := owner.SetDesiredState(ctx, registry.Revision, qemuOwnerAccountID, serviceaccounts.Disabled); err != nil {
		return errors.New("QEMU identity-owner desired-state disable failed")
	}
	registry, journals, err = owner.Snapshot(ctx)
	if err != nil || registry.Revision != 4 || len(registry.Accounts) != 1 || len(journals) != 1 ||
		registry.Accounts[0].State != serviceaccounts.Disabled || journals[0].Phase != identityprovision.UnixConfirmed ||
		journals[0].RegistryRevision != 2 || journals[0].Account.State != serviceaccounts.Disabled ||
		!sameQEMUAccountIdentity(registry.Accounts[0], journals[0].Account) {
		return errors.New("QEMU desired-state disable changed the native identity journal")
	}
	if _, err := os.Lstat(filepath.Join(qemuOwnerAuthority, "operations", qemuOwnerAccountID, "smb")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("QEMU desired-state transition created Samba state")
	}
	if err := owner.Close(); err != nil {
		return errors.New("QEMU identity-owner desired-state authority did not close cleanly")
	}
	fmt.Println("PHANTOWD_IDENTITY_OWNER_DESIRED_STATE_READY enabled=true disabled=true registry_revisioned=true native_journal_immutable=true smb_journal=false auth_mutation=false service_activation=false http=false scope=qemu-only")
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
	if err := exerciseQEMURejectedSMBConfigsHaveNoSideEffects(); err != nil {
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
	if err := exerciseQEMUIdentityOwnerDesiredState(); err != nil {
		return err
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
	fmt.Println("PHANTOWD_IDENTITY_OWNER_BOOT_READY service_uid=0 socket_mode=0620 api_uid=nonroot config_validated_before_owner_state=true config_missing_rejected=true config_invalid_rejected=true no_side_effects=true process_restart=true drained=true desired_state_roundtrip=true native_journal_immutable=true smb_journal=false service_activation=false runtime=run http=false scope=qemu-only")
	return nil
}

func exerciseQEMURejectedSMBConfigsHaveNoSideEffects() (result error) {
	directory := filepath.Join(qemuOwnerRoot, "config-rejection-test")
	if err := os.Mkdir(directory, 0700); err != nil {
		return errors.New("QEMU Samba config rejection fixture could not start")
	}
	defer func() { result = errors.Join(result, os.Remove(directory)) }()

	missing := filepath.Join(directory, "missing.conf")
	backend, err := smbexec.New(missing)
	if backend != nil {
		_ = backend.Close()
	}
	if err == nil {
		return errors.New("missing Samba config was accepted")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		return errors.New("missing Samba config rejection created the path")
	}

	invalid := filepath.Join(directory, "invalid.conf")
	contents := []byte("[global]\nserver role = phantowd-invalid-role\n")
	file, err := os.OpenFile(invalid, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("invalid Samba config fixture could not be created")
	}
	_, writeErr := file.Write(contents)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	err = errors.Join(writeErr, file.Close())
	if err != nil {
		_ = os.Remove(invalid)
		return errors.New("invalid Samba config fixture could not be saved")
	}
	defer func() { result = errors.Join(result, os.Remove(invalid)) }()
	before, err := os.Stat(invalid)
	if err != nil {
		return errors.New("invalid Samba config metadata could not be captured")
	}
	backend, err = smbexec.New(invalid)
	if backend != nil {
		_ = backend.Close()
	}
	if err == nil {
		return errors.New("syntactically invalid Samba config was accepted")
	}
	after, statErr := os.Stat(invalid)
	afterContents, readErr := os.ReadFile(invalid)
	if statErr != nil || readErr != nil || !os.SameFile(before, after) ||
		before.Mode() != after.Mode() || string(afterContents) != string(contents) {
		clear(afterContents)
		return errors.New("invalid Samba config rejection changed its input")
	}
	clear(afterContents)
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "invalid.conf" {
		return errors.New("rejected Samba configs left unexpected filesystem state")
	}
	if _, err := os.Lstat(filepath.Join(directory, "authority")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("rejected Samba config created owner authority state")
	}
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
