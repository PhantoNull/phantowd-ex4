//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
	"golang.org/x/sys/unix"
)

const (
	storageBrokerDirectory   = "/run/phantowd-storage"
	storageBrokerSocket      = storageBrokerDirectory + "/channel"
	storageBrokerSocketName  = "channel"
	storageBrokerDeadline    = 15 * time.Second
	storageGPTBrokerDeadline = 45 * time.Second
	storageBrokerBacklog     = 1
	storageBrokerWorkers     = 2
)

var storageGPTObservationActive atomic.Bool

type storageBrokerPrincipals struct {
	apiUID    uint32
	apiGID    uint32
	brokerUID uint32
	deviceGID uint32
}

type storageBrokerListener struct {
	socket     *net.UnixListener
	dir        int
	identity   unix.Stat_t
	principals storageBrokerPrincipals
	mu         sync.Mutex
	closed     bool
}

func runStorageBroker() error {
	// Prevent a compromised broker from regaining privilege through a future
	// setuid/file-capability executable, even if one is added to the image.
	if ensureStorageBrokerNoNewPrivileges() != nil {
		return errStorageBrokerUnavailable
	}
	if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
		return errStorageBrokerUnavailable
	}
	principals, err := lookupStorageBrokerPrincipals()
	if err != nil || !validStorageBrokerCredentials(principals) {
		return errStorageBrokerUnavailable
	}
	listener, err := listenStorageBroker(storageBrokerDirectory, principals)
	if err != nil {
		return errStorageBrokerUnavailable
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := listener.Run(ctx); err != nil {
		return errStorageBrokerUnavailable
	}
	return nil
}

func ensureStorageBrokerNoNewPrivileges() error {
	allThreadsRestricted, err := storageBrokerTasksHaveNoNewPrivileges("/proc/self/task")
	if err != nil {
		return errStorageBrokerUnavailable
	}
	if allThreadsRestricted {
		return nil
	}

	// PR_SET_NO_NEW_PRIVS is per-thread. Pin this goroutine, set the attribute,
	// then exec the same binary; exec destroys the old Go thread group and the
	// replacement runtime starts with the attribute inherited by every thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
		return errStorageBrokerUnavailable
	}
	executable, err := os.Executable()
	if err != nil || executable == "" {
		return errStorageBrokerUnavailable
	}
	if unix.Exec(executable, os.Args, os.Environ()) != nil {
		return errStorageBrokerUnavailable
	}
	return errStorageBrokerUnavailable
}

func storageBrokerTasksHaveNoNewPrivileges(taskDirectory string) (bool, error) {
	tasks, err := os.ReadDir(taskDirectory)
	if err != nil || len(tasks) == 0 || len(tasks) > 256 {
		return false, errStorageBrokerUnavailable
	}
	for _, task := range tasks {
		if !task.IsDir() {
			return false, errStorageBrokerUnavailable
		}
		status, err := os.ReadFile(taskDirectory + "/" + task.Name() + "/status")
		if err != nil || len(status) == 0 || len(status) > 8192 {
			return false, errStorageBrokerUnavailable
		}
		found := false
		for _, line := range strings.Split(string(status), "\n") {
			key, value, ok := strings.Cut(line, ":")
			if ok && key == "NoNewPrivs" {
				if found {
					return false, errStorageBrokerUnavailable
				}
				found = true
				if strings.TrimSpace(value) != "1" {
					return false, nil
				}
			}
		}
		if !found {
			return false, errStorageBrokerUnavailable
		}
	}
	return true, nil
}

func lookupStorageBrokerPrincipals() (storageBrokerPrincipals, error) {
	api, err := user.Lookup("phantowd")
	if err != nil {
		return storageBrokerPrincipals{}, errStorageBrokerUnavailable
	}
	apiGroup, err := user.LookupGroup("phantowd")
	if err != nil {
		return storageBrokerPrincipals{}, errStorageBrokerUnavailable
	}
	broker, err := user.Lookup("phantowd-storage")
	if err != nil {
		return storageBrokerPrincipals{}, errStorageBrokerUnavailable
	}
	deviceGroup, err := user.LookupGroup("phantowd-storage-read")
	if err != nil {
		return storageBrokerPrincipals{}, errStorageBrokerUnavailable
	}
	apiUID, err := strconv.ParseUint(api.Uid, 10, 32)
	if err != nil {
		return storageBrokerPrincipals{}, errStorageBrokerUnavailable
	}
	apiGID, err := strconv.ParseUint(apiGroup.Gid, 10, 32)
	if err != nil {
		return storageBrokerPrincipals{}, errStorageBrokerUnavailable
	}
	brokerUID, err := strconv.ParseUint(broker.Uid, 10, 32)
	if err != nil {
		return storageBrokerPrincipals{}, errStorageBrokerUnavailable
	}
	deviceGID, err := strconv.ParseUint(deviceGroup.Gid, 10, 32)
	if err != nil {
		return storageBrokerPrincipals{}, errStorageBrokerUnavailable
	}
	principals := storageBrokerPrincipals{
		apiUID: uint32(apiUID), apiGID: uint32(apiGID),
		brokerUID: uint32(brokerUID), deviceGID: uint32(deviceGID),
	}
	if principals.apiUID == 0 || principals.apiGID == 0 || principals.brokerUID == 0 ||
		principals.deviceGID == 0 || principals.apiUID == principals.brokerUID || principals.apiGID == principals.deviceGID {
		return storageBrokerPrincipals{}, errStorageBrokerUnavailable
	}
	return principals, nil
}

func validStorageBrokerCredentials(principals storageBrokerPrincipals) bool {
	if os.Getuid() != int(principals.brokerUID) || os.Geteuid() != int(principals.brokerUID) ||
		os.Getgid() != int(principals.deviceGID) || os.Getegid() != int(principals.deviceGID) ||
		principals.brokerUID == 0 {
		return false
	}
	noNewPrivileges, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || noNewPrivileges != 1 {
		return false
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, group := range groups {
		if group != int(principals.deviceGID) {
			return false
		}
	}
	var header unix.CapUserHeader
	header.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData
	if unix.Capget(&header, &data[0]) != nil {
		return false
	}
	for _, capability := range data {
		if capability.Effective != 0 || capability.Permitted != 0 || capability.Inheritable != 0 {
			return false
		}
	}
	return true
}

func listenStorageBroker(directory string, principals storageBrokerPrincipals) (*storageBrokerListener, error) {
	if directory != storageBrokerDirectory || principals.brokerUID == 0 || principals.apiGID == 0 {
		return nil, errStorageBrokerUnavailable
	}
	parent, err := unix.Openat2(unix.AT_FDCWD, "/run", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, errStorageBrokerUnavailable
	}
	var parentStat unix.Stat_t
	parentSafe := unix.Fstat(parent, &parentStat) == nil && parentStat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		parentStat.Uid == 0 && parentStat.Mode&0022 == 0
	_ = unix.Close(parent)
	if !parentSafe {
		return nil, errStorageBrokerUnavailable
	}
	dir, err := unix.Openat2(unix.AT_FDCWD, directory, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, errStorageBrokerUnavailable
	}
	listener := &storageBrokerListener{dir: dir, principals: principals}
	good := false
	defer func() {
		if !good {
			_ = listener.Close()
		}
	}()
	if !listener.directorySafe() || unix.Flock(dir, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, errStorageBrokerUnavailable
	}
	path := "/proc/self/fd/" + strconv.Itoa(dir) + "/" + storageBrokerSocketName
	if err := listener.removeStale(path); err != nil {
		return nil, errStorageBrokerUnavailable
	}
	oldMask := unix.Umask(0077)
	defer unix.Umask(oldMask)
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, errStorageBrokerUnavailable
	}
	file := os.NewFile(uintptr(fd), "phantowd-storage-broker-listener")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errStorageBrokerUnavailable
	}
	defer file.Close()
	if unix.Bind(fd, &unix.SockaddrUnix{Name: path}) != nil ||
		unix.Fstatat(dir, storageBrokerSocketName, &listener.identity, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, errStorageBrokerUnavailable
	}
	if listener.identity.Mode&unix.S_IFMT != unix.S_IFSOCK || listener.identity.Uid != principals.brokerUID ||
		listener.identity.Gid != principals.apiGID || listener.identity.Nlink != 1 ||
		unix.Fchmodat(dir, storageBrokerSocketName, 0620, 0) != nil ||
		!listener.socketSafe(listener.identity) || unix.Listen(fd, storageBrokerBacklog) != nil {
		return nil, errStorageBrokerUnavailable
	}
	goListener, err := net.FileListener(file)
	if err != nil {
		return nil, errStorageBrokerUnavailable
	}
	listener.socket = goListener.(*net.UnixListener)
	listener.socket.SetUnlinkOnClose(false)
	good = true
	return listener, nil
}

func (l *storageBrokerListener) directorySafe() bool {
	var stat unix.Stat_t
	return l != nil && l.dir >= 0 && unix.Fstat(l.dir, &stat) == nil &&
		stat.Mode == unix.S_IFDIR|02750 && stat.Uid == l.principals.brokerUID && stat.Gid == l.principals.apiGID
}

func (l *storageBrokerListener) socketSafe(identity unix.Stat_t) bool {
	var stat, parent unix.Stat_t
	return l.directorySafe() &&
		unix.Fstatat(l.dir, storageBrokerSocketName, &stat, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		unix.Fstat(l.dir, &parent) == nil && stat.Dev == parent.Dev && stat.Dev == identity.Dev &&
		stat.Ino == identity.Ino && stat.Mode == unix.S_IFSOCK|0620 &&
		stat.Uid == l.principals.brokerUID && stat.Gid == l.principals.apiGID && stat.Nlink == 1
}

func (l *storageBrokerListener) removeStale(path string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(l.dir, storageBrokerSocketName, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || !l.socketStaleShape(stat) {
		return errStorageBrokerUnavailable
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return errStorageBrokerUnavailable
	}
	defer unix.Close(fd)
	err = unix.Connect(fd, &unix.SockaddrUnix{Name: path})
	var current unix.Stat_t
	if !errors.Is(err, unix.ECONNREFUSED) || unix.Fstatat(l.dir, storageBrokerSocketName, &current, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		current.Dev != stat.Dev || current.Ino != stat.Ino || !l.socketStaleShape(current) ||
		unix.Unlinkat(l.dir, storageBrokerSocketName, 0) != nil {
		return errStorageBrokerUnavailable
	}
	return nil
}

func (l *storageBrokerListener) socketStaleShape(stat unix.Stat_t) bool {
	var parent unix.Stat_t
	mode := stat.Mode & 07777
	return l.directorySafe() && unix.Fstat(l.dir, &parent) == nil &&
		stat.Dev == parent.Dev && stat.Mode&unix.S_IFMT == unix.S_IFSOCK &&
		(stat.Ino != 0) && (mode == 0620 || mode == 0700) &&
		stat.Uid == l.principals.brokerUID && stat.Gid == l.principals.apiGID && stat.Nlink == 1
}

func (l *storageBrokerListener) Run(ctx context.Context) (result error) {
	if l == nil || ctx == nil || l.socket == nil {
		return errStorageBrokerUnavailable
	}
	stop := context.AfterFunc(ctx, func() { _ = l.socket.Close() })
	var workers sync.WaitGroup
	active := make(chan struct{}, storageBrokerWorkers)
	defer func() {
		_ = l.socket.Close()
		stop()
		workers.Wait()
		if err := l.Close(); err != nil {
			result = errStorageBrokerUnavailable
		}
	}()
	for {
		connection, err := l.socket.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errStorageBrokerUnavailable
		}
		if ctx.Err() != nil || !l.socketSafe(l.identity) {
			_ = connection.Close()
			if ctx.Err() != nil {
				return nil
			}
			return errStorageBrokerUnavailable
		}
		select {
		case active <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-active }()
				serveStorageBrokerConnection(ctx, connection, l.principals.apiUID, l.principals.apiGID)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (l *storageBrokerListener) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	if l.socket != nil {
		_ = l.socket.Close()
	}
	if l.identity.Ino != 0 {
		var stat unix.Stat_t
		if !l.directorySafe() || unix.Fstatat(l.dir, storageBrokerSocketName, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			stat.Dev != l.identity.Dev || stat.Ino != l.identity.Ino || stat.Mode&unix.S_IFMT != unix.S_IFSOCK ||
			stat.Uid != l.principals.brokerUID || stat.Gid != l.principals.apiGID || stat.Nlink != 1 ||
			unix.Unlinkat(l.dir, storageBrokerSocketName, 0) != nil {
			l.mu.Unlock()
			if l.dir >= 0 {
				_ = unix.Close(l.dir)
				l.dir = -1
			}
			return errStorageBrokerUnavailable
		}
	}
	err := unix.Close(l.dir)
	l.dir = -1
	l.mu.Unlock()
	if err != nil {
		return errStorageBrokerUnavailable
	}
	return nil
}

func serveStorageBrokerConnection(ctx context.Context, connection *net.UnixConn, apiUID, apiGID uint32) {
	defer connection.Close()
	if !storageBrokerPeer(connection, apiUID, apiGID) {
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	response := storageBrokerResponse{Version: storageBrokerProtocolVersion, Status: "unavailable"}
	request, requestErr := decodeStorageBrokerRequest(connection)
	if ctx.Err() == nil && requestErr == nil {
		if request.Operation == storageBrokerOperationInventory {
			_ = connection.SetDeadline(time.Now().Add(storageBrokerDeadline))
			if snapshot, err := collectTrustedStorageForBroker(); err == nil {
				response.Status = "ok"
				response.Snapshot = &snapshot
			}
		} else if request.Operation == storageBrokerOperationGPT {
			if !storageGPTObservationActive.CompareAndSwap(false, true) {
				response.Status = "busy"
			} else {
				defer storageGPTObservationActive.Store(false)
				_ = connection.SetDeadline(time.Now().Add(storageGPTBrokerDeadline))
				probeContext, cancel := context.WithTimeout(ctx, storageGPTBrokerDeadline)
				defer cancel()
				if summary, err := observeTrustedGPTForBroker(probeContext); err == nil {
					response.Status = "ok"
					response.GPTObservation = &summary
				}
			}
		}
	}
	frame, err := encodeStorageBrokerFrame(response)
	if err != nil {
		return
	}
	for len(frame) > 0 {
		n, writeErr := connection.Write(frame)
		if writeErr != nil || n == 0 {
			return
		}
		frame = frame[n:]
	}
}

func collectTrustedStorageForBroker() (storageSnapshot, error) {
	principals, err := lookupStorageBrokerPrincipals()
	if err != nil || !validStorageBrokerCredentials(principals) {
		return storageSnapshot{}, errStorageBrokerUnavailable
	}
	opener := func(devices []volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
		return openBrokerReadOnlySources(devices, principals.deviceGID)
	}
	discovery, err := discoverTrustedStorageWith(os.DirFS("/sys"), os.DirFS("/proc"), opener)
	if err != nil {
		return storageSnapshot{}, errStorageBrokerUnavailable
	}
	snapshot := discovery.inventory
	openedCount := len(discovery.sources)
	if err := discovery.Close(); err != nil {
		return storageSnapshot{}, errStorageBrokerUnavailable
	}
	limitations := make([]string, 0, len(snapshot.Limitations)+2)
	for _, limitation := range snapshot.Limitations {
		if limitation != "no block device is opened and no disk content is read, assembled, mounted or modified" {
			limitations = append(limitations, limitation)
		}
	}
	if openedCount > 0 {
		limitations = append(limitations, "eligible whole-disk block nodes were opened O_RDONLY and generation-checked; no disk content was read")
	} else {
		limitations = append(limitations, "no eligible whole-disk candidate required opening in this snapshot")
	}
	limitations = append(limitations, "mount visibility covers only this broker process namespace; other userspace consumers are not excluded")
	snapshot.Scope = "broker-read-only-point-in-time"
	snapshot.BlockDevicesOpened = openedCount > 0
	snapshot.Limitations = limitations
	return snapshot, nil
}

func observeTrustedGPTForBroker(ctx context.Context) (storageGPTObservationSummary, error) {
	if ctx == nil || ctx.Err() != nil {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	principals, err := lookupStorageBrokerPrincipals()
	if err != nil || !validStorageBrokerCredentials(principals) {
		return storageGPTObservationSummary{}, errStorageBrokerUnavailable
	}
	opener := func(devices []volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
		return openBrokerReadOnlySources(devices, principals.deviceGID)
	}
	discovery, err := discoverTrustedStorageWith(os.DirFS("/sys"), os.DirFS("/proc"), opener)
	if err != nil {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	defer discovery.Close()
	if len(discovery.candidates) > storageGPTObservationMaxDisks || len(discovery.sources) != len(discovery.candidates) {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	observed, err := volumeprobe.ObserveGPTBlockSet(ctx, discovery.sources)
	if err != nil {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	currentStorage, err := collectStorage(os.DirFS("/sys"))
	if err != nil || !sameStorageSnapshot(discovery.inventory, currentStorage) {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	currentMounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
	if err != nil || !sameMountSnapshot(discovery.mounts, currentMounts) {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	currentSwap, err := collectSwapObservation(os.DirFS("/proc"))
	if err != nil || currentSwap.entries != 0 {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	currentPlan, err := planTrustedStorageDiscovery(currentStorage, currentMounts)
	if err != nil || !sameStorageDiscoveryPlan(currentPlan, discovery) {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	identityObservation, err := observeCandidateGPTIdentities(discovery, currentStorage, observed.Results())
	if err != nil {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	summary, err := summarizeGPTIdentityObservation(identityObservation)
	if err != nil || discovery.Close() != nil {
		return storageGPTObservationSummary{}, errStorageDiscoveryIncomplete
	}
	return summary, nil
}

func openBrokerReadOnlySources(devices []volumeprobe.ObservedBlockDevice, deviceGID uint32) ([]volumeprobe.BlockDeviceSource, error) {
	sources, err := volumeprobe.OpenObservedBlockSources(devices)
	if err != nil {
		return nil, errStorageBrokerUnavailable
	}
	for _, source := range sources {
		if source.File == nil {
			closeBlockDeviceSources(sources)
			return nil, errStorageBrokerUnavailable
		}
		var stat unix.Stat_t
		flags, flagsErr := unix.FcntlInt(source.File.Fd(), unix.F_GETFL, 0)
		if flagsErr != nil || flags&unix.O_ACCMODE != unix.O_RDONLY ||
			unix.Fstat(int(source.File.Fd()), &stat) != nil ||
			stat.Mode&unix.S_IFMT != unix.S_IFBLK || stat.Uid != 0 || stat.Gid != deviceGID ||
			stat.Mode&07777 != 0440 {
			for _, opened := range sources {
				if opened.File != nil {
					_ = opened.File.Close()
				}
			}
			return nil, errStorageBrokerUnavailable
		}
	}
	return sources, nil
}

func storageBrokerPeer(connection *net.UnixConn, uid, gid uint32) bool {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	valid := false
	err = raw.Control(func(fd uintptr) {
		kind, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil || kind != unix.SOCK_STREAM {
			return
		}
		credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		valid = err == nil && credentials.Pid > 0 && credentials.Uid == uid && (gid == 0 || credentials.Gid == gid)
	})
	return err == nil && valid
}

func collectStorageFromBroker() (storageSnapshot, error) {
	response, err := requestStorageBroker(context.Background(), storageBrokerOperationInventory)
	if err != nil || response.Status != "ok" || response.Snapshot == nil {
		return storageSnapshot{}, errStorageBrokerUnavailable
	}
	return *response.Snapshot, nil
}

func observeGPTPartitionIdentityFromBroker(ctx context.Context) (storageGPTObservationSummary, error) {
	response, err := requestStorageBroker(ctx, storageBrokerOperationGPT)
	if err != nil {
		return storageGPTObservationSummary{}, errStorageBrokerUnavailable
	}
	switch response.Status {
	case "ok":
		if response.GPTObservation == nil {
			return storageGPTObservationSummary{}, errStorageBrokerUnavailable
		}
		return *response.GPTObservation, nil
	case "busy":
		return storageGPTObservationSummary{}, errStorageGPTObservationBusy
	default:
		return storageGPTObservationSummary{}, errStorageBrokerUnavailable
	}
}

func requestStorageBroker(ctx context.Context, operation string) (storageBrokerResponse, error) {
	if ctx == nil || (operation != storageBrokerOperationInventory && operation != storageBrokerOperationGPT) {
		return storageBrokerResponse{}, errStorageBrokerUnavailable
	}
	principals, err := lookupStorageBrokerPrincipals()
	if err != nil {
		return storageBrokerResponse{}, errStorageBrokerUnavailable
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", storageBrokerSocket)
	if err != nil {
		return storageBrokerResponse{}, errStorageBrokerUnavailable
	}
	defer connection.Close()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || !storageBrokerPeer(unixConnection, principals.brokerUID, principals.deviceGID) {
		return storageBrokerResponse{}, errStorageBrokerUnavailable
	}
	deadline := time.Now().Add(storageBrokerDeadline)
	if operation == storageBrokerOperationGPT {
		deadline = time.Now().Add(storageGPTBrokerDeadline)
	}
	if contextDeadline, exists := ctx.Deadline(); exists && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	frame, err := encodeStorageBrokerRequest(operation)
	if err != nil {
		return storageBrokerResponse{}, errStorageBrokerUnavailable
	}
	for len(frame) > 0 {
		n, writeErr := connection.Write(frame)
		if writeErr != nil || n == 0 {
			return storageBrokerResponse{}, errStorageBrokerUnavailable
		}
		frame = frame[n:]
	}
	if unixConnection.CloseWrite() != nil {
		return storageBrokerResponse{}, errStorageBrokerUnavailable
	}
	response, err := decodeStorageBrokerFrame(connection)
	if err != nil {
		return storageBrokerResponse{}, errStorageBrokerUnavailable
	}
	return response, nil
}

func verifyQEMUStorageBrokerFixture() error {
	principals, err := lookupStorageBrokerPrincipals()
	if err != nil {
		return errStorageBrokerUnavailable
	}
	api, err := user.Lookup("phantowd")
	if err != nil {
		return errStorageBrokerUnavailable
	}
	groups, err := api.GroupIds()
	if err != nil {
		return errStorageBrokerUnavailable
	}
	for _, group := range groups {
		if group == strconv.FormatUint(uint64(principals.deviceGID), 10) {
			return errStorageBrokerUnavailable
		}
	}
	if !verifyQEMUStorageBrokerProcess(principals) {
		return errStorageBrokerUnavailable
	}
	for _, node := range []string{"sda", "sdb", "sdc", "sdd", "sde", "sdf"} {
		var stat unix.Stat_t
		if unix.Lstat("/dev/"+node, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFBLK ||
			stat.Uid != 0 || stat.Gid != principals.deviceGID || stat.Mode&07777 != 0440 {
			return errStorageBrokerUnavailable
		}
	}
	const node = "sdd"
	// Force the QEMU mdev hotplug rule to create the node. Leaving the already
	// correctly-moded devtmpfs node in place lets the polling loop succeed before
	// the asynchronous add event is handled, racing the following API restart.
	var stat unix.Stat_t
	if unix.Lstat("/dev/"+node, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFBLK ||
		stat.Uid != 0 || stat.Gid != principals.deviceGID || stat.Mode&07777 != 0440 ||
		os.Remove("/dev/"+node) != nil {
		return errStorageBrokerUnavailable
	}
	if err := os.WriteFile("/sys/class/block/"+node+"/uevent", []byte("add\n"), 0600); err != nil {
		return errStorageBrokerUnavailable
	}
	for attempt := 0; attempt < 40; attempt++ {
		var stat unix.Stat_t
		if unix.Lstat("/dev/"+node, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFBLK &&
			stat.Uid == 0 && stat.Gid == principals.deviceGID && stat.Mode&07777 == 0440 {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errStorageBrokerUnavailable
}

func verifyQEMUStorageBrokerProcess(principals storageBrokerPrincipals) bool {
	pidFile, err := os.ReadFile("/run/phantowd-storage-broker.pid")
	if err != nil || len(pidFile) == 0 || len(pidFile) > 32 {
		return false
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(string(pidFile)), 10, 32)
	if err != nil || pid == 0 {
		return false
	}
	taskDirectory := "/proc/" + strconv.FormatUint(pid, 10) + "/task"
	tasks, err := os.ReadDir(taskDirectory)
	if err != nil || len(tasks) == 0 || len(tasks) > 256 {
		return false
	}
	for _, task := range tasks {
		if !task.IsDir() {
			return false
		}
		status, err := os.ReadFile(taskDirectory + "/" + task.Name() + "/status")
		if err != nil || len(status) == 0 || len(status) > 8192 ||
			!validQEMUStorageBrokerTaskStatus(status, principals) {
			return false
		}
	}
	return true
}

func validQEMUStorageBrokerTaskStatus(status []byte, principals storageBrokerPrincipals) bool {
	fields := make(map[string]string)
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	uid := strings.Fields(fields["Uid"])
	gids := strings.Fields(fields["Gid"])
	if len(uid) != 4 || len(gids) != 4 || fields["NoNewPrivs"] != "1" {
		return false
	}
	for _, value := range uid {
		if value != strconv.FormatUint(uint64(principals.brokerUID), 10) {
			return false
		}
	}
	for _, value := range gids {
		if value != strconv.FormatUint(uint64(principals.deviceGID), 10) {
			return false
		}
	}
	for _, group := range strings.Fields(fields["Groups"]) {
		if group != strconv.FormatUint(uint64(principals.deviceGID), 10) {
			return false
		}
	}
	for _, name := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb"} {
		capabilities, err := strconv.ParseUint(fields[name], 16, 64)
		if err != nil || capabilities != 0 {
			return false
		}
	}
	return true
}
