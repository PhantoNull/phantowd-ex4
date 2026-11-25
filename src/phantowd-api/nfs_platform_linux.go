// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"golang.org/x/sys/unix"
)

type localNFSLink struct {
	index int
	name  string
	mac   string
}

// prepareLocalRegisteredNFS uses the executables from the appliance image and
// the current admitted mount and network namespaces. The caller must own the
// NFSD mount and select the endpoint, interface and client quiescence policy.
func prepareLocalRegisteredNFS(ctx context.Context, grants registeredNFSGrants) (*registeredNFS, error) {
	return prepareRegisteredNFSWith(ctx, grants, func(ctx context.Context, inputs *nfsowner.RetainedInputs, runtime nfsowner.LinuxServiceGrants) (*nfsowner.Owner, error) {
		return newLocalNFSRuntime(ctx, inputs, runtime, true, nfsowner.NewManagedLinux)
	})
}

// The QEMU-only caller exercises the same file and link verification on the
// legacy base, which omits the nft executable. Normal callers require it.
func newLocalNFSRuntime(ctx context.Context, inputs *nfsowner.RetainedInputs, grants nfsowner.LinuxServiceGrants, withFilter bool,
	construct func(context.Context, *nfsowner.RetainedInputs, nfsowner.LinuxServiceGrants) (*nfsowner.Owner, error)) (_ *nfsowner.Owner, result error) {
	if ctx == nil || os.Getuid() != 0 || os.Geteuid() != 0 || grants.Quiescent == nil ||
		grants.VerifyStorage == nil || construct == nil {
		return nil, nfsowner.ErrInvalid
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	link, err := observeLocalNFSLink(ctx, grants.Address, grants.IngressIndex)
	if err != nil {
		return nil, err
	}
	for _, role := range []struct {
		path string
		file **os.File
	}{
		{"/proc/fs/nfsd", &grants.NFSD},
		{"/proc/thread-self/ns/net", &grants.Network},
		{"/proc/thread-self/ns/mnt", &grants.MountNamespace},
	} {
		if *role.file != nil {
			return nil, nfsowner.ErrInvalid
		}
		file, err := os.Open(role.path)
		if err != nil {
			return nil, err
		}
		*role.file = file
		defer func() { result = errors.Join(result, file.Close()) }()
	}
	type executableRole struct {
		path string
		file **os.File
	}
	executables := []executableRole{
		{"/usr/sbin/exportfs", &grants.ExportFS},
		{"/usr/sbin/rpcbind", &grants.RPCBind},
		{"/usr/sbin/rpc.mountd", &grants.Mountd},
		{"/usr/bin/rpcinfo", &grants.Info},
	}
	if grants.NFTables != nil {
		return nil, nfsowner.ErrInvalid
	}
	if withFilter {
		executables = append(executables, executableRole{"/usr/sbin/nft", &grants.NFTables})
	}
	for _, executable := range executables {
		if *executable.file != nil {
			return nil, nfsowner.ErrInvalid
		}
		file, err := openLocalNFSExecutable(executable.path)
		if err != nil {
			return nil, fmt.Errorf("open image NFS executable %s: %w", executable.path, err)
		}
		*executable.file = file
		defer func() { result = errors.Join(result, file.Close()) }()
	}
	verifyStorage, address := grants.VerifyStorage, grants.Address
	grants.VerifyStorage = func(ctx context.Context) error {
		observed, err := observeLocalNFSLink(ctx, address, link.index)
		if err != nil || observed != link {
			return nfsowner.ErrReviewRequired
		}
		return verifyStorage(ctx)
	}
	if err := grants.VerifyStorage(ctx); err != nil {
		return nil, err
	}
	if !withFilter {
		grants.IngressIndex = 0
	}
	return construct(ctx, inputs, grants)
}

func observeLocalNFSLink(ctx context.Context, address netip.Addr, index int) (localNFSLink, error) {
	if ctx == nil || ctx.Err() != nil || !address.Is4() || !address.IsGlobalUnicast() || index <= 0 {
		return localNFSLink{}, nfsowner.ErrInvalid
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	interfaces, err := net.Interfaces()
	if err != nil {
		return localNFSLink{}, err
	}
	var link localNFSLink
	for _, candidate := range interfaces {
		addrs, err := candidate.Addrs()
		if err != nil {
			return localNFSLink{}, err
		}
		for _, entry := range addrs {
			prefix, err := netip.ParsePrefix(entry.String())
			if err != nil {
				return localNFSLink{}, nfsowner.ErrInvalid
			}
			if prefix.Addr().Unmap() != address {
				continue
			}
			if link.index != 0 || candidate.Index != index || candidate.Flags&net.FlagUp == 0 ||
				candidate.Flags&net.FlagLoopback != 0 || len(candidate.HardwareAddr) != 6 {
				return localNFSLink{}, nfsowner.ErrInvalid
			}
			link = localNFSLink{index: index, name: candidate.Name, mac: candidate.HardwareAddr.String()}
		}
	}
	if link.index == 0 || ctx.Err() != nil {
		return localNFSLink{}, nfsowner.ErrInvalid
	}
	return link, nil
}

func openLocalNFSExecutable(path string) (file *os.File, result error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			result = errors.Join(result, err)
			if file != nil {
				result = errors.Join(result, file.Close())
				file = nil
			}
		}
	}()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != 0 || before.Gid != 0 || before.Nlink != 1 ||
		before.Mode&07022 != 0 || before.Mode&0100 == 0 {
		return nil, nfsowner.ErrInvalid
	}
	file, err = os.Open("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return nil, err
	}
	if unix.Fstat(int(file.Fd()), &after) != nil || before.Dev != after.Dev ||
		before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid ||
		before.Gid != after.Gid || before.Nlink != after.Nlink || before.Size != after.Size ||
		before.Ctim != after.Ctim {
		return nil, errors.Join(nfsowner.ErrInvalid, file.Close())
	}
	return file, nil
}
