// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nftguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// A managed runtime serializes these operations and retains the NFSD lock
// through removal. The platform must reserve these ports and this table name
// for NFS in the retained network namespace.
type nfsFirewall struct {
	code      *os.File
	domain    func(context.Context) error
	hardware  string
	rules     nfsFirewallRules
	handle    uint64
	attempted bool
	review    bool
}

func newNFSFirewall(ctx context.Context, domain func(context.Context) error, address netip.Addr,
	index int, sources []netip.Prefix, executable *os.File) (*nfsFirewall, error) {
	if ctx == nil || domain == nil || !address.Is4() || index <= 0 || executable == nil {
		return nil, ErrInvalid
	}
	sources, err := normalizeNFSSources(sources)
	if err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := domain(ctx); err != nil {
		return nil, err
	}
	device, err := nfsFirewallInterface(index, address)
	if err != nil {
		return nil, err
	}
	code, err := processowner.RetainExecutable(executable)
	if err != nil {
		return nil, err
	}
	return &nfsFirewall{code: code, domain: domain, hardware: device.HardwareAddr.String(), rules: nfsFirewallRules{
		index: index, name: device.Name, address: address, sources: sources, token: "phantowd:" + rand.Text(),
	}}, nil
}

func nfsFirewallInterface(index int, address netip.Addr) (*net.Interface, error) {
	device, err := net.InterfaceByIndex(index)
	if err != nil || device.Flags&net.FlagUp == 0 {
		return nil, ErrState
	}
	addrs, err := device.Addrs()
	if err != nil {
		return nil, err
	}
	for _, value := range addrs {
		prefix, err := netip.ParsePrefix(value.String())
		if err != nil {
			return nil, err
		}
		if prefix.Addr() == address {
			return device, nil
		}
	}
	return nil, ErrState
}

func (f *nfsFirewall) start(ctx context.Context) error {
	if f.attempted || f.review {
		return ErrState
	}
	if err := f.check(ctx); err != nil {
		return err
	}
	f.attempted = true
	if _, err := f.run(ctx, f.rules.install(), "-f", "-"); err != nil {
		return f.requireReview(err)
	}
	handle, err := f.inspect(ctx)
	if err != nil {
		return f.requireReview(err)
	}
	f.handle = handle
	return nil
}

func (f *nfsFirewall) check(ctx context.Context) error {
	if f.review {
		return ErrReviewRequired
	}
	if !f.attempted {
		return f.requireAbsent(ctx)
	}
	handle, err := f.inspect(ctx)
	if err != nil || handle != f.handle || handle == 0 {
		return f.requireReview(err)
	}
	return nil
}

func (f *nfsFirewall) close(ctx context.Context) error {
	if err := f.check(ctx); err != nil {
		return err
	}
	if f.attempted {
		if _, err := f.run(ctx, "", "delete", "table", "inet", "handle", strconv.FormatUint(f.handle, 10)); err != nil {
			return f.requireReview(err)
		}
		if err := f.requireAbsent(ctx); err != nil {
			return f.requireReview(err)
		}
	}
	return f.release()
}

func (f *nfsFirewall) release() error {
	if err := f.code.Close(); err != nil {
		return f.requireReview(err)
	}
	f.code = nil
	return nil
}

func (f *nfsFirewall) requireUnclaimed(ctx context.Context) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := f.domain(ctx); err != nil {
		return err
	}
	if err := checkNFSTransport(ctx, 0, nfsPorts[:]); err != nil {
		return err
	}
	return f.domain(ctx)
}

func (f *nfsFirewall) requireReview(err error) error {
	f.review = true
	return errors.Join(ErrReviewRequired, err)
}

func (f *nfsFirewall) inspect(ctx context.Context) (uint64, error) {
	out, err := f.run(ctx, "", "-a", "-j", "-n", "list", "table", "inet", nfsTable)
	if err != nil {
		return 0, err
	}
	objects, err := nftguard.ParseObjects(out)
	if err != nil {
		return 0, ErrState
	}
	return f.rules.snapshot(objects)
}

func (f *nfsFirewall) requireAbsent(ctx context.Context) error {
	out, err := f.run(ctx, "", "-a", "-j", "-n", "list", "tables")
	if err != nil {
		return err
	}
	objects, err := nftguard.ParseObjects(out)
	if err != nil || nftguard.RequireAbsent(objects, "inet", nfsTable) != nil {
		return ErrState
	}
	return nil
}

func (f *nfsFirewall) run(ctx context.Context, request string, args ...string) ([]byte, error) {
	if f.code == nil {
		return nil, ErrState
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := f.domain(ctx); err != nil {
		return nil, err
	}
	device, err := nfsFirewallInterface(f.rules.index, f.rules.address)
	if err != nil || device.Name != f.rules.name || device.HardwareAddr.String() != f.hardware {
		return nil, errors.Join(ErrState, err)
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Args[0], cmd.Dir = "/usr/sbin/nft", "/"
	cmd.Env, cmd.ExtraFiles = []string{"LC_ALL=C"}, []*os.File{f.code}
	cmd.Stdin = strings.NewReader(request)
	cmd.WaitDelay = time.Second
	out := &exportOutput{limit: 8 << 20}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	return out.data.Bytes(), f.domain(ctx)
}
