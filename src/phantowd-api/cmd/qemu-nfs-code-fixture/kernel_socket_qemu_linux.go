//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"golang.org/x/sys/unix"
)

// Both original objects survive every outcome until the disposable VM exits.
var kernelSocketFixtureRetained struct {
	controller *nfskernel.ControllerQEMU
	foreign    *os.File
}

func kernelSocketCommandQEMU(command []byte) bool {
	if len(command) == 0 || len(command) > 4096 || strings.IndexByte(string(command), 0) >= 0 {
		return false
	}
	count := 0
	for _, word := range strings.FieldsFunc(string(command), func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }) {
		if word == "phantowd_nfs_code_fixture=1" {
			count++
		} else if strings.HasPrefix(word, "phantowd_nfs_") {
			return false
		}
	}
	return count == 1
}

type kernelSocketForeignObservation struct{ device, inode, cookie uint64 }

func observeKernelSocketForeign(file *os.File) (kernelSocketForeignObservation, error) {
	if file == nil {
		return kernelSocketForeignObservation{}, nfskernel.ErrRefused
	}
	fd := int(file.Fd())
	var st unix.Stat_t
	address, addressErr := unix.Getsockname(fd)
	bound, ok := address.(*unix.SockaddrInet4)
	accepting, acceptingErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	cookie, cookieErr := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Ino == 0 ||
		addressErr != nil || !ok || bound.Port != 2049 || bound.Addr != [4]byte{127, 0, 0, 1} ||
		acceptingErr != nil || accepting != 0 || cookieErr != nil || cookie == 0 {
		return kernelSocketForeignObservation{}, nfskernel.ErrRefused
	}
	return kernelSocketForeignObservation{uint64(st.Dev), st.Ino, cookie}, nil
}

func runKernelSocketRefusalQEMU(ctx context.Context, command []byte) (result error) {
	phase := "guard"
	defer func() {
		if result != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_KERNEL_SOCKET_FAILURE phase=%s\n", phase)
		}
	}()
	if ctx == nil || ctx.Err() != nil || !kernelSocketCommandQEMU(command) || kernelSocketFixtureRetained.controller != nil {
		return nfskernel.ErrRefused
	}
	// The real constructor enforces ARMv5/root/model/original namespace guards
	// BEFORE this fixture can bind any socket. No host or NAS fallback exists.
	controller, err := nfskernel.OpenCodeQEMU(ctx)
	if err != nil {
		return err
	}
	kernelSocketFixtureRetained.controller = controller
	if err := controller.CheckPreparedQEMU(ctx); err != nil {
		return err
	}
	phase = "foreign-bound-control"
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return err
	}
	kernelSocketFixtureRetained.foreign = os.NewFile(uintptr(fd), "nfs-fixture-independent-bound-socket")
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: 2049, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return err
	}
	foreign, err := observeKernelSocketForeign(kernelSocketFixtureRetained.foreign)
	if err != nil {
		return err
	}
	before, err := sourceFDCount()
	if err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_KERNEL_SOCKET_ARMED foreign_bound=true foreign_listening=false original_prepared=true scope=qemu-only")
	phase = "actual-start-refusal"
	startErr := controller.Start(ctx)
	if !errors.Is(startErr, nfskernel.ErrRefused) || ctx.Err() != nil {
		return errors.Join(nfskernel.ErrRefused, startErr)
	}
	if count, err := sourceFDCount(); err != nil || count != before+1 {
		return errors.New("controlled startup did not retain exactly one acquired socket")
	}
	if !errors.Is(startErr, unix.EADDRINUSE) || controller.CheckUnattachedStoppedQEMU(ctx) == nil {
		return errors.New("actual bind cause or pre-stop refusal missing")
	}
	preCanceled, preCancel := context.WithCancel(ctx)
	preCancel()
	if !errors.Is(controller.Stop(preCanceled), nfskernel.ErrRefused) {
		return errors.New("pre-canceled stop was admitted")
	}
	if count, err := sourceFDCount(); err != nil || count != before+1 || controller.CheckUnattachedStoppedQEMU(ctx) == nil {
		return errors.New("pre-canceled stop changed the original pending socket")
	}
	phase = "owned-socket-close"
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stopErr := controller.Stop(cleanup)
	cancel()
	if !errors.Is(stopErr, nfskernel.ErrRefused) {
		return errors.Join(nfskernel.ErrRefused, stopErr)
	}
	if count, err := sourceFDCount(); err != nil || count != before {
		return errors.New("unattached owned socket was not settled")
	}
	phase = "original-stopped-witness"
	if controller.CheckUnattachedStoppedQEMU(ctx) != nil {
		return errors.New("original unattached stopped witness missing")
	}
	copyController := *controller
	if copyController.CheckUnattachedStoppedQEMU(ctx) == nil {
		return errors.New("copied controller admitted as original stopped witness")
	}
	for _, operation := range []func(context.Context) error{controller.Start, controller.Stop, controller.CheckRunning,
		controller.CheckStopped, controller.CheckPreparedQEMU, controller.Close} {
		if !errors.Is(operation(ctx), nfskernel.ErrRefused) {
			return errors.New("reviewed controller admitted retry, restart or release")
		}
	}
	if replacement, err := nfskernel.OpenCodeQEMU(ctx); replacement != nil || !errors.Is(err, nfskernel.ErrRefused) {
		return errors.New("retained original reservation admitted replacement")
	}
	phase = "foreign-control-retained"
	if after, err := observeKernelSocketForeign(kernelSocketFixtureRetained.foreign); err != nil || after != foreign {
		return errors.New("independent bound socket changed")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if count, err := sourceFDCount(); err != nil || count != before || controller.CheckUnattachedStoppedQEMU(ctx) != nil {
		return errors.New("reviewed observations released original references")
	}
	fmt.Println("PHANTOWD_NFS_KERNEL_SOCKET_READY actual_bind_refused=true owned_socket_closed=true original_control_retained=true foreign_socket_unchanged=true kernel_never_attached=true kernel_never_started=true review_retained=true no_retry=true no_restart=true release=false product=false scope=kernel-component-only")
	return nil
}
