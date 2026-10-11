//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Fixed disposable authenticated OPEN/CLOSE tracer. This is not a server-open
// lease: no READ/frame is requested, and worker/FileId/object/TCP binding is not
// inferred from client telemetry or the fixture's fixed pathname.
func (p *Plan) ProbeServerCaptureOpenQEMU(ctx context.Context, code *os.File) (result error) {
	if ctx == nil || p == nil || code == nil || serverObserverCodeGuardQEMU() != nil {
		return ErrInvalid
	}
	line, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(line) > 4096 {
		return ErrInvalid
	}
	marked := false
	for _, field := range strings.Fields(string(line)) {
		if field == "phantowd_capture_client_open_fixture=1" {
			marked = true
		}
	}
	if !marked {
		return ErrInvalid
	}
	var roots [6]*os.File
	for i, name := range []string{"/run/phantowd-native-samba-root/etc", "/run/phantowd-native-samba-state", "/run/observer-readonly", "/run/observer-writable", "/run/phantowd-pending-client-input", "/run/phantowd-pending-client-bootstrap"} {
		fd, err := unix.Open(name, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		roots[i] = os.NewFile(uintptr(fd), "fixed-capture-open-original-root")
		defer func(f *os.File) { result = errors.Join(result, f.Close()) }(roots[i])
	}
	fd, err := unix.Open("/usr/lib/phantowd/qemu-pending-client-inputs.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	manifestFile := os.NewFile(uintptr(fd), "independent-fixed-client-build-expectations")
	var manifestStat unix.Stat_t
	if unix.Fstat(fd, &manifestStat) != nil || manifestStat.Mode != unix.S_IFREG|0644 || manifestStat.Uid != 0 || manifestStat.Gid != 0 || manifestStat.Size <= 0 || manifestStat.Size > 128<<10 {
		return errors.Join(ErrInvalid, manifestFile.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(manifestFile, (128<<10)+1))
	closeErr := manifestFile.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) != manifestStat.Size {
		return errors.Join(ErrMismatch, readErr, closeErr)
	}
	manifest, err := DecodePendingExpectedQEMU(data)
	if err != nil {
		return err
	}
	clientPlan, err := PendingExpectedPlanQEMU(manifest.RootFiles, manifest.RootAliases)
	if err != nil {
		return err
	}
	bootstrapPlan, err := PendingExpectedPlanQEMU(manifest.BootstrapFiles, nil)
	if err != nil {
		return err
	}
	dataFD, err := openBeneath(int(roots[2].Fd()), "capture-read", unix.O_RDONLY)
	if err != nil {
		return err
	}
	original := os.NewFile(uintptr(dataFD), "original-synthetic-open-data")
	defer func() { result = errors.Join(result, original.Close()) }()
	var beforeData unix.Stat_t
	if unix.Fstat(dataFD, &beforeData) != nil || beforeData.Mode != unix.S_IFREG|0444 || beforeData.Uid != 65534 || beforeData.Gid != 65534 || beforeData.Nlink != 1 || beforeData.Size != 4 {
		return ErrMismatch
	}
	checkData := func() error {
		var current unix.Stat_t
		contents, err := io.ReadAll(io.NewSectionReader(original, 0, 5))
		if err != nil || string(contents) != "data" || unix.Fstat(dataFD, &current) != nil ||
			current.Dev != beforeData.Dev || current.Ino != beforeData.Ino || current.Mode != beforeData.Mode || current.Size != beforeData.Size ||
			current.Uid != beforeData.Uid || current.Gid != beforeData.Gid || current.Nlink != beforeData.Nlink || current.Mtim != beforeData.Mtim || current.Ctim != beforeData.Ctim {
			return errors.Join(ErrMismatch, err)
		}
		return nil
	}
	if err := checkData(); err != nil {
		return err
	}
	a, b, err := os.Pipe()
	if err != nil {
		return err
	}
	if err := errors.Join(a.Close(), b.Close()); err != nil {
		return err
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	refused, err := newServerCaptureClientOwnerQEMU(ctx, clientPlan, bootstrapPlan, roots[4], roots[5], nil)
	if refused != nil || !errors.Is(err, processowner.ErrInvalid) {
		return errors.Join(ErrMismatch, err)
	}
	if count, err := retainedFixtureFDCount(); err != nil || count != before {
		return errors.Join(ErrMismatch, err)
	}
	r, err := newServerCaptureRuntimeQEMU(ctx, p, code, roots[0], roots[1], [2]*os.File{roots[2], roots[3]})
	if err != nil {
		return err
	}
	defer func() {
		if !r.closed {
			stopped, stopErr := r.Stop(context.Background())
			closeErr := r.Close()
			if closeErr != nil || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
				result = errors.Join(result, ErrReviewRequired, stopErr, closeErr)
			}
		}
	}()
	started, err := r.Start(ctx)
	if err != nil || started.State != processowner.StateReady {
		return errors.Join(errors.New("capture OPEN daemon startup"), err)
	}
	// Public disposable fixture credential only; never an operator password.
	o, err := newServerCaptureClientOwnerQEMU(ctx, clientPlan, bootstrapPlan, roots[4], roots[5], []byte("qemu-capture-only"))
	if err != nil {
		return err
	}
	defer func() {
		if !o.closed {
			if o.started && !o.settled {
				result = errors.Join(result, o.stop(context.Background()))
			}
			// Failure unwinds this defer before the runtime defer. Even after
			// a successful client CLOSE, keep its originals until the server
			// group is independently settled; uncertain stop retains review.
			stopped, stopErr := r.Stop(context.Background())
			if stopErr != nil || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
				o.review = true
				result = errors.Join(result, ErrReviewRequired, stopErr)
				return
			}
			result = errors.Join(result, o.close())
		}
	}()
	if err := o.start(ctx); err != nil {
		return errors.Join(errors.New("capture client original OPEN"), err)
	}
	initial, err := o.initialHandle(ctx)
	if err != nil || initial.SessionID == 0 || initial.TreeID == 0 || initial.PersistentID == 0 || initial.VolatileID == 0 {
		return errors.Join(ErrMismatch, err)
	}
	if _, err := r.Observe(ctx); err != nil {
		return err
	}
	if err := o.close(); !errors.Is(err, processowner.ErrBusy) {
		return errors.New("live client released complete originals")
	}
	module := o.inputs.client.files[pendingClientObserverQEMU]
	if module == nil {
		return ErrMismatch
	}
	if err := o.closeClient(ctx); err != nil {
		return errors.Join(errors.New("capture client original CLOSE"), err)
	}
	if _, err := module.Stat(); err != nil {
		return errors.New("client CLOSE released original module")
	}
	if err := o.inputs.revalidate(ctx); err != nil {
		return err
	}
	if err := checkData(); err != nil {
		return err
	}
	stopped, err := r.Stop(context.Background())
	if err != nil || stopped.State != processowner.StateStopped || len(stopped.Members) != 1 || stopped.Members[0].Process.PID != 0 {
		return errors.Join(errors.New("capture OPEN server group did not settle"), err)
	}
	if _, err := module.Stat(); err != nil {
		return errors.New("server stop lost original client module")
	}
	if err := o.close(); err != nil {
		return err
	}
	if err := r.Close(); err != nil {
		return err
	}
	if err := checkData(); err != nil {
		return err
	}
	after, err := retainedFixtureFDCount()
	if err != nil || after != before {
		return errors.Join(errors.New("capture OPEN descriptor leak"), err)
	}
	fmt.Println("PHANTOWD_CAPTURE_OPEN_PROOF authenticated_client=true actual_open_close=true complete_client_inputs=true module_retained=true original_channel_pair=true stop_before_release=true unchanged_data=true fd_equal=true reads=false samples=false worker_binding=false authority=false scope=qemu-only")
	return nil
}
