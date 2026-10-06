//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

const sambaFixtureHelper = "/usr/sbin/phantowd-samba-root-launcher"

// This separate constructor exists ONLY in the guarded disposable fixture.
// It reuses serialized retention/stop/review policy, not NewOwner's generic
// static/non-root admission. It is not the complete Samba-specific Owner:
// config, identity and data grants still lack retained product authority.
func (p *Plan) newSambaCodeLifetimeQEMU(ctx context.Context, root *os.File) (owner *Owner, result error) {
	if p == nil || ctx == nil || root == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := sambaCodeFixtureGuard(); err != nil {
		return nil, err
	}
	o := &Owner{gate: make(chan struct{}, 1)}
	defer func() {
		if result != nil {
			result = errors.Join(result, o.release())
		}
	}()
	var err error
	o.retainedCode, err = p.prepareRetainedCode(ctx, root)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(sambaFixtureHelper, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	helper := os.NewFile(uintptr(fd), "fixed-qemu-bootstrap")
	if err := staticExecutable(helper); err != nil {
		return nil, errors.Join(err, helper.Close())
	}
	o.processes, err = processowner.NewPinnedSet([]processowner.MemberSpec{{Name: "samba-code", Process: processowner.Spec{
		Executable: sambaFixtureHelper, Args: []string{"owned-server"},
		RunAs: &processowner.Credentials{UID: 0, GID: 0},
		Ready: func(ctx context.Context) (bool, error) {
			_, err := sambaFixtureClient(ctx, "qpwriter", "ls")
			return err == nil, ctx.Err()
		},
		ReadyTimeout: 20 * time.Second, ProbeInterval: 200 * time.Millisecond, StopTimeout: 4 * time.Second,
	}}}, []*os.File{helper})
	closeErr := helper.Close()
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	// Late original-object identity check after the fixed helper/process inputs.
	if err := o.revalidate(ctx); err != nil {
		return nil, err
	}
	o.snapshot = OwnerSnapshot{State: processowner.StateStopped, Bundle: o.retainedCode.observation}
	return o, nil
}

func sambaCodeFixtureGuard() error {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" || os.Getuid() != 0 ||
		os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return ErrInvalid
	}
	return nil
}

// ProbeSambaCodeLifetimeQEMU exercises actual live dynamic-code retention and
// one controlled mode drift. Fixed paths/IDs/bootstrap are fixture-only. It
// returns no owner/descriptors and creates no product activation entrypoint.
func (p *Plan) ProbeSambaCodeLifetimeQEMU(ctx context.Context, root, writer *os.File) (result error) {
	if p == nil || len(p.files) == 0 || ctx == nil || root == nil || writer == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sambaCodeFixtureGuard(); err != nil {
		return err
	}
	readerInfo, err := root.Stat()
	if err != nil {
		return err
	}
	writerInfo, err := writer.Stat()
	var writableFS unix.Statfs_t
	if err != nil || !os.SameFile(readerInfo, writerInfo) ||
		unix.Fstatfs(int(writer.Fd()), &writableFS) != nil || writableFS.Type != unix.TMPFS_MAGIC ||
		writableFS.Flags&unix.ST_RDONLY != 0 {
		return errors.New("invalid disposable fault anchor")
	}
	// Initialize runtime pipe polling before comparing steady-state descriptors.
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
	for _, test := range []struct{ drift, forced bool }{{false, false}, {true, false}, {true, true}} {
		if err := p.sambaCodeLifetimeCase(ctx, root, writer, test.drift, test.forced); err != nil {
			return err
		}
	}
	after, err := retainedFixtureFDCount()
	if err != nil || after != before {
		return errors.Join(errors.New("Samba code lifetime descriptor leak"), err)
	}
	fmt.Println("PHANTOWD_SAMBA_OWNER_CODE_LIFETIME_READY caller_close=true live_code_pins=true normal_stop=true drift_stopped=true forced_stop_review=true review_retained=true restoration_refused=true released=true no_fd_leak=true scope=qemu-only")
	return nil
}

func (p *Plan) sambaCodeLifetimeCase(ctx context.Context, root, writer *os.File, drift, forced bool) (result error) {
	caller, err := duplicateRoot(root)
	if err != nil {
		return err
	}
	o, err := p.newSambaCodeLifetimeQEMU(ctx, caller)
	callerErr := caller.Close()
	if err != nil || callerErr != nil {
		if o != nil {
			return errors.Join(err, callerErr, o.Close(context.Background()))
		}
		return errors.Join(err, callerErr)
	}
	defer func() {
		if o != nil {
			result = errors.Join(result, o.Close(context.Background()))
		}
	}()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := o.Start(canceled); !errors.Is(err, context.Canceled) || got.State == processowner.StateReady {
		return errors.New("canceled code lifetime admission")
	}
	bounded, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	started, err := o.Start(bounded)
	if err != nil || started.State != processowner.StateReady || len(started.Processes.Members) != 1 {
		return errors.Join(errors.New("retained Samba code readiness"), err)
	}
	pid := started.Processes.Members[0].Process.PID
	if err := o.verifyLiveSambaCodeQEMU(pid); err != nil {
		return err
	}
	if got, err := o.Observe(bounded); err != nil || got.State != processowner.StateReady {
		return errors.Join(errors.New("live complete-code revalidation"), err)
	}
	if drift {
		if forced {
			if err := stopSambaFixtureGroup(pid); err != nil {
				return err
			}
		}
		fd, err := openBeneath(int(writer.Fd()), "usr/lib/gconv/gconv-modules", unix.O_RDONLY)
		if err != nil {
			return err
		}
		control := os.NewFile(uintptr(fd), "fixed-qemu-mode-fault")
		defer control.Close()
		if unix.Fchmod(fd, 0444) != nil {
			return errors.New("controlled code mode mutation")
		}
		defer unix.Fchmod(fd, 0555)
		var observed unix.Stat_t
		if unix.Fstat(fd, &observed) != nil || observed.Mode&0777 != 0444 {
			return errors.New("controlled mode mutation not observed")
		}
		got, err := o.Observe(bounded)
		if !errors.Is(err, ErrReviewRequired) || got.State != processowner.StateReviewRequired ||
			len(o.files) != len(p.files) || o.root == nil ||
			(!forced && (!errors.Is(unix.Kill(-pid, 0), unix.ESRCH) || got.Processes.Members[0].Process.PID != 0)) ||
			(forced && (got.Processes.State != processowner.StateReviewRequired || got.Processes.Members[0].Process.PID != pid)) {
			return errors.Join(errors.New("code drift did not stop and retain for review"), err)
		}
		// References remain actually usable until explicit verified teardown.
		for _, pin := range o.files {
			if _, err := pin.Stat(); err != nil {
				return errors.New("review lost a retained code descriptor")
			}
		}
		if unix.Fchmod(fd, 0555) != nil || unix.Fstat(fd, &observed) != nil || observed.Mode&0777 != 0555 {
			return errors.New("controlled mode restoration")
		}
		if got, err := o.Start(bounded); !errors.Is(err, ErrReviewRequired) || got.State != processowner.StateReviewRequired {
			return errors.New("restoration restarted reviewed Samba")
		}
	}
	closeErr := o.Close(context.Background())
	if (!drift && closeErr != nil) || (drift && !errors.Is(closeErr, ErrReviewRequired)) ||
		!errors.Is(unix.Kill(-pid, 0), unix.ESRCH) || o.root != nil || len(o.files) != 0 ||
		!errors.Is(o.revalidate(ctx), ErrUnavailable) || o.Close(context.Background()) != nil {
		return errors.Join(errors.New("Samba code release before verified teardown"), closeErr)
	}
	o = nil
	return nil
}

// Only the exact fixture-created group is frozen, after real SMB readiness.
// Read back a stopped leader before invoking the existing bounded Owner stop.
// This forces termination escalation; it is not a product pause/kill API.
func stopSambaFixtureGroup(pid int) error {
	if pid <= 1 || unix.Kill(-pid, unix.SIGSTOP) != nil {
		return errors.New("fixture group freeze failed")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
		if err != nil || len(status) > 64<<10 {
			return errors.New("fixture frozen-group observation failed")
		}
		if bytes.Contains(status, []byte("State:\tT (stopped)\n")) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("fixture group did not enter stopped state")
}

func sambaFixtureClient(ctx context.Context, user, operation string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	return exec.CommandContext(bounded, sambaFixtureHelper, "client", user, "ReadWrite", operation).CombinedOutput()
}

func (o *Owner) verifyLiveSambaCodeQEMU(pid int) error {
	if pid <= 1 || len(o.files) != len(o.plan.files) {
		return errors.New("incomplete live Samba code")
	}
	for _, pin := range o.files {
		if _, err := pin.Stat(); err != nil {
			return errors.New("live code reference lost")
		}
	}
	group, err := unix.Getpgid(pid)
	if err != nil || group != pid {
		return errors.New("live Samba escaped group")
	}
	base := "/proc/" + strconv.Itoa(pid)
	actual, err := os.Stat(base + "/exe")
	if err != nil {
		return err
	}
	expected, err := o.files["usr/sbin/smbd"].Stat()
	if err != nil || !os.SameFile(actual, expected) {
		return errors.New("Samba did not execute retained code object")
	}
	status, err := os.ReadFile(base + "/status")
	if err != nil || len(status) > 64<<10 {
		return errors.New("live Samba authority unavailable")
	}
	for _, expected := range []string{"CapEff:\t00000000000000db", "CapPrm:\t00000000000000db",
		"CapBnd:\t00000000000000db", "CapInh:\t0000000000000000", "CapAmb:\t0000000000000000", "NoNewPrivs:\t1"} {
		if !bytes.Contains(status, []byte(expected+"\n")) {
			return errors.New("live Samba authority changed")
		}
	}
	childRoot, err := os.Readlink(base + "/root")
	if err != nil || childRoot != "/run/phantowd-samba-root" {
		return errors.New("live Samba root changed")
	}
	childNS, err := os.Readlink(base + "/ns/mnt")
	if err != nil {
		return err
	}
	parentNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil || parentNS == childNS {
		return errors.New("live Samba namespace shared")
	}
	output, err := sambaFixtureClient(context.Background(), "qpreader", "get owned-created /run/download")
	if err != nil || strings.Contains(string(output), "NT_STATUS_") {
		return errors.New("retained Samba distinct reader unavailable")
	}
	wanted, err := os.ReadFile("/run/upload")
	if err != nil {
		return err
	}
	got, err := os.ReadFile("/run/download")
	if err != nil || !bytes.Equal(wanted, got) {
		return errors.New("retained Samba reader bytes changed")
	}
	return nil
}
