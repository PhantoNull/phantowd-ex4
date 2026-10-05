//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"golang.org/x/sys/unix"
)

const writableFixtureData = "PHANTOWD_WRITER"

// Fixed QEMU-only child; not a LIO backend or a general process launcher.
// No interpolated names/credentials/commands. The child receives only its
// inherited RW file capability and uses UID/GID1000, not the opener's root UID.
type fixtureWritableBackend struct {
	cmd                     *exec.Cmd
	done                    chan struct{}
	file                    *os.File
	stopCalls               int
	stopFailure             bool
	stopWithLiveReference   bool
	prepareCalls            int
	credentialPeers         []iscsicredentials.Credential
	stopWithLiveCredentials bool
}

func (b *fixtureWritableBackend) start(ctx context.Context, file *os.File) error {
	return b.startFixedConsumer(ctx, []*os.File{file}, "-qemu-writable-backing-consumer", []string{writableFixtureData})
}
func (b *fixtureWritableBackend) startFixedConsumer(ctx context.Context, files []*os.File, mode string, markers []string) error {
	if len(files) == 0 || len(files) != len(markers) ||
		(mode != "-qemu-writable-backing-consumer" && mode != "-qemu-target-backing-consumer") {
		return ErrInvalid
	}
	b.file = files[0]
	b.cmd = exec.Command("/usr/bin/phantowd-api", mode)
	b.cmd.Dir = "/"
	b.cmd.ExtraFiles = append([]*os.File(nil), files...)
	b.cmd.Stdout = io.Discard
	b.cmd.Stderr = io.Discard
	b.cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}, Pdeathsig: syscall.SIGKILL}
	if err := b.cmd.Start(); err != nil {
		return ErrUnavailable
	}
	b.done = make(chan struct{})
	go func() { _ = b.cmd.Wait(); close(b.done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ready := true
		for i, file := range files {
			data := make([]byte, len(markers[i]))
			if _, err := file.ReadAt(data, 0); err != nil || string(data) != markers[i] {
				ready = false
				break
			}
		}
		if ready {
			for sample := 0; sample < 32; sample++ {
				if err := b.verifyFixtureCredentials(); err != nil {
					return err
				}
			}
			return nil
		}
		select {
		case <-b.done:
			return ErrUnavailable
		case <-ctx.Done():
			return ErrUnavailable
		default:
		}
		if time.Now().After(deadline) {
			return ErrUnavailable
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (b *fixtureWritableBackend) verifyFixtureCredentials() error {
	file, err := os.Open("/proc/" + strconv.Itoa(b.cmd.Process.Pid) + "/status")
	if err != nil {
		return ErrUnavailable
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 8193))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 8192 {
		return ErrUnavailable
	}
	uid, gid, groups := false, false, false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && (fields[0] == "Uid:" || fields[0] == "Gid:") {
			if fields[1] != "1000" || fields[2] != "1000" || fields[3] != "1000" || fields[4] != "1000" {
				return ErrUnavailable
			}
			if fields[0] == "Uid:" {
				uid = true
			} else {
				gid = true
			}
		}
		if len(fields) == 1 && fields[0] == "Groups:" {
			groups = true
		}
	}
	if !uid || !gid || !groups {
		return ErrUnavailable
	}
	return nil
}
func (b *fixtureWritableBackend) running(context.Context) (bool, error) {
	if b.done == nil {
		return false, nil
	}
	select {
	case <-b.done:
		return false, nil
	default:
		return true, nil
	}
}
func (b *fixtureWritableBackend) stop(ctx context.Context) error {
	b.stopCalls++
	if len(b.credentialPeers) > 0 {
		_, err := b.credentialPeers[0].Incoming.WriteTo(io.Discard)
		b.stopWithLiveCredentials = err == nil
	}
	if b.file != nil {
		_, err := b.file.Stat()
		b.stopWithLiveReference = err == nil
	}
	if b.stopFailure {
		return ErrReview
	}
	return b.teardown(ctx)
}

// Independent test-fixture teardown after assertions; never an Owner retry or
// product recovery. Kill/Wait belong to this exact child, not a pathname/PID scan.
func (b *fixtureWritableBackend) teardown(ctx context.Context) error {
	if b.done == nil {
		return nil
	}
	if err := b.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return ErrReview
	}
	select {
	case <-b.done:
		return nil
	case <-ctx.Done():
		return ErrReview
	}
}

func RunQEMUWritableFixture(root *mountguard.Root, anchor string) (result error) {
	workspace, err := os.MkdirTemp(anchor, "writable-backing-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(workspace)) }()
	parent := filepath.Base(workspace)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	open := func(name string) (*Pin, *os.File, error) {
		file := workspace + "/" + name
		if err := os.WriteFile(file, make([]byte, 4096), 0600); err != nil {
			return nil, nil, err
		}
		p, _, err := Open(root, parent+"/"+name, 4096)
		if err != nil {
			return nil, nil, err
		}
		// Fixture-only descriptor acquisition from a freshly generated private
		// file. NOT a production name-based opener; constructor compares the
		// retained descriptor with Pin before/after and never creates/truncates.
		fd, err := unix.Open(file, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			p.Close()
			return nil, nil, err
		}
		return p, os.NewFile(uintptr(fd), "qemu-writable-fixture"), nil
	}
	p, file, err := open("admission")
	if err != nil {
		return err
	}
	defer p.Close()
	defer file.Close()
	var missingBackend *fixtureWritableBackend
	if owner, err := newWritableOwner(p, file, missingBackend); owner != nil || !errors.Is(err, ErrInvalid) || p.consumer != nil {
		return errors.New("typed nil backend admitted on real Root")
	}
	for _, kind := range []string{"foreign", "readonly", "append", "inherit"} {
		var other *os.File
		if kind == "foreign" {
			q, f, e := open("foreign")
			if e != nil {
				return e
			}
			q.Close()
			other = f
		} else {
			flags := unix.O_RDWR | unix.O_CLOEXEC
			if kind == "readonly" {
				flags = unix.O_RDONLY | unix.O_CLOEXEC
			}
			if kind == "append" {
				flags |= unix.O_APPEND
			}
			if kind == "inherit" {
				flags = unix.O_RDWR
			}
			fd, e := unix.Open(workspace+"/admission", flags, 0)
			if e != nil {
				return e
			}
			other = os.NewFile(uintptr(fd), "qemu-refused-backing")
		}
		owner, e := newWritableOwner(p, other, &fixtureWritableBackend{})
		if owner != nil || !errors.Is(e, ErrUnavailable) {
			other.Close()
			return fmt.Errorf("writable %s admission accepted", kind)
		}
		if _, e := other.Stat(); e != nil {
			return errors.New("failed admission took descriptor ownership")
		}
		if e := other.Close(); e != nil {
			return e
		}
		if p.consumer != nil {
			return errors.New("failed admission took Pin ownership")
		}
	}
	for _, kind := range []string{"normal", "replace", "exit", "uncertain"} {
		p, f, err := open(kind)
		if err != nil {
			return err
		}
		backend := &fixtureWritableBackend{}
		owner, err := newWritableOwner(p, f, backend)
		if err != nil {
			f.Close()
			p.Close()
			return err
		}
		if duplicate, err := newWritableOwner(p, f, &fixtureWritableBackend{}); duplicate != nil || !errors.Is(err, ErrBusy) || p.consumer != owner {
			return errors.New("duplicate consumer claim admitted")
		}
		if err := exerciseWritableOwnerFixture(ctx, owner, backend, workspace+"/"+kind, kind, nil); err != nil {
			// Synthetic resource teardown only, after independent confirmed reap.
			if backend.teardown(ctx) == nil {
				_ = f.Close()
				p.mu.Lock()
				p.consumer = nil
				_ = p.closeLocked()
				p.mu.Unlock()
			}
			return fmt.Errorf("writable lifecycle %s: %w", kind, err)
		}
	}
	fmt.Println("PHANTOWD_WRITABLE_BACKING_READY actual_descriptor=true foreign_or_unsafe_flags_denied=true consumer_uid=1000 inherited_rw=true pin_close_busy=true stop_before_release=true replace_quarantined=true unexpected_exit=true uncertain_stop_retains=true no_retry=true serialized_stop=true product_opener=false iscsi_backend=false scope=disposable-qemu-only")
	return nil
}

func exerciseWritableOwnerFixture(ctx context.Context, owner *writableOwner, backend *fixtureWritableBackend, file, kind string, lease *mountowner.MountedVolumeSetLease) error {
	if lease != nil {
		if err := lease.Close(); !errors.Is(err, mountowner.ErrBusy) {
			return errors.New("claimed backing allowed direct mount lease close")
		}
	}
	if err := owner.pin.Close(); !errors.Is(err, ErrBusy) {
		return errors.New("claimed Pin closed")
	}
	if err := owner.start(ctx); err != nil {
		return err
	}
	if err := owner.close(); !errors.Is(err, ErrBusy) {
		return errors.New("live consumer references released")
	}
	if err := owner.observe(ctx); err != nil {
		return err
	}
	switch kind {
	case "normal":
		var wg sync.WaitGroup
		failures := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := owner.stop(ctx); err != nil {
					failures <- err
				}
			}()
		}
		wg.Wait()
		close(failures)
		for err := range failures {
			return err
		}
		if backend.stopCalls != 1 || !backend.stopWithLiveReference || !owner.released {
			return errors.New("stop/reference ordering")
		}
	case "replace":
		if err := os.Rename(file, file+".old"); err != nil {
			return err
		}
		if err := os.WriteFile(file, make([]byte, 4096), 0600); err != nil {
			return err
		}
		if err := owner.observe(ctx); !errors.Is(err, ErrReview) {
			return errors.New("replacement not reviewed")
		}
		if backend.stopCalls != 1 || !backend.stopWithLiveReference || !owner.released {
			return errors.New("drift release preceded stop")
		}
		bytes, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		for _, b := range bytes {
			if b != 0 {
				return errors.New("replacement file modified")
			}
		}
	case "exit":
		if err := backend.teardown(ctx); err != nil {
			return err
		}
		if err := owner.observe(ctx); !errors.Is(err, ErrReview) {
			return errors.New("unexpected exit not reviewed")
		}
		if !owner.released || backend.stopCalls != 1 {
			return errors.New("exit cleanup ordering")
		}
	case "uncertain":
		backend.stopFailure = true
		if err := owner.stop(ctx); !errors.Is(err, ErrReview) {
			return errors.New("uncertain stop accepted")
		}
		for _, op := range []func() error{func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close, func() error { return owner.start(ctx) }} {
			if err := op(); !errors.Is(err, ErrReview) {
				return errors.New("uncertain review bypass")
			}
		}
		if backend.stopCalls != 1 || owner.released || owner.pin.consumer != owner {
			return errors.New("uncertain stop released/retried")
		}
		if err := owner.pin.Close(); !errors.Is(err, ErrBusy) {
			return errors.New("uncertain Pin close bypass")
		}
		if _, err := owner.file.Stat(); err != nil {
			return errors.New("uncertain RW reference lost")
		}
		if lease != nil {
			if err := lease.Close(); !errors.Is(err, mountowner.ErrBusy) {
				return errors.New("uncertain stop released mount lifetime")
			}
		}
		// Destroy this disposable fixture only after separately proving child reap;
		// the Owner itself stays reviewed, never becomes a recovery implementation.
		if err := backend.teardown(ctx); err != nil {
			return err
		}
		if err := owner.file.Close(); err != nil {
			return err
		}
		owner.pin.mu.Lock()
		owner.pin.consumer = nil
		err := owner.pin.closeLocked()
		owner.pin.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}
