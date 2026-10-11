//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const serverCaptureClientHandlePrefixQEMU = "PHANTOWD_CAPTURE_CLIENT_HANDLE "
const serverCaptureClientOpenNoticeQEMU = "PHANTOWD_CAPTURE_CLIENT_OPEN scope=qemu-only proof=false\n"
const serverCaptureClientCloseNoticeQEMU = "PHANTOWD_CAPTURE_CLIENT_CLOSE scope=qemu-only proof=false\n"

func serverCaptureClientHandleNoticeQEMU(h PendingHandleObservationQEMU) string {
	return serverCaptureClientHandlePrefixQEMU + h.notice()[len(pendingHandlePrefixQEMU):]
}

// Exact bounded client telemetry only, never original server/open authority.
// Every operation must consume the same initial tuple and the caller's fixed
// requested read count. Incomplete output never publishes partial metadata.
func serverCaptureClientNoticesQEMU(stdout, stderr []byte, samples uint8, closing bool, initial PendingHandleObservationQEMU) (PendingHandleObservationQEMU, bool, error) {
	refuse := func() (PendingHandleObservationQEMU, bool, error) {
		return PendingHandleObservationQEMU{}, false, ErrReviewRequired
	}
	if len(stderr) != 0 || len(stdout) > 4096 || samples > 2 {
		return refuse()
	}
	observed := initial
	if !initial.valid() {
		if initial != (PendingHandleObservationQEMU{}) || closing || samples != 0 {
			return refuse()
		}
		end := bytes.IndexByte(stdout, '\n')
		prefix := []byte(serverCaptureClientHandlePrefixQEMU)
		if end < 0 {
			if len(stdout) > 256 || (!bytes.HasPrefix(prefix, stdout) && !bytes.HasPrefix(stdout, prefix)) {
				return refuse()
			}
			return PendingHandleObservationQEMU{}, false, nil
		}
		if !bytes.HasPrefix(stdout, prefix) || end+1 > 256 {
			return refuse()
		}
		canonical := append([]byte(pendingHandlePrefixQEMU), stdout[len(prefix):end+1]...)
		var err error
		observed, err = parsePendingHandleQEMU(canonical)
		if err != nil {
			return refuse()
		}
	}
	expected := serverCaptureClientHandleNoticeQEMU(observed) + serverCaptureClientOpenNoticeQEMU
	for sample := uint8(1); sample <= samples; sample++ {
		expected += fmt.Sprintf("PHANTOWD_CAPTURE_CLIENT_READ sequence=%d scope=qemu-only proof=false\n", sample)
	}
	if closing {
		expected += serverCaptureClientCloseNoticeQEMU
	}
	if !bytes.HasPrefix([]byte(expected), stdout) {
		return refuse()
	}
	if string(stdout) != expected {
		return PendingHandleObservationQEMU{}, false, nil
	}
	return observed, true, nil
}

// Dedicated single-use read-only capture process, not complete code/storage or
// server-open authority. Containing composition retains/revalidates the whole
// client/root/bootstrap census before and after every operation. No WRITE,
// caller-selected program/profile or replacement backend. Never installed.
type ServerCaptureClientQEMU struct {
	self    *ServerCaptureClientQEMU
	adapter *PendingClientQEMU
}

func NewServerCaptureClientQEMU(helper, root, client *os.File, secret []byte) (*ServerCaptureClientQEMU, error) {
	line, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(line) > 4096 {
		return nil, ErrInvalid
	}
	marked := false
	for _, field := range strings.Fields(string(line)) {
		if field == "phantowd_capture_runtime_fixture=1" {
			marked = true
		}
	}
	if !marked {
		return nil, ErrInvalid
	}
	inner, err := newPendingClientQEMU(helper, root, client, secret, true)
	if err != nil {
		return nil, err
	}
	inner.captureMode = true
	value := &ServerCaptureClientQEMU{adapter: inner}
	value.self = value
	return value, nil
}

func (c *ServerCaptureClientQEMU) validQEMU() bool {
	return c != nil && c.self == c && c.adapter != nil && c.adapter.self == c.adapter && c.adapter.captureMode && c.adapter.handleMode
}

func (c *ServerCaptureClientQEMU) Start(ctx context.Context) error {
	if !c.validQEMU() {
		return ErrUnavailable
	}
	return c.adapter.Start(ctx)
}

func (c *ServerCaptureClientQEMU) CloseClient(ctx context.Context) error {
	if !c.validQEMU() {
		return ErrUnavailable
	}
	return c.adapter.CloseClient(ctx)
}

func (c *ServerCaptureClientQEMU) Stop(ctx context.Context) error {
	if !c.validQEMU() {
		return ErrUnavailable
	}
	return c.adapter.Stop(ctx)
}

func (c *ServerCaptureClientQEMU) Close() error {
	if !c.validQEMU() {
		return ErrUnavailable
	}
	return c.adapter.Close()
}

// Rechecks the originally retained proc directory, not a reopened numeric PID.
// This is process containment only, not a worker/SMB/local-file observation.
func (c *PendingClientQEMU) captureRecheckProcessQEMU() error {
	if !c.captureMode || !c.handleMode || c.originalProc == nil || c.process == nil || c.process.exited() || len(c.pins) != 3 {
		return ErrUnavailable
	}
	generation, err := pendingProcGenerationReadQEMU(c.originalProc)
	if err != nil || generation != c.originalGeneration || generation.pid != c.process.pid || generation.parent != os.Getpid() || generation.group != c.process.pid {
		return errors.Join(ErrUnavailable, err)
	}
	actual, err := os.Stat("/proc/self/fd/" + strconv.FormatUint(uint64(c.originalProc.Fd()), 10) + "/exe")
	expected, expectedErr := c.pins[2].Stat()
	if err != nil || expectedErr != nil || !os.SameFile(actual, expected) {
		return ErrUnavailable
	}
	status, err := pendingProcReadQEMU(c.originalProc, "status", 64<<10)
	if err != nil {
		return err
	}
	return pendingClientStatusQEMU(status)
}

// Cached startup tuple only; no raw telemetry, live SMB re-observation or grant.
func (client *ServerCaptureClientQEMU) InitialHandleObservationQEMU(ctx context.Context) (PendingHandleObservationQEMU, error) {
	if !client.validQEMU() {
		return PendingHandleObservationQEMU{}, ErrUnavailable
	}
	c := client.adapter
	if err := c.enter(ctx); err != nil {
		return PendingHandleObservationQEMU{}, err
	}
	defer func() { <-c.gate }()
	if c.review || !c.started || c.settled || c.closeSent || !c.handleInitial.valid() {
		return PendingHandleObservationQEMU{}, ErrReviewRequired
	}
	if err := c.recheckPins(); err != nil {
		return PendingHandleObservationQEMU{}, c.fail(err)
	}
	if err := c.captureRecheckProcessQEMU(); err != nil {
		return PendingHandleObservationQEMU{}, c.fail(err)
	}
	if ready, err := c.notices(false); err != nil || !ready {
		return PendingHandleObservationQEMU{}, c.fail(errors.Join(ErrNotReady, err))
	}
	if err := ctx.Err(); err != nil {
		return PendingHandleObservationQEMU{}, err
	}
	return c.handleInitial, nil
}

// Requests one fixed byte read on the original client handle (max two). No
// retry/reconnect/reopen; uncertain completion quarantines and stops the group,
// retaining originals in review. Success is ONLY client telemetry, never a
// server sample/lease. Original worker/frame/object binding remains separate.
func (client *ServerCaptureClientQEMU) ReadSample(ctx context.Context) error {
	if !client.validQEMU() {
		return ErrUnavailable
	}
	c := client.adapter
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	if c.review || !c.started || c.settled || c.closeSent || c.process == nil || c.control == nil || !c.handleInitial.valid() {
		return ErrReviewRequired
	}
	if c.captureReads >= 2 {
		return c.fail(ErrReviewRequired)
	}
	if err := c.recheckPins(); err != nil {
		return c.fail(err)
	}
	if err := c.captureRecheckProcessQEMU(); err != nil {
		return c.fail(err)
	}
	if ready, err := c.notices(false); err != nil || !ready {
		return c.fail(errors.Join(ErrNotReady, err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.captureReads++ // Intent precedes the single command; never retry uncertainty.
	written, err := c.control.Write([]byte{'R'})
	if err != nil || written != 1 {
		return c.fail(errors.Join(ErrUnavailable, err))
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := bounded.Err(); err != nil {
			return c.fail(err)
		}
		ready, err := c.notices(false)
		if err != nil || c.process.exited() {
			return c.fail(errors.Join(ErrNotReady, err))
		}
		if ready {
			if err := c.recheckPins(); err != nil {
				return c.fail(err)
			}
			if err := c.captureRecheckProcessQEMU(); err != nil {
				return c.fail(err)
			}
			if err := bounded.Err(); err != nil {
				return c.fail(err)
			}
			return nil
		}
		select {
		case <-bounded.Done():
			return c.fail(bounded.Err())
		case <-ticker.C:
		}
	}
}
