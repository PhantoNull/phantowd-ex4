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
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Two one-byte read observations only; not a pending request or WRITE lease.
// Complete original input fences remain unchanged and require empty queues.
// Consume the one requested record before those post-fences; never relax them.
func (o *pendingClientOwnerQEMU) readCaptureFrameQEMU(ctx context.Context) (frame pendingServerPacketObservationQEMU, result error) {
	if err := o.enter(ctx); err != nil {
		return frame, err
	}
	defer func() { <-o.gate }()
	if o.review || !o.started || o.settled || o.inputs == nil || o.captureAdapter == nil || o.adapter != nil || o.connectionPeer != nil || o.capturePeer == nil {
		return frame, ErrReviewRequired
	}
	peer := o.capturePeer
	if err := peer.enter(ctx); err != nil {
		return frame, err
	}
	defer func() { <-peer.gate }()
	if peer.closed || peer.review || peer.captureWorker == nil || peer.captureWorker.file == nil || peer.channel == nil || peer.channel.sequence >= 2 {
		return frame, ErrReviewRequired
	}
	defer func() {
		if result != nil {
			frame = pendingServerPacketObservationQEMU{}
			_, peerErr := peer.contain(result)
			result = errors.Join(result, peerErr, o.fail(result))
		}
	}()
	if err := o.inputs.revalidate(ctx); err != nil {
		return frame, err
	}
	if err := peer.observeCaptureWorkerLockedQEMU(ctx, o.connectionFile, o.connectionInitial); err != nil {
		return frame, err
	}
	if err := o.captureAdapter.RecheckConnectionQEMU(ctx); err != nil {
		return frame, err
	}
	initial, err := o.captureAdapter.InitialHandleObservationQEMU(ctx)
	if err != nil {
		return frame, err
	}
	expected, err := captureWorkerSenderQEMU(peer.captureWorker.proc, peer.captureWorker.status.server.PID)
	if err != nil {
		return frame, fmt.Errorf("capture sender before READ: %w", err)
	}
	if err := o.captureAdapter.ReadSample(ctx); err != nil {
		return frame, fmt.Errorf("capture client READ result: %w", err)
	}
	observed, err := peer.channel.next(ctx)
	if err != nil {
		return frame, fmt.Errorf("capture frame receive: %w", err)
	}
	if observed.credentials != expected || !peer.channel.queueEmpty() || matchPendingServerOpenMetadataQEMU(observed.metadata, peer.captureWorker.status, initial) != nil {
		return frame, ErrMismatch
	}
	// The successful client read does not substitute for the original sender,
	// worker/object/process/TCP or complete code/configuration/state fences.
	if err := peer.observeCaptureWorkerLockedQEMU(ctx, o.connectionFile, o.connectionInitial); err != nil {
		return frame, err
	}
	after, err := captureWorkerSenderQEMU(peer.captureWorker.proc, peer.captureWorker.status.server.PID)
	if err != nil || after != expected {
		return frame, errors.Join(ErrMismatch, err)
	}
	if err := o.captureAdapter.RecheckConnectionQEMU(ctx); err != nil {
		return frame, err
	}
	if err := o.inputs.revalidate(ctx); err != nil {
		return frame, err
	}
	if peer.channel.sequence == 2 {
		if err := peer.channel.recheck(ctx); err != nil {
			return frame, err
		}
	}
	if err := ctx.Err(); err != nil {
		return frame, err
	}
	return observed, nil
}

func captureWorkerSenderQEMU(proc *os.File, pid string) (unix.Ucred, error) {
	if proc == nil {
		return unix.Ucred{}, ErrInvalid
	}
	fd, err := unix.Openat(int(proc.Fd()), "status", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return unix.Ucred{}, err
	}
	file := os.NewFile(uintptr(fd), "original-worker-real-credentials")
	data, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return unix.Ucred{}, err
	}
	return parseCaptureWorkerSenderQEMU(data, pid)
}

// Kernel SCM credentials are real process IDs, not the authenticated SMB user.
// Actual real UID/GID and NNP are observed independently from the original proc;
// Samba may use the fixed nobody mode with saved root IDs after authentication.
// Its set_effective_gid deliberately leaves the real GID at zero. The packet
// must match that independently observed real GID, not the effective share GID.
func parseCaptureWorkerSenderQEMU(data []byte, pid string) (unix.Ucred, error) {
	if len(data) == 0 || len(data) > 64<<10 || !pendingNumberQEMU(pid, 31, true) || pid == "1" {
		return unix.Ucred{}, ErrMismatch
	}
	seen := map[string]bool{}
	var realUID, realGID uint32
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "Pid:":
			if seen[fields[0]] || len(fields) != 2 || fields[1] != pid {
				return unix.Ucred{}, ErrMismatch
			}
		case "Uid:", "Gid:":
			if seen[fields[0]] || len(fields) != 5 || fields[3] != "0" || fields[2] != fields[4] {
				return unix.Ucred{}, ErrMismatch
			}
			if fields[1] != fields[2] && (fields[0] != "Gid:" || fields[1] != "0" || fields[2] != "65534") {
				return unix.Ucred{}, ErrMismatch
			}
			for _, id := range fields[1:] {
				if !pendingNumberQEMU(id, 32, false) || (id != "0" && id != "65534") {
					return unix.Ucred{}, ErrMismatch
				}
			}
			value, _ := strconv.ParseUint(fields[1], 10, 32)
			if fields[0] == "Uid:" {
				realUID = uint32(value)
			} else {
				realGID = uint32(value)
			}
		case "NoNewPrivs:":
			if seen[fields[0]] || len(fields) != 2 || fields[1] != "1" {
				return unix.Ucred{}, ErrMismatch
			}
		default:
			continue
		}
		seen[fields[0]] = true
	}
	if len(seen) != 4 {
		return unix.Ucred{}, ErrMismatch
	}
	value, _ := strconv.ParseUint(pid, 10, 31)
	return unix.Ucred{Pid: int32(value), Uid: realUID, Gid: realGID}, nil
}
