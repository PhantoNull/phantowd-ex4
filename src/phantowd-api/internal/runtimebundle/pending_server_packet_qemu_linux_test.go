//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

func pendingPacketFixtureFrameQEMU(sequence uint32) []byte {
	frame := pendingServerFrameExampleQEMU(sequence)
	binary.LittleEndian.PutUint32(frame[76:], uint32(os.Getpid()))
	return frame
}

func TestPendingServerOpenPacketPair(t *testing.T) {
	pair, err := newPendingServerPacketQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pair.close(); err != nil {
			t.Error("original fixture endpoints did not close")
		}
	}()
	for _, sequence := range []uint32{1, 2} {
		frame := pendingPacketFixtureFrameQEMU(sequence)
		if err := unix.Sendmsg(int(pair.sender.Fd()), frame, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
			t.Fatal(err)
		}
		got, err := pair.next(context.Background())
		if err != nil || got.metadata.workerPID != uint32(os.Getpid()) ||
			got.credentials.Pid != int32(os.Getpid()) || got.credentials.Uid != uint32(os.Geteuid()) ||
			got.credentials.Gid != uint32(os.Getegid()) || got.metadata.shareFileID != 7777 {
			t.Fatal("real private packet lost payload/kernel credential domains")
		}
	}
}

func TestPendingServerOpenPacketRefusesAndRetains(t *testing.T) {
	for _, name := range []string{"empty", "short", "long", "concat", "wrong-sequence", "claimed-pid", "wrong-version", "rights", "no-passcred"} {
		t.Run(name, func(t *testing.T) {
			pair, err := newPendingServerPacketQEMU(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := pair.close(); err != nil {
					t.Error("owned fixture endpoints not closed")
				}
			}()
			frame := pendingPacketFixtureFrameQEMU(1)
			var control []byte
			switch name {
			case "empty":
				frame = nil
			case "short":
				frame = frame[:87]
			case "long":
				frame = append(frame, 0)
			case "concat":
				frame = append(frame, frame...)
			case "wrong-sequence":
				binary.LittleEndian.PutUint32(frame[12:], 2)
			case "claimed-pid":
				binary.LittleEndian.PutUint32(frame[76:], uint32(os.Getpid()+1))
			case "wrong-version":
				frame[8] = 2
			case "rights":
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				defer writer.Close()
				control = unix.UnixRights(int(reader.Fd()))
			case "no-passcred":
				if err := unix.SetsockoptInt(int(pair.receiver.Fd()), unix.SOL_SOCKET, unix.SO_PASSCRED, 0); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Sendmsg(int(pair.sender.Fd()), frame, control, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
				t.Fatal(err)
			}
			got, err := pair.next(context.Background())
			if got != (pendingServerPacketObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
				t.Fatal("bad private packet published partial metadata or failed open")
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(before) != len(after) {
				t.Fatal("rejected ancillary data leaked descriptors")
			}
			if _, err := pair.receiver.Stat(); err != nil {
				t.Fatal("refusal released original receiver")
			}
			if _, err := pair.sender.Stat(); err != nil {
				t.Fatal("refusal released original sender")
			}
			if err := unix.Sendmsg(int(pair.sender.Fd()), pendingPacketFixtureFrameQEMU(1), nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
				t.Fatal(err)
			}
			if got, err := pair.next(context.Background()); got != (pendingServerPacketObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
				t.Fatal("fresh packet cleared reviewed transport")
			}
		})
	}
}

func TestPendingServerOpenPacketRejectsQueuedExtra(t *testing.T) {
	for _, name := range []string{"data", "empty", "rights"} {
		t.Run(name, func(t *testing.T) {
			pair, err := newPendingServerPacketQEMU(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := pair.close(); err != nil {
					t.Error("fixture endpoints not closed")
				}
			}()
			for _, sequence := range []uint32{1, 2} {
				if err := unix.Sendmsg(int(pair.sender.Fd()), pendingPacketFixtureFrameQEMU(sequence), nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
					t.Fatal(err)
				}
			}
			extra := []byte{1}
			var control []byte
			if name == "empty" {
				extra = nil
			}
			if name == "rights" {
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				defer writer.Close()
				control = unix.UnixRights(int(reader.Fd()))
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Sendmsg(int(pair.sender.Fd()), extra, control, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
				t.Fatal(err)
			}
			if _, err := pair.next(context.Background()); err != nil {
				t.Fatal("first original record refused")
			}
			got, err := pair.next(context.Background())
			if got != (pendingServerPacketObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
				t.Fatal("queued third packet published a completed pair")
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(after) != len(before) {
				t.Fatal("queue refusal imported or leaked a descriptor")
			}
			if _, err := pair.originalReceiver.Stat(); err != nil {
				t.Fatal("refusal released original receiver")
			}
		})
	}
}

func TestPendingServerOpenPacketRecheck(t *testing.T) {
	pair, err := newPendingServerPacketQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pair.close(); err != nil {
			t.Error("fixture endpoints not closed")
		}
	}()
	for _, sequence := range []uint32{1, 2} {
		if err := unix.Sendmsg(int(pair.sender.Fd()), pendingPacketFixtureFrameQEMU(sequence), nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
			t.Fatal(err)
		}
		if _, err := pair.next(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err := pair.recheck(context.Background()); err != nil {
		t.Fatal("completed unchanged transport refused")
	}
	if err := unix.Sendmsg(int(pair.sender.Fd()), pendingPacketFixtureFrameQEMU(2), nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
		t.Fatal(err)
	}
	if err := pair.recheck(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("late packet did not preserve review")
	}
	if err := pair.recheck(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("review cleared on a later check")
	}
}

func TestPendingServerOpenPacketCancellationAndExclusion(t *testing.T) {
	pair, err := newPendingServerPacketQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pair.close(); err != nil {
			t.Error("fixture endpoints not closed")
		}
	}()
	copyPair := *pair
	if got, err := copyPair.next(context.Background()); got != (pendingServerPacketObservationQEMU{}) || err != ErrInvalid {
		t.Fatal("copied owner admitted")
	}
	if err := copyPair.close(); err != ErrInvalid {
		t.Fatal("copied owner released original endpoints")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := pair.next(ctx); got != (pendingServerPacketObservationQEMU{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-cancelled admission changed contract")
	}
	if pair.review {
		t.Fatal("pre-cancelled operation changed original state")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		got, err := pair.next(ctx)
		if got != (pendingServerPacketObservationQEMU{}) {
			err = ErrMismatch
		}
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for len(pair.gate) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(pair.gate) == 0 {
		cancel()
		<-done
		t.Fatal("reader did not enter")
	}
	if got, err := pair.next(context.Background()); got != (pendingServerPacketObservationQEMU{}) || !errors.Is(err, processowner.ErrBusy) {
		t.Error("concurrent admission did not refuse busy")
	}
	if err := pair.close(); !errors.Is(err, processowner.ErrBusy) {
		t.Error("busy close released active endpoints")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || !errors.Is(err, ErrReviewRequired) {
		t.Fatal("in-flight cancellation did not preserve review")
	}
	if _, err := pair.originalReceiver.Stat(); err != nil {
		t.Fatal("cancellation released receiver")
	}
	if _, err := pair.originalSender.Stat(); err != nil {
		t.Fatal("cancellation released sender")
	}
}

func TestPendingServerOpenPacketOriginalEndpoints(t *testing.T) {
	for _, name := range []string{"alias", "foreign", "passcred", "passsec", "pidfd", "cloexec", "nonblock", "changed-second"} {
		t.Run(name, func(t *testing.T) {
			pair, err := newPendingServerPacketQEMU(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				pair.receiver = pair.originalReceiver
				if err := pair.close(); err != nil {
					t.Error("owned fixture endpoints not closed")
				}
			}()
			frame := pendingPacketFixtureFrameQEMU(1)
			if name == "changed-second" {
				if err := unix.Sendmsg(int(pair.sender.Fd()), frame, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
					t.Fatal(err)
				}
				if _, err := pair.next(context.Background()); err != nil {
					t.Fatal(err)
				}
				frame = pendingPacketFixtureFrameQEMU(2)
				binary.LittleEndian.PutUint64(frame[56:], 4294967400)
			} else if name == "alias" || name == "foreign" {
				var replacement *os.File
				if name == "alias" {
					fd, err := unix.FcntlInt(pair.receiver.Fd(), unix.F_DUPFD_CLOEXEC, 0)
					if err != nil {
						t.Fatal(err)
					}
					replacement = os.NewFile(uintptr(fd), "fixture-receiver-alias")
				} else {
					other, err := newPendingServerPacketQEMU(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					defer other.close()
					replacement = other.receiver
				}
				if name == "alias" {
					defer replacement.Close()
				}
				pair.receiver = replacement
				if err := pair.close(); !errors.Is(err, ErrReviewRequired) {
					t.Fatal("foreign endpoint accepted for closure")
				}
				if _, err := replacement.Stat(); err != nil {
					t.Fatal("refusal closed foreign endpoint")
				}
			} else {
				fd := int(pair.receiver.Fd())
				switch name {
				case "passcred":
					err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 0)
				case "passsec":
					err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSSEC, 1)
					if errors.Is(err, unix.EOPNOTSUPP) {
						if !pair.left.passsecUnavailable {
							t.Fatal("unavailable security option lost its retained classification")
						}
						if err := unix.Sendmsg(int(pair.sender.Fd()), frame, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
							t.Fatal(err)
						}
						if _, err := pair.next(context.Background()); err != nil {
							t.Fatal("known absent security channel refused a valid credential record")
						}
						t.Log("kernel security channel is unavailable and cannot be enabled; no enabled-option refusal is claimed")
						return
					}
				case "pidfd":
					err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSPIDFD, 1)
				case "cloexec":
					_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0)
				case "nonblock":
					_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, unix.O_NONBLOCK)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := unix.Sendmsg(int(pair.sender.Fd()), frame, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
				t.Fatal(err)
			}
			if got, err := pair.next(context.Background()); got != (pendingServerPacketObservationQEMU{}) || !errors.Is(err, ErrReviewRequired) {
				t.Fatal("changed original transport published metadata")
			}
			if _, err := pair.originalReceiver.Stat(); err != nil {
				t.Fatal("review released original receiver")
			}
			if _, err := pair.originalSender.Stat(); err != nil {
				t.Fatal("review released original sender")
			}
		})
	}
}

func TestPendingServerOpenPacketCProducerQEMU(t *testing.T) {
	if os.Getenv("PHANTOWD_SERVER_OPEN_WIRE_FIXTURE") != "1" {
		t.Skip("explicit disposable ARM guest only; no active worker is inferred")
	}
	pair, err := newPendingServerPacketQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pair.close(); err != nil {
			t.Error("original fixture channel did not close")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/phantowd-server-open-source-test", "--packets")
	cmd.ExtraFiles = []*os.File{pair.sender}
	var output, diagnostic pendingServerFrameTestCaptureQEMU
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	// This finite synthetic producer must settle before fixture endpoints close.
	// Waiting first deliberately does NOT claim live-worker/lifetime admission.
	if err := cmd.Run(); err != nil || output.used != 0 || diagnostic.used != 0 {
		t.Fatal("fixed packet producer refused or emitted diagnostics")
	}
	if pair.left.peer.Pid != int32(os.Getpid()) || pair.left.peer.Pid == int32(cmd.Process.Pid) {
		t.Fatal("socket creator confused with actual packet sender")
	}
	for range 2 {
		got, err := pair.next(context.Background())
		if err != nil || got.credentials.Pid != int32(cmd.Process.Pid) ||
			got.credentials.Uid != uint32(os.Geteuid()) || got.credentials.Gid != uint32(os.Getegid()) ||
			got.metadata.workerPID != uint32(cmd.Process.Pid) || got.metadata.session != 42 ||
			got.metadata.tree != 21 || got.metadata.persistent != 123 || got.metadata.volatile != 456 ||
			got.metadata.shareFileID != 7777 || got.metadata.workerUnique != 999 {
			t.Fatal("actual C packet lost credentials or metadata domains")
		}
	}
	if err := pair.recheck(context.Background()); err != nil {
		t.Fatal("settled synthetic packet pair did not recheck")
	}
	fmt.Println("PHANTOWD_SERVER_OPEN_PACKET_READY frames=2 kernel_credentials=true original_pair=true synthetic_open=true active_worker=false proof=false scope=qemu-only")
}
