//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smartdevice"
	"golang.org/x/sys/unix"
)

// The existing root MD fixture already owns these two disposable devices.
// No broker rule, normal startup or generic non-root launcher is modified.
func exerciseQEMUSMARTGenerationWitnesses() error {
	if os.Geteuid() != 0 {
		return errors.New("SMART witness fixture requires the existing root MD stage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	before, err := collectSMARTDiskCensus(ctx, os.DirFS("/sys"))
	if err != nil {
		return errors.New("SMART witness census incomplete")
	}
	for _, name := range []string{"sde", "sdf"} {
		found := false
		for _, disk := range before.disks {
			if disk.name != name {
				continue
			}
			found = true
			file, err := os.OpenFile("/dev/"+name, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
			if err != nil {
				return errors.New("SMART witness fixture open failed")
			}
			wrong := disk.generation
			wrong.DiskSequence ^= 1
			invalid, refusal := smartdevice.Retain(ctx, file, wrong)
			if invalid != nil || !errors.Is(refusal, smartdevice.ErrUnsafe) {
				if invalid != nil {
					invalid.Close(context.Background())
				}
				file.Close()
				return errors.New("SMART witness accepted stale generation")
			}
			w, err := smartdevice.Retain(ctx, file, disk.generation)
			closeErr := file.Close()
			if err != nil {
				return errors.New("SMART witness did not retain actual MD member")
			}
			// Cleanup must not inherit an expired test budget. No child uses this
			// witness, so its own duplicate can always be released on return.
			defer w.Close(context.Background())
			if closeErr != nil {
				return errors.New("SMART witness caller close was uncertain")
			}
			if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
				return errors.New("SMART witness caller descriptor remains open")
			}
			if err := w.Check(ctx); err != nil {
				w.Close(context.Background())
				return errors.New("SMART witness lost caller-independent pin")
			}
			if err := smartdevice.VerifyQEMUStickyReview(ctx, w); err != nil {
				w.Close(context.Background())
				return errors.New("SMART witness review restored incorrectly")
			}
			if err := w.Close(ctx); err != nil || !errors.Is(w.Check(ctx), smartdevice.ErrClosed) {
				return errors.New("SMART witness explicit release failed")
			}
		}
		if !found {
			return errors.New("SMART witness active member absent from census")
		}
	}
	after, err := collectSMARTDiskCensus(ctx, os.DirFS("/sys"))
	if err != nil || !sameSMARTDiskCensus(before, after) {
		return errors.New("SMART witness complete census changed")
	}
	return nil
}
