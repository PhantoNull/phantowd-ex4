//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

func TestPendingWorkerRequiresOriginalParentGroupAndStart(t *testing.T) {
	good := "1002 (smbd (worker)) S 1000 1000 " + strings.Repeat("0 ", 16) + "123456 0 0\n"
	if start, err := parsePendingWorkerStatQEMU([]byte(good), "1002", 1000); err != nil || start != "123456" {
		t.Fatal("original worker stat refused:", start, err)
	}
	for _, bad := range []string{"", "1002 (smbd) S 1000 1000", strings.Replace(good, " S ", " Z ", 1),
		strings.Replace(good, "1000 1000", "999 1000", 1), strings.Replace(good, "1000 1000", "1000 999", 1),
		strings.Replace(good, "1002 (", "1003 (", 1), strings.Replace(good, "123456", "0123456", 1),
		strings.Replace(good, "123456", "0", 1), good + strings.Repeat("0", 4096)} {
		if start, err := parsePendingWorkerStatQEMU([]byte(bad), "1002", 1000); err == nil || start != "" {
			t.Fatal("incomplete/replaced/dead worker accepted")
		}
	}
	if _, err := parsePendingWorkerStatQEMU([]byte(good), "01002", 1000); err == nil {
		t.Fatal("noncanonical PID accepted")
	}
}

func TestPendingServerObservationRejectsAbsentCanceledBusyAndUnstarted(t *testing.T) {
	var absent *NativeSambaRuntimeQEMU
	if w, err := absent.observePendingServerOpenQEMU(context.Background(), nil, unix.Stat_t{}); err == nil || w != nil {
		t.Fatal("absent runtime accepted")
	}
	r := &NativeSambaRuntimeQEMU{owner: &Owner{}, gate: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.observePendingServerOpenQEMU(ctx, nil, unix.Stat_t{}); !errors.Is(err, context.Canceled) || r.owner.review {
		t.Fatal("pre-cancellation consumed admission")
	}
	r.gate <- struct{}{}
	_, err := r.observePendingServerOpenQEMU(context.Background(), nil, unix.Stat_t{})
	<-r.gate
	if !errors.Is(err, processowner.ErrBusy) || r.owner.review {
		t.Fatal("busy observer executed or reviewed runtime")
	}
	if _, err := r.observePendingServerOpenQEMU(context.Background(), nil, unix.Stat_t{}); !errors.Is(err, ErrReviewRequired) || !r.owner.review {
		t.Fatal("unstarted runtime admitted or refusal cleared review")
	}
	var witness *pendingServerOpenQEMU
	if witness.recheckQEMU(context.Background(), nil, unix.Stat_t{}) == nil {
		t.Fatal("missing original witness accepted")
	}
}
