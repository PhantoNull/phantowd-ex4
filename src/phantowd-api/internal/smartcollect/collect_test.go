// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartcollect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smartreport"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

type fakeBackend struct {
	target                                   Target
	observeCalls, captureCalls, settledCalls int
	observe                                  func(context.Context) (Source, error)
	capture                                  func(context.Context) (Result, error)
	settled                                  func(context.Context) (bool, error)
}

func targetFixture() Target {
	return Target{Generation: volumeprobe.BlockDeviceGeneration{Major: 8, Minor: 0, DiskSequence: 42}, CensusToken: [32]byte{9}}
}

func reportFixture(exit int, passed bool) []byte {
	return fmt.Appendf(nil, `{"json_format_version":[1,0],"smartctl":{"version":[7,5],"pre_release":false,"exit_status":%d},"device":{"protocol":"ATA"},"smart_support":{"available":true,"enabled":true},"smart_status":{"passed":%t},"serial_number":"private-fixture-only"}`, exit, passed)
}

func (b *fakeBackend) Observe(ctx context.Context) (Source, error) {
	b.observeCalls++
	if b.observe != nil {
		return b.observe(ctx)
	}
	return Source{State: SourceAdmitted, Target: b.target}, nil
}
func (b *fakeBackend) Capture(ctx context.Context) (Result, error) {
	b.captureCalls++
	if b.capture != nil {
		return b.capture(ctx)
	}
	return Result{Termination: Exited, Stdout: reportFixture(0, true)}, nil
}
func (b *fakeBackend) Settled(ctx context.Context) (bool, error) {
	b.settledCalls++
	if b.settled != nil {
		return b.settled(ctx)
	}
	return true, nil
}

func collectorFixture(t *testing.T, backend *fakeBackend) *Collector {
	t.Helper()
	c, err := New(backend, backend.target, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func assertNoSample(t *testing.T, sample Sample, err, expected error) {
	t.Helper()
	if sample != (Sample{}) || !errors.Is(err, expected) {
		t.Fatalf("unexpected redacted result: valid=%t err=%v", sample.Valid(), err)
	}
}

func TestConstructorRefusesInvalidInputsWithoutEffects(t *testing.T) {
	b := &fakeBackend{target: targetFixture()}
	badDevice, badSequence, badToken := b.target, b.target, b.target
	badDevice.Generation.Major = 0
	badDevice.Generation.Minor = 0
	badSequence.Generation.DiskSequence = 0
	badToken.CensusToken = [32]byte{}
	var typedNil *fakeBackend
	for _, tc := range []struct {
		backend Backend
		target  Target
		budget  time.Duration
	}{
		{nil, b.target, time.Second}, {typedNil, b.target, time.Second},
		{b, badDevice, time.Second}, {b, badSequence, time.Second}, {b, badToken, time.Second},
		{b, b.target, 0}, {b, b.target, time.Second - 1}, {b, b.target, 30*time.Second + 1},
	} {
		if c, err := New(tc.backend, tc.target, tc.budget); c != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid constructor accepted")
		}
	}
	if b.observeCalls+b.captureCalls+b.settledCalls != 0 {
		t.Fatal("constructor performed backend work")
	}
}

func TestFixedSourceAndSampleSemantics(t *testing.T) {
	for _, tc := range []struct {
		exit       int
		passed     bool
		state      smartreport.State
		assessment smartreport.Assessment
	}{
		{0, true, smartreport.Complete, smartreport.ReportedPass},
		{64, true, smartreport.Complete, smartreport.ReportedPass},
		{8, false, smartreport.Complete, smartreport.ReportedFail},
		{12, false, smartreport.Partial, smartreport.ReportedFail},
		{4, true, smartreport.Partial, smartreport.ReportedPass},
	} {
		b := &fakeBackend{target: targetFixture()}
		data := reportFixture(tc.exit, tc.passed)
		b.capture = func(context.Context) (Result, error) {
			return Result{Termination: Exited, ExitCode: tc.exit, Stdout: data}, nil
		}
		input := b.target
		c, err := New(b, input, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		input.Generation.DiskSequence++ // Caller input is not retained by reference.
		sample, err := c.Collect(context.Background())
		if err != nil || !sample.Valid() || sample.Generation() != b.target.Generation ||
			sample.Report().State() != tc.state || sample.Report().Assessment() != tc.assessment ||
			sample.Report().Flags().ErrorLogRecords != (tc.exit&64 != 0) {
			t.Fatal("source/collection/assessment distinction lost", err)
		}
		if b.observeCalls != 2 || b.captureCalls != 1 || b.settledCalls != 2 {
			t.Fatal("not one capture between fresh source and ownership checks")
		}
		clear(data)
		if sample.Report().Assessment() != tc.assessment {
			t.Fatal("sample retained raw report memory")
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		got, err := c.Collect(context.Background())
		assertNoSample(t, got, err, ErrClosed)
		if b.captureCalls != 1 || c.backend != nil {
			t.Fatal("close captured again or kept released reference")
		}
	}
}

func TestUnadmittedSourceQuarantinesBeforeCapture(t *testing.T) {
	for _, state := range []SourceState{SourceUnknown, SourceAbsent, SourceAmbiguous, SourceIncomplete, SourceUnsupported, 255} {
		b := &fakeBackend{target: targetFixture()}
		b.observe = func(context.Context) (Source, error) { return Source{State: state, Target: b.target}, nil }
		c := collectorFixture(t, b)
		got, err := c.Collect(context.Background())
		assertNoSample(t, got, err, ErrSource)
		b.observe = nil
		got, err = c.Collect(context.Background())
		assertNoSample(t, got, err, ErrReview)
		if b.captureCalls != 0 {
			t.Fatal("source restoration resumed capture")
		}
	}
}

func TestEveryBindingChangeBeforeOrAfterCaptureRefuses(t *testing.T) {
	for _, after := range []bool{false, true} {
		for _, change := range []func(*Target){
			func(v *Target) { v.Generation.Major++ }, func(v *Target) { v.Generation.Minor++ },
			func(v *Target) { v.Generation.DiskSequence++ }, func(v *Target) { v.CensusToken[0]++ },
		} {
			b := &fakeBackend{target: targetFixture()}
			b.observe = func(context.Context) (Source, error) {
				observed := b.target
				if !after || b.observeCalls == 2 {
					change(&observed)
				}
				return Source{State: SourceAdmitted, Target: observed}, nil
			}
			c := collectorFixture(t, b)
			got, err := c.Collect(context.Background())
			assertNoSample(t, got, err, ErrSource)
			b.observe = nil
			got, err = c.Collect(context.Background())
			assertNoSample(t, got, err, ErrReview)
			wantCaptures := 0
			if after {
				wantCaptures = 1
			}
			if b.captureCalls != wantCaptures {
				t.Fatal("incorrect capture count or retry")
			}
		}
	}
}

func TestProcessDispositionAndOutputRefusals(t *testing.T) {
	valid := Result{Termination: Exited, Stdout: reportFixture(0, true)}
	for _, change := range []func(*Result){
		func(r *Result) { r.Termination = TerminationUnknown }, func(r *Result) { r.Termination = Signaled },
		func(r *Result) { r.Termination = TimedOut }, func(r *Result) { r.Termination = Canceled },
		func(r *Result) { r.Termination = 255 }, func(r *Result) { r.ExitCode = -1 },
		func(r *Result) { r.ExitCode = 256 }, func(r *Result) { r.Stdout = make([]byte, smartreport.MaxBytes+1) },
		func(r *Result) { r.Stderr = make([]byte, MaxStderr+1) },
	} {
		b := &fakeBackend{target: targetFixture()}
		b.capture = func(context.Context) (Result, error) { r := valid; change(&r); return r, nil }
		c := collectorFixture(t, b)
		got, err := c.Collect(context.Background())
		assertNoSample(t, got, err, ErrCollection)
		if b.captureCalls != 1 || b.observeCalls != 1 {
			t.Fatal("refusal retried or published source")
		}
	}
}

func TestBackendErrorsAndMalformedReportsAreRedacted(t *testing.T) {
	for _, phase := range []string{"observe", "capture", "settled", "report"} {
		b := &fakeBackend{target: targetFixture()}
		private := errors.New("private-fixture-only /untrusted/path")
		want := ErrCollection
		switch phase {
		case "observe":
			b.observe = func(context.Context) (Source, error) { return Source{}, private }
			want = ErrSource
		case "capture":
			b.capture = func(context.Context) (Result, error) { return Result{}, private }
		case "settled":
			b.settled = func(context.Context) (bool, error) { return false, private }
			want = ErrUnsettled
		case "report":
			b.capture = func(context.Context) (Result, error) {
				return Result{Termination: Exited, Stdout: []byte("private-fixture-only")}, nil
			}
			want = ErrReport
		}
		c := collectorFixture(t, b)
		got, err := c.Collect(context.Background())
		assertNoSample(t, got, err, want)
		if strings.Contains(err.Error(), "private-fixture") {
			t.Fatal("backend/report detail escaped")
		}
	}
}

func TestUnsettledCaptureRetainsReferenceUntilExplicitVerification(t *testing.T) {
	b := &fakeBackend{target: targetFixture()}
	b.settled = func(context.Context) (bool, error) { return b.settledCalls == 1, nil }
	c := collectorFixture(t, b)
	got, err := c.Collect(context.Background())
	assertNoSample(t, got, err, ErrUnsettled)
	if err := c.Close(context.Background()); !errors.Is(err, ErrUnsettled) || c.backend == nil {
		t.Fatal("uncertain close released backend")
	}
	got, err = c.Collect(context.Background())
	assertNoSample(t, got, err, ErrReview)
	b.settled = nil
	if err := c.Close(context.Background()); err != nil || c.backend != nil || !c.review {
		t.Fatal("verified close failed or cleared review")
	}
	if b.captureCalls != 1 {
		t.Fatal("cleanup retried capture")
	}
}

func TestUnsettledBeforeCaptureNeverStartsProcess(t *testing.T) {
	b := &fakeBackend{target: targetFixture()}
	b.settled = func(context.Context) (bool, error) { return false, nil }
	c := collectorFixture(t, b)
	got, err := c.Collect(context.Background())
	assertNoSample(t, got, err, ErrUnsettled)
	if b.captureCalls != 0 || c.backend == nil {
		t.Fatal("unsettled admission started capture or lost ownership reference")
	}
	b.settled = nil
	got, err = c.Collect(context.Background())
	assertNoSample(t, got, err, ErrReview)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledCloseCannotReleaseOrResumeBackend(t *testing.T) {
	b := &fakeBackend{target: targetFixture()}
	c := collectorFixture(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	b.settled = func(context.Context) (bool, error) { cancel(); return true, nil }
	if err := c.Close(ctx); !errors.Is(err, ErrUnsettled) || c.backend == nil || c.closed {
		t.Fatal("canceled verification released the backend")
	}
	got, err := c.Collect(context.Background())
	assertNoSample(t, got, err, ErrReview)
	b.settled = nil
	if err := c.Close(context.Background()); err != nil || c.backend != nil {
		t.Fatal("explicit absence verification could not close", err)
	}
}

func TestSettledRefusalAllowsOnlyLaterExplicitCapture(t *testing.T) {
	b := &fakeBackend{target: targetFixture()}
	b.capture = func(context.Context) (Result, error) {
		return Result{Termination: Signaled, ExitCode: 143, Stdout: reportFixture(0, true)}, nil
	}
	c := collectorFixture(t, b)
	got, err := c.Collect(context.Background())
	assertNoSample(t, got, err, ErrCollection)
	if b.captureCalls != 1 {
		t.Fatal("refused command was automatically retried")
	}
	b.capture = nil
	got, err = c.Collect(context.Background())
	if err != nil || !got.Valid() || b.captureCalls != 2 {
		t.Fatal("later explicit operation failed despite verified settled ownership", err)
	}
}

func TestConcurrentCollectionAndCloseRefuseWithoutQueue(t *testing.T) {
	b := &fakeBackend{target: targetFixture()}
	entered, release := make(chan struct{}), make(chan struct{})
	b.capture = func(context.Context) (Result, error) {
		close(entered)
		<-release
		return Result{Termination: Exited, Stdout: reportFixture(0, true)}, nil
	}
	c := collectorFixture(t, b)
	done := make(chan error, 1)
	go func() { _, err := c.Collect(context.Background()); done <- err }()
	<-entered
	got, err := c.Collect(context.Background())
	assertNoSample(t, got, err, ErrBusy)
	if err := c.Close(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("close raced active capture")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if b.captureCalls != 1 {
		t.Fatal("busy call queued or captured")
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCancellationNeverPublishesAndStillVerifiesOwnership(t *testing.T) {
	for _, phase := range []string{"capture", "publication"} {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		b := &fakeBackend{target: targetFixture()}
		b.capture = func(operation context.Context) (Result, error) {
			deadline, exists := operation.Deadline()
			if !exists || time.Until(deadline) > 2*time.Second {
				t.Error("operation has no fixed deadline")
			}
			if phase == "capture" {
				cancel()
			}
			return Result{Termination: Exited, Stdout: reportFixture(0, true)}, nil
		}
		b.observe = func(context.Context) (Source, error) {
			if phase == "publication" && b.observeCalls == 2 {
				cancel()
			}
			return Source{State: SourceAdmitted, Target: b.target}, nil
		}
		b.settled = func(verification context.Context) (bool, error) {
			if b.settledCalls == 2 && verification.Err() != nil {
				t.Error("cleanup abandoned with canceled capture context")
			}
			return true, nil
		}
		c := collectorFixture(t, b)
		got, err := c.Collect(ctx)
		assertNoSample(t, got, err, context.Canceled)
		if b.captureCalls != 1 || b.settledCalls != 2 {
			t.Fatal("canceled capture not settled")
		}
	}
}

func TestPreCanceledNilAndZeroCollectorsHaveNoEffects(t *testing.T) {
	b := &fakeBackend{target: targetFixture()}
	c := collectorFixture(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := c.Collect(ctx)
	assertNoSample(t, got, err, context.Canceled)
	if err := c.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("precanceled close accepted")
	}
	for _, invalid := range []*Collector{nil, {}} {
		got, err := invalid.Collect(context.Background())
		assertNoSample(t, got, err, ErrInvalid)
	}
	got, err = c.Collect(nil)
	assertNoSample(t, got, err, ErrInvalid)
	if b.observeCalls+b.captureCalls+b.settledCalls != 0 {
		t.Fatal("invalid admission invoked backend")
	}
}

func TestEvidenceRejectsJSON(t *testing.T) {
	b := &fakeBackend{target: targetFixture()}
	c := collectorFixture(t, b)
	sample, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{b.target, Source{}, Result{}, sample, c} {
		if output, err := json.Marshal(value); output != nil || !errors.Is(err, ErrPrivate) {
			t.Fatal("private evidence serialized")
		}
	}
	for _, destination := range []any{new(Target), new(Source), new(Result), new(Sample), new(Collector)} {
		if err := json.Unmarshal([]byte(`{}`), destination); !errors.Is(err, ErrPrivate) {
			t.Fatal("evidence accepted JSON")
		}
	}
}

func TestCopiedCollectorCannotForkLifecycleAuthority(t *testing.T) {
	b := &fakeBackend{target: targetFixture()}
	c := collectorFixture(t, b)
	copied := *c
	got, err := copied.Collect(context.Background())
	assertNoSample(t, got, err, ErrInvalid)
	if err := copied.Close(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal("copied collector changed ownership")
	}
	if b.observeCalls+b.captureCalls+b.settledCalls != 0 {
		t.Fatal("copied collector invoked backend")
	}
	got, err = c.Collect(context.Background())
	if err != nil || !got.Valid() {
		t.Fatal("copy refusal invalidated original", err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err = copied.Collect(context.Background())
	assertNoSample(t, got, err, ErrInvalid)
	if b.captureCalls != 1 {
		t.Fatal("copied lifecycle resurrected capture after original close")
	}
}

func FuzzPublicationRequiresAdmittedSourceAndOrdinaryExit(f *testing.F) {
	f.Add(uint8(SourceAdmitted), uint8(SourceAdmitted), uint8(Exited), int16(0), reportFixture(0, true))
	f.Add(uint8(SourceAdmitted), uint8(SourceAbsent), uint8(Exited), int16(0), reportFixture(0, true))
	f.Add(uint8(SourceAdmitted), uint8(SourceAdmitted), uint8(Signaled), int16(0), reportFixture(0, true))
	f.Fuzz(func(t *testing.T, before, after, disposition uint8, exit int16, data []byte) {
		b := &fakeBackend{target: targetFixture()}
		b.observe = func(context.Context) (Source, error) {
			state := before
			if b.observeCalls == 2 {
				state = after
			}
			return Source{State: SourceState(state), Target: b.target}, nil
		}
		b.capture = func(context.Context) (Result, error) {
			return Result{Termination: Termination(disposition), ExitCode: int(exit), Stdout: data}, nil
		}
		c := collectorFixture(t, b)
		sample, err := c.Collect(context.Background())
		if b.captureCalls > 1 || b.observeCalls > 2 || b.settledCalls > 2 {
			t.Fatal("unbounded invocation or retry")
		}
		if err != nil {
			if sample != (Sample{}) {
				t.Fatal("refusal published partial sample")
			}
			return
		}
		if !sample.Valid() || before != uint8(SourceAdmitted) || after != uint8(SourceAdmitted) ||
			disposition != uint8(Exited) || exit < 0 || exit > 255 || len(data) > smartreport.MaxBytes {
			t.Fatal("publication without source/exit/bounds evidence")
		}
	})
}
