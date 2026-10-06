//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestServiceRuntimeStopsConsumersBeforeClosingHandoffOnSourceLoss(t *testing.T) {
	var events []string
	handoff := &serviceRuntimeHandoffFake{
		events: &events,
		verify: []error{nil, nil, ErrHandoffReview},
		bindings: []ServicePathBinding{{
			ShareID: "media", VolumeID: "volume-a", RelativePath: "media", SourceMountID: 21, DeviceMajor: 8,
			Path: "/run/phantowd/service-handoff/test/media",
		}},
		closeErr: ErrHandoffReview,
	}
	processes := &serviceRuntimeProcessSetFake{events: &events}
	runtime, err := newServiceRuntime(handoff, processes)
	if err != nil {
		t.Fatal("construct internal service runtime:", err)
	}

	started, err := runtime.Start(context.Background())
	if err != nil || started != ServiceRuntimeReady {
		t.Fatalf("consumers did not start after verified bindings: state=%q err=%v", started, err)
	}
	state, err := runtime.Observe(context.Background())
	if !errors.Is(err, ErrServiceRuntimeReview) || state != ServiceRuntimeReview {
		t.Fatalf("source loss did not quarantine runtime: state=%q err=%v", state, err)
	}
	if want := []string{"mount", "bindings", "verify", "set-start", "verify", "verify", "set-stop", "handoff-close"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("handoff closed before consumers stopped or out of order: got %v, want %v", events, want)
	}
	if processes.stopCalls != 1 || handoff.closeCalls != 1 {
		t.Fatalf("source-loss quarantine was retried: process stops=%d handoff closes=%d", processes.stopCalls, handoff.closeCalls)
	}
	if _, err := runtime.Stop(context.Background()); !errors.Is(err, ErrServiceRuntimeReview) {
		t.Fatalf("review state was cleared or retried by Stop: %v", err)
	}
	if processes.stopCalls != 1 || handoff.closeCalls != 1 {
		t.Fatalf("reviewed cleanup was retried: process stops=%d handoff closes=%d", processes.stopCalls, handoff.closeCalls)
	}
}

func TestServiceRuntimeRetainsHandoffWhenConsumerStopIsUncertain(t *testing.T) {
	var events []string
	handoff := &serviceRuntimeHandoffFake{
		events: &events,
		verify: []error{nil, nil, ErrHandoffReview},
		bindings: []ServicePathBinding{{
			ShareID: "media", VolumeID: "volume-a", RelativePath: "media", SourceMountID: 21, DeviceMajor: 8,
			Path: "/run/phantowd/service-handoff/test/media",
		}},
	}
	processes := &serviceRuntimeProcessSetFake{
		events:    &events,
		stopErr:   processowner.ErrReviewRequired,
		stopState: processowner.StateReviewRequired,
	}
	runtime, err := newServiceRuntime(handoff, processes)
	if err != nil {
		t.Fatal("construct internal service runtime:", err)
	}
	if state, err := runtime.Start(context.Background()); err != nil || state != ServiceRuntimeReady {
		t.Fatalf("runtime did not start: state=%q err=%v", state, err)
	}
	state, err := runtime.Observe(context.Background())
	if !errors.Is(err, ErrServiceRuntimeReview) || state != ServiceRuntimeReview {
		t.Fatalf("uncertain consumer stop did not require review: state=%q err=%v", state, err)
	}
	if handoff.closeCalls != 0 {
		t.Fatalf("handoff was closed while a consumer may still be using it: closes=%d", handoff.closeCalls)
	}
	if _, err := runtime.Stop(context.Background()); !errors.Is(err, ErrServiceRuntimeReview) {
		t.Fatalf("review state was cleared or stop was retried: %v", err)
	}
	if processes.stopCalls != 1 || handoff.closeCalls != 0 {
		t.Fatalf("uncertain cleanup was retried or lease released: process stops=%d handoff closes=%d", processes.stopCalls, handoff.closeCalls)
	}
	if want := []string{"mount", "bindings", "verify", "set-start", "verify", "verify", "set-stop"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("uncertain stop did not retain handoff in order: got %v, want %v", events, want)
	}
}

func TestValidServiceBindingsAllowsDistinctSharesFromOneVolume(t *testing.T) {
	bindings := []ServicePathBinding{
		{ShareID: "books", VolumeID: "volume-a", RelativePath: "media/books", SourceMountID: 21,
			DeviceMajor: 8, Path: "/run/phantowd/service-handoff/test/books"},
		{ShareID: "comics", VolumeID: "volume-a", RelativePath: "media/comics", SourceMountID: 21,
			DeviceMajor: 8, Path: "/run/phantowd/service-handoff/test/comics"},
	}
	if !validServiceBindings(bindings) {
		t.Fatal("distinct share roots from one fixed volume were rejected")
	}
	bindings[1].ShareID = bindings[0].ShareID
	if validServiceBindings(bindings) {
		t.Fatal("duplicate share IDs were accepted")
	}
}

type serviceRuntimeHandoffFake struct {
	events     *[]string
	verify     []error
	bindings   []ServicePathBinding
	closeErr   error
	closeCalls int
}

func (h *serviceRuntimeHandoffFake) Mount(context.Context) (ServicePaths, error) {
	*h.events = append(*h.events, "mount")
	return ServicePaths{}, nil
}

func (h *serviceRuntimeHandoffFake) Bindings() ([]ServicePathBinding, error) {
	*h.events = append(*h.events, "bindings")
	return h.bindings, nil
}

func (h *serviceRuntimeHandoffFake) Verify() error {
	*h.events = append(*h.events, "verify")
	if len(h.verify) == 0 {
		return nil
	}
	err := h.verify[0]
	h.verify = h.verify[1:]
	return err
}

func (h *serviceRuntimeHandoffFake) Close() error {
	*h.events = append(*h.events, "handoff-close")
	h.closeCalls++
	return h.closeErr
}

type serviceRuntimeProcessSetFake struct {
	events    *[]string
	stopCalls int
	stopErr   error
	stopState processowner.State
}

func (p *serviceRuntimeProcessSetFake) Start(context.Context) (processowner.SetSnapshot, error) {
	*p.events = append(*p.events, "set-start")
	return processowner.SetSnapshot{State: processowner.StateReady, Generation: 1}, nil
}

func (p *serviceRuntimeProcessSetFake) Observe(context.Context) (processowner.SetSnapshot, error) {
	*p.events = append(*p.events, "set-observe")
	return processowner.SetSnapshot{State: processowner.StateReady, Generation: 1}, nil
}

func (p *serviceRuntimeProcessSetFake) Stop(context.Context) (processowner.SetSnapshot, error) {
	*p.events = append(*p.events, "set-stop")
	p.stopCalls++
	state := p.stopState
	if state == "" {
		state = processowner.StateStopped
	}
	return processowner.SetSnapshot{State: state, Generation: 1}, p.stopErr
}
