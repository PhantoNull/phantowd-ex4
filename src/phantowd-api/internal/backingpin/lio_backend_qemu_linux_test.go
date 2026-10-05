//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestLIOBackendWriteOnlyAttributeOpenMode(t *testing.T) {
	for _, name := range []string{"control", "disable_if_idle"} {
		flags, err := lioBackendWriteFlags(name, false)
		if err != nil || flags != unix.O_WRONLY {
			t.Fatal("write-only configfs attribute requests read support")
		}
		if _, err := lioBackendWriteFlags(name, true); !errors.Is(err, ErrInvalid) {
			t.Fatal("write-only readback requested")
		}
	}
	if flags, err := lioBackendWriteFlags("enable", true); err != nil || flags != unix.O_RDWR {
		t.Fatal("readback mode lost")
	}
	if _, err := lioBackendWriteFlags("enable", false); !errors.Is(err, ErrInvalid) {
		t.Fatal("readback disabled on ordinary state")
	}
}

func TestLIOTargetCapturedDefinitionAndRefusals(t *testing.T) {
	p := fixtureTargetPolicy(1, "data/first", "data/second")
	p.ISCSI.Targets[0].LUNs[0], p.ISCSI.Targets[0].LUNs[1] = p.ISCSI.Targets[0].LUNs[1], p.ISCSI.Targets[0].LUNs[0]
	target, definitions, err := lioTargetDefinition(p, "fixture-target")
	if err != nil || len(target.LUNs) != 2 || target.LUNs[0].Number != 0 || target.LUNs[1].Number != 7 {
		t.Fatal("canonical captured definition", err)
	}
	p.ISCSI.Targets[0].LUNs[0].Number = 9
	p.ISCSI.Targets[0].Initiators[0].Grants[0].Access = "ro"
	p.ISCSI.Backings[0].RelativePath = "other"
	if target.LUNs[1].Number != 7 || target.Initiators[0].Grants[0].Access != "rw" || definitions["fixture-backing"].RelativePath != "data/first" {
		t.Fatal("caller mutated captured definition")
	}
	if _, _, err := lioTargetDefinition(p, "foreign"); !errors.Is(err, ErrInvalid) {
		t.Fatal("foreign target admitted")
	}
	p = fixtureTargetPolicy(1, "data/first", "data/second")
	p.ISCSI.Targets[0].Initiators[0].Authentication.Mode = "mutual-chap"
	p.ISCSI.Targets[0].Initiators[0].Authentication.TargetUser = "other-user"
	p.ISCSI.Targets[0].Initiators[0].Authentication.TargetSecretRef = "other-secret"
	if p.Validate() != nil {
		t.Fatal("invalid test policy")
	}
	if _, _, err := lioTargetDefinition(p, "fixture-target"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unsupported enforcement inferred")
	}
}

func TestLIOTargetRosterMatchesEveryMember(t *testing.T) {
	p := fixtureTargetPolicy(1, "data/first", "data/second")
	target, defs, err := lioTargetDefinition(p, "fixture-target")
	if err != nil {
		t.Fatal(err)
	}
	b := &lioBackend{target: target, definitions: defs}
	f, err := os.CreateTemp(t.TempDir(), "synthetic-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	members := []targetBacking{{lunID: "fixture-lun", number: 0, backingID: "fixture-backing", capacity: 4096, blockSize: 512, access: "rw", file: f},
		{lunID: "fixture-second-lun", number: 7, backingID: "fixture-second", capacity: 8192, blockSize: 4096, access: "rw", file: f}}
	// Lower pure matching seam only: real descriptor alias checks remain in Owner.
	if !b.matchMembers(members) {
		t.Fatal("exact roster refused")
	}
	for _, kind := range []string{"missing", "order", "id", "number", "backing", "capacity", "block", "access", "nil"} {
		t.Run(kind, func(t *testing.T) {
			bad := append([]targetBacking(nil), members...)
			switch kind {
			case "missing":
				bad = bad[:1]
			case "order":
				bad[0], bad[1] = bad[1], bad[0]
			case "id":
				bad[1].lunID = "foreign"
			case "number":
				bad[1].number = 1
			case "backing":
				bad[1].backingID = "fixture-backing"
			case "capacity":
				bad[1].capacity = 4096
			case "block":
				bad[1].blockSize = 512
			case "access":
				bad[1].access = "ro"
			case "nil":
				bad[1].file = nil
			}
			if b.matchMembers(bad) {
				t.Fatal("changed/partial roster admitted")
			}
		})
	}
}

func TestLIOBackendOrdinaryFilesystemAndPartialStateRefused(t *testing.T) {
	directory := t.TempDir()
	f, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if b, err := newLIOBackend(fixtureTargetPolicy(1, "data/a", "data/b"), "fixture-target", f, f); b != nil || err == nil {
		t.Fatal("ordinary filesystem admitted")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("constructor mutated rejected root")
	}
	if _, err := f.Stat(); err != nil {
		t.Fatal("constructor consumed borrowed root")
	}
	if _, err := lioBackendLeaf(f, "auth/password", 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("unfixed attribute accepted")
	}
	ctx := context.Background()
	for _, b := range []*lioBackend{nil, {}, {started: true}, {started: true, stopAttempted: true}} {
		if live, err := b.running(ctx); live || !errors.Is(err, ErrReview) {
			t.Fatal("partial state/panic")
		}
		if err := b.startTarget(ctx, nil); err == nil {
			t.Fatal("unprepared start")
		}
	}
	if err := (&lioBackend{}).checkExpected(nil); !errors.Is(err, ErrReview) {
		t.Fatal("nil context")
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := (&lioBackend{}).checkExpected(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("cancelled observation")
	}
	if _, err := json.Marshal(&lioBackend{}); err == nil {
		t.Fatal("serializable privileged backend")
	}
}
