//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
)

func TestLIOAuthRosterValidatedWithoutPartialMaterial(t *testing.T) {
	s := &lioCredentialSink{acls: []lioAuthSelection{{name: "peer-a"}, {name: "peer-b"}}}
	peers := []iscsicredentials.Credential{{InitiatorName: "peer-b", Mode: "mutual-chap", InitiatorUser: "b", TargetUser: "out-b"},
		{InitiatorName: "peer-a", Mode: "chap", InitiatorUser: "a"}}
	got, err := s.matchPeers(peers)
	if err != nil || len(got) != 2 || got[0].InitiatorName != "peer-a" || got[1].Mode != "mutual-chap" {
		t.Fatal("exact roster", err)
	}
	for _, kind := range []string{"missing", "duplicate", "foreign", "bad-user", "null-prefix", "unknown-mode", "stale-outbound", "same-mutual-user"} {
		t.Run(kind, func(t *testing.T) {
			in := append([]iscsicredentials.Credential(nil), peers...)
			switch kind {
			case "missing":
				in = in[:1]
			case "duplicate":
				in[1].InitiatorName = in[0].InitiatorName
			case "foreign":
				in[1].InitiatorName = "foreign"
			case "bad-user":
				in[1].InitiatorUser = "user\n"
			case "null-prefix":
				in[1].InitiatorUser = "NULL-ignored"
			case "unknown-mode":
				in[1].Mode = "none"
			case "stale-outbound":
				in[1].TargetUser = "unexpected"
			case "same-mutual-user":
				in[0].TargetUser = in[0].InitiatorUser
			}
			if got, err := s.matchPeers(in); got != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("partial/accepted roster", err)
			}
		})
	}
	if _, err := json.Marshal(s); err == nil {
		t.Fatal("serializable sink")
	}
	if strings.Contains(fmt.Sprintf("%#v", s), "peer-a") {
		t.Fatal("formatter leaks roster")
	}
}

func TestLIOAttributeReadbackBoundaries(t *testing.T) {
	for _, value := range []string{"value\n", "value", "value\nextra", "value\n\n", "other\n", ""} {
		name := filepath.Join(t.TempDir(), "attribute")
		if err := os.WriteFile(name, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		got := lioCompareAttribute(f, []byte("value"))
		if (got == nil) != (value == "value\n") {
			t.Fatal("nonexact readback")
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if lioCompareAttribute(nil, []byte("value")) == nil {
		t.Fatal("nil attribute")
	}
}

func TestLIOSecretSinkLowerIOSeam(t *testing.T) {
	// Explicit regular-file I/O seam, NOT configfs constructor qualification.
	const token = "PublicSyntheticToken1!"
	name := filepath.Join(t.TempDir(), "attribute")
	if err := os.WriteFile(name, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, install := range []bool{false, true} {
		if _, err := f.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		value := []byte(token)
		n, err := (lioAttributeSink{f, install}).Write(value)
		if err != nil || n != len(value) || string(value) != token {
			t.Fatal("sink alters/shortens source", err)
		}
	}
	if n, err := (lioAttributeSink{f, false}).Write([]byte("short")); n != 0 || err == nil {
		t.Fatal("invalid sink length")
	}
	if n, err := (lioAttributeSink{f, false}).Write([]byte("DifferentSynthetic!!")); n != 0 || err == nil {
		t.Fatal("mismatched readback")
	}
}

func TestLIOConfigFSRequiredAndRefusalsDoNotWrite(t *testing.T) {
	for _, name := range []string{"../auth", "iqn.2026-10.invalid.phantowd:peer/../../other", "iqn.2026-10.invalid.phantowd:peer\n", "", "IQN.2026-10.invalid.phantowd:peer"} {
		if lioPeerComponent(name) {
			t.Fatal("unsafe path component")
		}
	}
	if !lioPeerComponent("iqn.2026-10.invalid.phantowd:peer") {
		t.Fatal("safe component refused")
	}
	directory := t.TempDir()
	file, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := newLIOCredentialSink(file, []lioAuthSelection{{name: "peer", auth: file}}); err == nil {
		t.Fatal("ordinary filesystem admitted")
	}
	if _, err := lioOpenAttribute(file, "../password", os.O_RDWR); !errors.Is(err, ErrInvalid) {
		t.Fatal("unfixed attribute", err)
	}
	if _, err := newLIOCredentialSink(nil, nil); err == nil {
		t.Fatal("nil constructor")
	}
	var nilSink *lioCredentialSink
	if nilSink.PrepareCredentials(context.Background(), nil) == nil || nilSink.verifyDisabled(context.Background()) == nil {
		t.Fatal("nil operation")
	}
	sink := &lioCredentialSink{}
	if sink.PrepareCredentials(nil, nil) == nil {
		t.Fatal("nil context")
	}
	if sink.verifyDisabled(context.Background()) == nil {
		t.Fatal("unprepared verification")
	}
	sink.review = true
	if !errors.Is(sink.PrepareCredentials(context.Background(), nil), ErrReview) || !errors.Is(sink.verifyDisabled(context.Background()), ErrReview) {
		t.Fatal("review retry")
	}
	sink.review = false
	sink.attempted = true
	if !errors.Is(sink.PrepareCredentials(context.Background(), nil), ErrBusy) {
		t.Fatal("repeat prepare")
	}
}
