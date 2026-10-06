//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package iscsicredentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func testDocument() document {
	return document{Kind: "phantowd-chap-credentials", SchemaVersion: 1, Revision: 1,
		Entries: []entry{{Ref: "incoming", Secret: "SyntheticIncoming1!"}, {Ref: "outgoing", Secret: "SyntheticOutgoing2!"}}}
}
func testPolicy() naspolicy.Config {
	s := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "test-volume", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
		Users:   []shareconfig.User{}, Shares: []shareconfig.Share{}}
	return naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: 1,
		FileServices: fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1, Shares: s,
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1, Exports: []nfsconfig.Export{}}},
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
			Backings: []iscsipolicy.Backing{{ID: "backing", VolumeID: "test-volume", RelativePath: "data/lun.img", CapacityBytes: 4096, BlockSize: 512, Allocation: "preallocated"}},
			Targets: []iscsipolicy.Target{{ID: "target", Name: "iqn.2001-04.com.example:target", State: "disabled",
				LUNs: []iscsipolicy.LUN{{ID: "lun", Number: 0, BackingID: "backing", Access: "rw"}},
				Initiators: []iscsipolicy.Initiator{{Name: "iqn.2001-04.com.example:peer",
					Authentication: iscsipolicy.Authentication{Mode: "mutual-chap", InitiatorUser: "peer", InitiatorSecretRef: "incoming", TargetUser: "target", TargetSecretRef: "outgoing"},
					Grants:         []iscsipolicy.Grant{{LUNID: "lun", Access: "rw"}}}}}}}}
}

type testConsumer struct {
	calls int
	peers []Credential
	fail  bool
}

func (c *testConsumer) PrepareCredentials(_ context.Context, peers []Credential) error {
	c.calls++
	c.peers = append([]Credential(nil), peers...)
	if c.fail {
		return errors.New("untrusted backend error with synthetic-secret")
	}
	return nil
}
func rootFixture(t *testing.T, d document) (string, *Owner) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("positive root-only opener requires isolated root Linux/QEMU")
	}
	directory := filepath.Join(t.TempDir(), "vault")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := revisionstore.OpenWithCodec(directory, codec())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(0, d); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	o, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return directory, o
}

func TestDocumentBoundsAndStrictRedactedFailures(t *testing.T) {
	d := testDocument()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal("disk codec cannot encode")
	}
	if _, err := decode(bytes.NewReader(b)); err != nil {
		t.Fatal("valid document refused")
	}
	for _, mutate := range []func(*document){
		func(d *document) { d.Kind = "foreign" }, func(d *document) { d.SchemaVersion = 2 }, func(d *document) { d.Revision = 0 },
		func(d *document) { d.Entries = nil }, func(d *document) { d.Entries[0].Ref = "../incoming" },
		func(d *document) { d.Entries[1].Ref = d.Entries[0].Ref }, func(d *document) { d.Entries[1].Secret = d.Entries[0].Secret },
		func(d *document) { d.Entries[0].Secret = "NULLSyntheticLong!" }, func(d *document) { d.Entries[0].Secret = "Synthetic space !" },
		func(d *document) { d.Entries[0].Secret = strings.Repeat("a", 15) }, func(d *document) { d.Entries[0].Secret = strings.Repeat("a", 129) },
		func(d *document) { d.Entries[0].Secret = "Synthetic\nNewline!" }, func(d *document) { d.Entries[0].Secret = "SyntheticNonASCIIé" },
	} {
		next := testDocument()
		mutate(&next)
		if !errors.Is(validate(next), ErrInvalid) {
			t.Fatal("invalid document accepted")
		}
	}
	for _, raw := range []string{
		string(b) + "{}", strings.Replace(string(b), `"revision":1`, `"revision":1,"revision":1`, 1),
		strings.Replace(string(b), `"entries":`, `"Entries":`, 1), strings.Replace(string(b), `"schema_version":1`, `"schema_version":null`, 1),
		strings.Replace(string(b), `"ref":`, `"unknown":`, 1), strings.Repeat("x", maxBytes+1),
	} {
		got, err := decode(strings.NewReader(raw))
		if !errors.Is(err, ErrInvalid) || len(got.Entries) != 0 || strings.Contains(err.Error(), "Synthetic") {
			t.Fatal("partial or non-redacted decode")
		}
	}
	for _, s := range []string{strings.Repeat("a", 16), strings.Repeat("a", 128)} {
		if !validSecret(s) {
			t.Fatal("length boundary refused")
		}
	}
	if testPolicy().Validate() != nil {
		t.Fatal("invalid test policy")
	}
}

func TestRootOnlyOpenerHasNoProvisioningFallback(t *testing.T) {
	if o, err := Open(filepath.Join(t.TempDir(), "absent")); o != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing store accepted")
	}
	if os.Geteuid() != 0 { // EUID refusal must precede even reading a plausible path.
		if o, err := Open(t.TempDir()); o != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("non-root opened vault")
		}
	}
}

func TestRootOnlyStoreRefusesUnsafeExistingObjects(t *testing.T) {
	for _, kind := range []string{"directory-mode", "file-mode", "symlink", "hardlink", "corrupt", "missing-current"} {
		t.Run(kind, func(t *testing.T) {
			dir, o := rootFixture(t, testDocument())
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, "chap-secrets.json")
			switch kind {
			case "directory-mode":
				if err := os.Chmod(dir, 0750); err != nil {
					t.Fatal(err)
				}
			case "file-mode":
				if err := os.Chmod(name, 0640); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				other := filepath.Join(dir, "private-copy")
				if err := os.Rename(name, other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, name); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(name, filepath.Join(dir, "alias")); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(name, []byte("{untrusted-secret-diagnostic"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-current":
				if err := os.Rename(name, filepath.Join(dir, ".chap-secrets.pending")); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := Open(dir); got != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("unsafe object admitted", kind)
			}
		})
	}
}

func TestNoPartialMaterialWhenAnUnselectedTargetReferenceIsMissing(t *testing.T) {
	_, o := rootFixture(t, testDocument())
	p := testPolicy()
	p.ISCSI.Backings = append(p.ISCSI.Backings, iscsipolicy.Backing{ID: "other-backing", VolumeID: "test-volume", RelativePath: "data/other.img", CapacityBytes: 4096, BlockSize: 512, Allocation: "preallocated"})
	p.ISCSI.Targets = append(p.ISCSI.Targets, iscsipolicy.Target{ID: "other-target", Name: "iqn.2001-04.com.example:other", State: "disabled",
		LUNs:       []iscsipolicy.LUN{{ID: "other-lun", Number: 0, BackingID: "other-backing", Access: "rw"}},
		Initiators: []iscsipolicy.Initiator{{Name: "iqn.2001-04.com.example:other-peer", Authentication: iscsipolicy.Authentication{Mode: "chap", InitiatorUser: "other-peer", InitiatorSecretRef: "absent"}, Grants: []iscsipolicy.Grant{{LUNID: "other-lun", Access: "rw"}}}}})
	if err := p.Validate(); err != nil {
		t.Fatal("bad fixture policy")
	}
	c := &testConsumer{}
	if b, err := o.Acquire(context.Background(), 1, p, "target", c); b != nil || !errors.Is(err, ErrInvalid) || c.calls != 0 {
		t.Fatal("partial selected target material returned")
	}
	if err := o.Close(); err != nil {
		t.Fatal("failed all-policy resolution retained claim")
	}
}

type diagnosticWriter struct{}

func (diagnosticWriter) Write(p []byte) (int, error) { return len(p) / 2, errors.New(string(p)) }
func TestSecretSinkFailureNeverEchoesBytes(t *testing.T) {
	s := newSecret("PublicSyntheticToken1!")
	defer s.wipe()
	if n, err := s.WriteTo(diagnosticWriter{}); n != 0 || !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "Synthetic") {
		t.Fatal("sink failure not redacted")
	}
}

func TestBundleFixedConsumerRetentionReleaseAndOpaqueValues(t *testing.T) {
	_, o := rootFixture(t, testDocument())
	ctx := context.Background()
	c := &testConsumer{}
	b, err := o.Acquire(ctx, 1, testPolicy(), "target", c)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(o.Close(), ErrBusy) {
		t.Fatal("live claim did not fence close")
	}
	if err := b.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if c.calls != 1 || len(c.peers) != 1 || c.peers[0].Mode != "mutual-chap" {
		t.Fatal("incorrect consumer roster")
	}
	var incoming, outgoing bytes.Buffer
	if _, err := c.peers[0].Incoming.WriteTo(&incoming); err != nil {
		t.Fatal(err)
	}
	if _, err := c.peers[0].Outgoing.WriteTo(&outgoing); err != nil {
		t.Fatal(err)
	}
	if incoming.String() != testDocument().Entries[0].Secret || outgoing.String() != testDocument().Entries[1].Secret {
		t.Fatal("credential binding differs")
	}
	if !errors.Is(b.Prepare(ctx), ErrBusy) || c.calls != 1 {
		t.Fatal("prepare repeated")
	}
	for _, v := range []any{o, b, c.peers[0], c.peers[0].Incoming, Owner{}, Bundle{}, Credential{}, Secret{}, testDocument(), testDocument().Entries[0]} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if !strings.Contains(fmt.Sprintf(format, v), "redacted CHAP material") {
				t.Fatal("value not text-redacted")
			}
		}
	}
	for _, v := range []any{o, b, c.peers[0], c.peers[0].Incoming, Owner{}, Bundle{}, Credential{}, Secret{}} {
		if data, err := json.Marshal(v); err == nil || len(data) != 0 {
			t.Fatal("opaque value serialized")
		}
	}
	if err := b.Release(); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []Secret{c.peers[0].Incoming, c.peers[0].Outgoing} {
		if _, err := secret.WriteTo(io.Discard); !errors.Is(err, ErrClosed) {
			t.Fatal("released borrowed secret usable")
		}
		for _, v := range secret.buffer.value {
			if v != 0 {
				t.Fatal("owned buffer not wiped")
			}
		}
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMissingReservedForeignAndTypedNilSelectionsConsumeNothing(t *testing.T) {
	_, o := rootFixture(t, testDocument())
	ctx := context.Background()
	for _, kind := range []string{"revision", "target", "missing", "null-user", "null-target-user", "typed-nil", "nil-context"} {
		p := testPolicy()
		target := iscsipolicy.TargetID("target")
		rev := uint64(1)
		c := &testConsumer{}
		callctx := ctx
		switch kind {
		case "revision":
			rev = 2
		case "target":
			target = "foreign"
		case "missing":
			p.ISCSI.Targets[0].Initiators[0].Authentication.InitiatorSecretRef = "absent"
		case "null-user":
			p.ISCSI.Targets[0].Initiators[0].Authentication.InitiatorUser = "NULLuser"
		case "null-target-user":
			p.ISCSI.Targets[0].Initiators[0].Authentication.TargetUser = "NULLtarget"
		case "typed-nil":
			c = nil
		case "nil-context":
			callctx = nil
		}
		if b, err := o.Acquire(callctx, rev, p, target, c); b != nil || err == nil {
			t.Fatal("bad selection admitted", kind)
		}
		if c != nil && c.calls != 0 {
			t.Fatal("admission called backend", kind)
		}
	}
	if err := o.Close(); err != nil {
		t.Fatal("failed selection retained claim", err)
	}
}

func TestRestoredMutationAndUncertainPrepareNeverRetryOrWipeImplicitly(t *testing.T) {
	for _, kind := range []string{"before", "after", "prepare"} {
		t.Run(kind, func(t *testing.T) {
			dir, o := rootFixture(t, testDocument())
			ctx := context.Background()
			c := &testConsumer{fail: kind == "prepare"}
			b, err := o.Acquire(ctx, 1, testPolicy(), "target", c)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "after" {
				if err := b.Prepare(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "prepare" {
				name := filepath.Join(dir, "chap-secrets.json")
				original, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, []byte("{interrupted"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, original, 0600); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(b.Verify(ctx), ErrReview) {
					t.Fatal("restored mutation accepted")
				}
			}
			if !errors.Is(b.Prepare(ctx), ErrReview) {
				t.Fatal("uncertainty did not quarantine")
			}
			calls := c.calls
			if !errors.Is(b.Prepare(ctx), ErrReview) || c.calls != calls {
				t.Fatal("uncertain prepare retried")
			}
			if !errors.Is(o.Close(), ErrBusy) {
				t.Fatal("uncertainty dropped claim")
			}
			if _, err := b.peers[0].Incoming.WriteTo(io.Discard); err != nil {
				t.Fatal("uncertainty wiped live borrow")
			}
			if err := b.Release(); err != nil {
				t.Fatal(err)
			} // fixture, independently no backend resources
		})
	}
}

func TestConcurrentPrepareIsSingleAndSecretReleaseSerializes(t *testing.T) {
	_, o := rootFixture(t, testDocument())
	ctx := context.Background()
	c := &testConsumer{}
	b, err := o.Acquire(ctx, 1, testPolicy(), "target", c)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() { _ = b.Prepare(ctx) })
	}
	wg.Wait()
	if c.calls != 1 {
		t.Fatal("concurrent prepare repeated")
	}
	for range 12 {
		wg.Go(func() { _, _ = c.peers[0].Incoming.WriteTo(io.Discard) })
	}
	wg.Go(func() { _ = b.Release() })
	wg.Wait()
	if _, err := c.peers[0].Incoming.WriteTo(io.Discard); !errors.Is(err, ErrClosed) {
		t.Fatal("post-release borrow usable")
	}
}
