//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestTargetPlanningRefusesConfiguredSMBExposure(t *testing.T) {
	p := fixtureTargetPolicy(1, "data/a", "data/b")
	p.FileServices.Shares.Users = []shareconfig.User{{ID: "reader", Name: "reader"}}
	p.FileServices.Shares.Shares = []shareconfig.Share{{ID: "visible", Name: "visible", VolumeID: "qemu-plan", RelativePath: "data",
		Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}}}}
	if p.Validate() != nil {
		t.Fatal("desired overlap must remain saveable, not silently activate")
	}
	var in []targetSelection
	for _, id := range []iscsipolicy.BackingID{"fixture-backing", "fixture-second"} {
		f, err := os.CreateTemp(t.TempDir(), "input-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		in = append(in, targetSelection{backingID: id, pin: &Pin{}, file: f})
	}
	if plan, err := planTarget(p, "fixture-target", in); plan != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("read-only share exposure admitted for target resources")
	}
	if target, defs, err := lioTargetDefinition(p, "fixture-target"); target.ID != "" || defs != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("exposed target definition captured for LIO")
	}
	for _, member := range in {
		if _, err := member.file.Stat(); err != nil || member.pin.consumer != nil {
			t.Fatal("rejected selection consumed caller resources")
		}
	}
}

func TestTargetDefinitionRefusesConfiguredNFSExposure(t *testing.T) {
	p := fixtureTargetPolicy(1, "data/a", "other/b")
	p.FileServices.NFS.Exports = []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "qemu-plan", RelativePath: "other",
		Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "ro", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}}}
	if p.Validate() != nil {
		t.Fatal("valid read-only NFS desired policy refused")
	}
	if target, defs, err := lioTargetDefinition(p, "fixture-target"); target.ID != "" || defs != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("later member exposed through NFS admitted")
	}
}

func TestTargetKnownUseCanonicalBoundariesAndVolumeScope(t *testing.T) {
	for _, protocol := range []string{"configured-smb", "configured-nfs"} {
		for _, access := range []string{"ro", "rw"} {
			for _, tc := range []struct {
				path    string
				refused bool
			}{{".", true}, {"data", true}, {"data/a", true}, {"data/a/nested", true}, {"database", false}, {"data/ab", false}, {"elsewhere", false}} {
				t.Run(protocol+"-"+access+"-"+tc.path, func(t *testing.T) {
					p := fixtureTargetPolicy(1, "data/a", "other/b")
					fixtureTargetExposure(&p, protocol, tc.path)
					p.ISCSI.Targets[0].LUNs[0].Access = access
					p.ISCSI.Targets[0].Initiators[0].Grants[0].Access = access
					if protocol == "configured-smb" {
						p.FileServices.Shares.Shares[0].Grants[0].Access = access
					} else {
						p.FileServices.NFS.Exports[0].Clients[0].Access = access
					}
					if p.Validate() != nil {
						t.Fatal("invalid control policy")
					}
					before, _ := json.Marshal(p)
					target, defs, err := lioTargetDefinition(p, "fixture-target")
					if tc.refused {
						if target.ID != "" || defs != nil || !errors.Is(err, ErrInvalid) {
							t.Fatal("known exposure produced partial definition")
						}
					} else if err != nil || target.ID != "fixture-target" || len(defs) != 2 {
						t.Fatal("lexically disjoint control refused", err)
					}
					// Metadata selection seam ONLY, not a qualified mounted root.
					pin := &Pin{mountRoot: &mountowner.VolumeRootPin{}, volumeID: "qemu-plan", directory: "data", name: "a", fileIdentity: identity{size: 4096}}
					if policyMatchesPin(p, "fixture-backing", pin) == tc.refused {
						t.Fatal("singleton policy path bypassed or over-refused")
					}
					after, _ := json.Marshal(p)
					if string(before) != string(after) {
						t.Fatal("admission mutated desired policy")
					}
				})
			}
		}
		p := fixtureTargetPolicy(1, "data/a", "other/b")
		fixtureTargetExposure(&p, protocol, ".")
		p.FileServices.Shares.Volumes = append(p.FileServices.Shares.Volumes, shareconfig.Volume{ID: "different", FilesystemUUID: "22222222-3333-4444-5555-666666666666"})
		if protocol == "configured-smb" {
			p.FileServices.Shares.Shares[0].VolumeID = "different"
		} else {
			p.FileServices.NFS.Exports[0].VolumeID = "different"
		}
		if target, _, err := lioTargetDefinition(p, "fixture-target"); err != nil || target.ID != "fixture-target" {
			t.Fatal("different logical volume treated as known path overlap", err)
		}
	}
}

type targetLifecycleBackend struct {
	*credentialLifecycleBackend
	starts        int
	borrowed      []targetBacking
	allLiveAtStop bool
	startFailure  error
}

func (b *targetLifecycleBackend) startTarget(ctx context.Context, files []targetBacking) error {
	b.starts++
	b.borrowed = append([]targetBacking(nil), files...)
	if err := b.lifecycleBackend.start(ctx, files[0].file); err != nil {
		return err
	}
	files[0].file = nil // A mutable backend argument cannot alter the owner's roster.
	return b.startFailure
}
func (b *targetLifecycleBackend) stop(ctx context.Context) error {
	b.allLiveAtStop = true
	for _, file := range b.borrowed {
		if _, err := file.file.Stat(); err != nil {
			b.allLiveAtStop = false
		}
	}
	return b.credentialLifecycleBackend.stop(ctx)
}

func TestTargetPlanExactCompleteMembershipAndOrder(t *testing.T) {
	open := func() *os.File {
		f, err := os.CreateTemp(t.TempDir(), "input-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	p := fixtureTargetPolicy(1, "data/a", "data/b")
	in := []targetSelection{{backingID: "fixture-second", pin: &Pin{}, file: open()}, {backingID: "fixture-backing", pin: &Pin{}, file: open()}}
	plan, err := planTarget(p, "fixture-target", in)
	if err != nil || len(plan) != 2 || plan[0].number != 0 || plan[1].number != 7 || plan[0].blockSize != 512 || plan[1].blockSize != 4096 || plan[1].capacity != 8192 {
		t.Fatal("canonical target plan", err)
	}
	p.ISCSI.Targets[0].LUNs[1].Access = "ro"
	p.ISCSI.Targets[0].Initiators[0].Grants[1].Access = "ro"
	if plan, err := planTarget(p, "fixture-target", in); err != nil || plan[1].access != "ro" {
		t.Fatal("desired access not preserved")
	}
	for _, kind := range []string{"missing", "extra", "foreign", "duplicate-id", "duplicate-pin", "duplicate-fd", "nil-pin", "nil-file", "foreign-target", "closed-file"} {
		t.Run(kind, func(t *testing.T) {
			inputs := append([]targetSelection(nil), in...)
			id := iscsipolicy.TargetID("fixture-target")
			switch kind {
			case "missing":
				inputs = inputs[:1]
			case "extra":
				inputs = append(inputs, targetSelection{backingID: "extra", pin: &Pin{}, file: open()})
			case "foreign":
				inputs[0].backingID = "foreign"
			case "duplicate-id":
				inputs[0].backingID = inputs[1].backingID
			case "duplicate-pin":
				inputs[0].pin = inputs[1].pin
			case "duplicate-fd":
				inputs[0].file = inputs[1].file
			case "nil-pin":
				inputs[0].pin = nil
			case "nil-file":
				inputs[0].file = nil
			case "foreign-target":
				id = "other"
			case "closed-file":
				inputs[0].file = open()
				_ = inputs[0].file.Close()
			}
			if got, err := planTarget(p, id, inputs); got != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("partial/unsafe plan admitted")
			}
		})
	}
}

func TestTargetMetadataAliasesCannotHideBehindDifferentMounts(t *testing.T) {
	first := &Pin{fileIdentity: identity{major: 8, minor: 0, inode: 42, mount: 10}}
	alias := &Pin{fileIdentity: identity{major: 8, minor: 0, inode: 42, mount: 20}}
	if distinctTargetObjects([]targetBacking{{pin: first}, {pin: alias}}) {
		t.Fatal("bind alias admitted")
	}
	alias.fileIdentity.inode = 43
	if !distinctTargetObjects([]targetBacking{{pin: first}, {pin: alias}}) {
		t.Fatal("distinct file refused")
	}
	alias.fileIdentity.inode = 42
	alias.fileIdentity.minor = 1
	if !distinctTargetObjects([]targetBacking{{pin: first}, {pin: alias}}) {
		t.Fatal("distinct device refused")
	}
	if distinctTargetObjects([]targetBacking{{pin: &Pin{}}}) {
		t.Fatal("unobserved object admitted")
	}
}

// Native state-machine seam, not real Pin/descriptor admission. Actual mounted
// target admission/rollback and real child reap stay mandatory in guest fixtures.
func TestTargetWholeLifetimeAndUncertainty(t *testing.T) {
	for _, kind := range []string{"normal", "stop", "start", "second-drift", "second-file-close", "second-pin-close", "supervise-cancel"} {
		t.Run(kind, func(t *testing.T) {
			o, base := lifecycleOwner(t)
			second, err := os.CreateTemp(t.TempDir(), "second-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = second.Close() })
			p2 := &Pin{consumer: o}
			o.group = []targetBacking{{number: 0, pin: o.pin, file: o.file}, {number: 7, pin: p2, file: second}}
			b := &targetLifecycleBackend{credentialLifecycleBackend: &credentialLifecycleBackend{lifecycleBackend: base}}
			o.backend = &targetBackendAdapter{backend: b, backings: o.group}
			ctx := context.Background()
			if kind == "start" {
				b.startFailure = ErrUnavailable
			}
			if kind == "stop" {
				base.stopError = ErrReview
			}
			if err := o.start(ctx); kind == "start" {
				if !errors.Is(err, ErrReview) || !o.released || !b.allLiveAtStop {
					t.Fatal("partial start did not stop whole borrower")
				}
				return
			} else if err != nil {
				t.Fatal(err)
			}
			if o.group[0].file == nil {
				t.Fatal("backend changed owned roster")
			}
			for _, pin := range []*Pin{o.pin, p2} {
				if !errors.Is(pin.Close(), ErrBusy) {
					t.Fatal("live pin not fenced")
				}
			}
			switch kind {
			case "normal":
				if err := o.stop(ctx); err != nil {
					t.Fatal(err)
				}
			case "stop":
				if !errors.Is(o.stop(ctx), ErrReview) {
					t.Fatal("uncertain whole stop accepted")
				}
			case "second-drift":
				o.check = func() error { return ErrReview }
				if !errors.Is(o.observe(ctx), ErrReview) {
					t.Fatal("member loss accepted")
				}
			case "second-file-close":
				_ = second.Close()
				if !errors.Is(o.stop(ctx), ErrReview) {
					t.Fatal("member close uncertainty accepted")
				}
			case "second-pin-close":
				f, err := os.CreateTemp(t.TempDir(), "meta-")
				if err != nil {
					t.Fatal(err)
				}
				_ = f.Close()
				p2.file = f
				if !errors.Is(o.stop(ctx), ErrReview) {
					t.Fatal("metadata close uncertainty accepted")
				}
			case "supervise-cancel":
				watch, deadlineCancel := context.WithTimeout(ctx, 5*time.Second)
				defer deadlineCancel()
				cancel, done, err := startFixtureSupervisor(watch, o)
				if err != nil {
					t.Fatal(err)
				}
				cancel()
				if err, settled := awaitFixtureSupervisor(done); !settled || !errors.Is(err, context.Canceled) || errors.Is(err, ErrReview) {
					t.Fatal("whole target cancellation", err)
				}
			}
			if b.starts != 1 || base.stopCalls != 1 {
				t.Fatal("whole backend repeated")
			}
			retained := kind == "stop" || kind == "second-file-close" || kind == "second-pin-close"
			if retained {
				if o.released {
					t.Fatal("uncertainty marked complete release")
				}
				if kind == "stop" {
					for _, member := range o.group {
						if member.file == nil || member.pin.consumer != o {
							t.Fatal("uncertain stop dropped member")
						}
						if _, err := member.file.Stat(); err != nil {
							t.Fatal(err)
						}
					}
				}
			} else if !o.released || !o.pin.closed || !p2.closed || !b.allLiveAtStop {
				t.Fatal("whole stop/release ordering")
			}
		})
	}
}

func TestTargetCredentialClaimIsGlobalThroughPartialReferenceClosure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only credential positive requires isolated root fixture")
	}
	o, base := lifecycleOwner(t)
	policy, _ := lifecyclePolicyOwner(t, o)
	second, err := os.CreateTemp(t.TempDir(), "second-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	p2 := &Pin{consumer: o}
	o.group = []targetBacking{{pin: o.pin, file: o.file}, {pin: p2, file: second}}
	b := &targetLifecycleBackend{credentialLifecycleBackend: &credentialLifecycleBackend{lifecycleBackend: base}}
	o.backend = &targetBackendAdapter{backend: b, backings: o.group}
	vault, err := iscsicredentials.OpenQEMUFixture(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := vault.Acquire(context.Background(), 1, fixtureBackingPolicy(1, "synthetic/data"), "fixture-target", b)
	if err != nil {
		t.Fatal(err)
	}
	o.credentials = claim
	t.Cleanup(func() { _ = claim.Release(); _ = vault.Close() })
	if err := o.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	if !errors.Is(o.stop(context.Background()), ErrReview) || o.credentials == nil || o.policy == nil || !errors.Is(vault.Close(), iscsicredentials.ErrBusy) {
		t.Fatal("partial close dropped global sources")
	}
	if o.group[0].file != nil || o.pin.consumer != o || p2.consumer != o {
		t.Fatal("data close failure prematurely dropped pins")
	}
	if _, err := b.peers[0].Incoming.WriteTo(io.Discard); err != nil {
		t.Fatal("partial close wiped credentials")
	}
	_ = policy
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if !errors.Is(o.stop(context.Background()), ErrReview) {
				t.Error("review retried")
			}
		})
	}
	wg.Wait()
	if base.stopCalls != 1 {
		t.Fatal("uncertain release retried stop")
	}
}
