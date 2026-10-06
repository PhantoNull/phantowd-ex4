//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func registryCollectorReader(t *testing.T, volumes ...shareconfig.Volume) (*volumeregistry.Reader, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	d := volumeregistry.Document{Format: volumeregistry.Format, SchemaVersion: volumeregistry.SchemaVersion,
		Revision: 11, Volumes: append([]shareconfig.Volume{}, volumes...)}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "volumes.json")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := volumeregistry.Open(f)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal("protected fixture reader unavailable", err, closeErr)
	}
	// Some refusal cases explicitly close this Reader first. Their close is
	// checked at that boundary; cleanup must not treat its second Close as a
	// successful new lifecycle operation.
	t.Cleanup(func() { _ = r.Close() })
	return r, file, data
}

func TestRegisteredStorageCollectorStableScopedResults(t *testing.T) {
	for _, kind := range []string{"stable", "missing", "unknown", "conflict", "empty"} {
		t.Run(kind, func(t *testing.T) {
			volume := shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID}
			volumes := []shareconfig.Volume{volume}
			if kind == "missing" {
				volumes[0].FilesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			}
			if kind == "empty" {
				volumes = nil
			}
			r, _, _ := registryCollectorReader(t, volumes...)
			policy := registryPolicyFixture(volumes...)
			if kind == "unknown" {
				policy.Shares.Volumes[0].ID = "different-id"
			}
			if kind == "conflict" {
				policy.Shares.Volumes[0].FilesystemUUID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
			}
			sysfs, proc, roots := mountedCensusFixture()
			calls := 0
			got, err := collectRegisteredStorageReviewWith(context.Background(), policy, r, sysfs, proc,
				func(anchors []string) (mountguard.MountedInventory, error) {
					calls++
					if !reflect.DeepEqual(anchors, []string{"/data"}) {
						t.Fatal("subset reached observer", anchors)
					}
					return roots, nil
				})
			if err != nil || calls != 4 || got.policy.policyRevision != 7 || got.policy.registryRevision != 11 ||
				got.backing.registryRevision != 11 || got.policy.coverage != got.backing.coverage || got.policy.objectCount != 1 {
				t.Fatal("composed scope/revisions lost", got, calls, err)
			}
			if kind == "empty" {
				if len(got.policy.volumes) != 0 || got.policy.unclaimedObjectCount != 1 || len(got.backing.volumes) != 0 {
					t.Fatal("empty registry hid census", got)
				}
			} else {
				want := map[string]string{"stable": "observed-in-scope", "missing": "not-observed-in-scope", "unknown": "not-registered", "conflict": "registry-policy-conflict"}[kind]
				if len(got.policy.volumes) != 1 || got.policy.volumes[0].observed.status != want {
					t.Fatal("claim silently rebound", got)
				}
			}
			if _, err := json.Marshal(got); err == nil {
				t.Fatal("composite serialized")
			}
			if err := json.Unmarshal([]byte(`{}`), &got); err == nil {
				t.Fatal("request created composite")
			}
		})
	}
}

func TestRegisteredStorageCollectorEarlyRefusal(t *testing.T) {
	for _, kind := range []string{"nil-context", "canceled", "nil-reader", "closed-reader", "invalid-policy", "split-policy", "nil-sysfs", "nil-proc", "nil-observer", "unsafe-registry"} {
		t.Run(kind, func(t *testing.T) {
			r, file, _ := registryCollectorReader(t)
			policy := registryPolicyFixture()
			var ctx context.Context = context.Background()
			sysfsFixture, procFixture, roots := mountedCensusFixture()
			var sysfs, proc fs.FS = sysfsFixture, procFixture
			calls := 0
			var observe mountedExtRootObserver = func([]string) (mountguard.MountedInventory, error) { calls++; return roots, nil }
			switch kind {
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-reader":
				r = nil
			case "closed-reader":
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
			case "invalid-policy":
				policy.Format = "invalid"
			case "split-policy":
				policy.NFS.Revision++
			case "nil-sysfs":
				sysfs = nil
			case "nil-proc":
				proc = nil
			case "nil-observer":
				observe = nil
			case "unsafe-registry":
				if err := os.Chmod(file, 0644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := collectRegisteredStorageReviewWith(ctx, policy, r, sysfs, proc, observe)
			if err != volumeregistry.ErrObservation || calls != 0 || !reflect.DeepEqual(got, registeredStorageReview{}) {
				t.Fatal("invalid input reached root observer or leaked partial result", got, calls, err)
			}
		})
	}
}

func TestRegisteredStorageCollectorRefusesDriftWithoutPartialPublication(t *testing.T) {
	for _, kind := range []string{"registry-during-first", "registry-during-recheck", "directory-aba", "closed-during-census", "root-drift", "excluded-mount-drift", "unclaimed-device-drift", "cancel", "observer-error"} {
		t.Run(kind, func(t *testing.T) {
			volume := shareconfig.Volume{ID: "books", FilesystemUUID: mountedReviewUUID}
			r, file, data := registryCollectorReader(t, volume)
			sysfs, proc, roots := mountedCensusFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			got, err := collectRegisteredStorageReviewWith(ctx, registryPolicyFixture(volume), r, sysfs, proc,
				func([]string) (mountguard.MountedInventory, error) {
					calls++
					if kind == "observer-error" {
						return mountguard.MountedInventory{}, errors.New("private fixture detail")
					}
					if (kind == "registry-during-first" && calls == 1) || (kind == "registry-during-recheck" && calls == 3) {
						if os.WriteFile(file, []byte(`{}`), 0600) != nil || os.WriteFile(file, data, 0600) != nil {
							t.Fatal("fixture restore failed")
						}
					}
					if kind == "directory-aba" && calls == 3 {
						other := filepath.Join(filepath.Dir(file), "temporary")
						if os.WriteFile(other, []byte("fixture"), 0600) != nil || os.Remove(other) != nil {
							t.Fatal("directory fixture failed")
						}
					}
					if kind == "closed-during-census" && calls == 3 {
						if err := r.Close(); err != nil {
							t.Fatal(err)
						}
					}
					if kind == "root-drift" && calls == 3 {
						roots.Mounts[0].MountID++
					}
					if kind == "excluded-mount-drift" && calls == 2 {
						proc["self/mountinfo"].Data = append(proc["self/mountinfo"].Data, []byte("41 36 0:44 / /extra ro - tmpfs tmpfs ro\n")...)
					}
					if kind == "unclaimed-device-drift" && calls == 2 {
						addNonPartitionBlockNode(sysfs, "sdb", 8, 16, "other-physical-disk", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
						physicalizeBlockNode(sysfs, "sdb")
					}
					if kind == "cancel" && calls == 3 {
						cancel()
					}
					return roots, nil
				})
			if err != volumeregistry.ErrObservation || !reflect.DeepEqual(got, registeredStorageReview{}) {
				t.Fatal("drift leaked composed observation", got, calls, err)
			}
		})
	}
}
