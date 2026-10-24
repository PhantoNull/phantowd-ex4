//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func nfsExpectedFixture(t *testing.T) ([]byte, [32]byte, *Plan) {
	t.Helper()
	root := sha256.Sum256([]byte("independent synthetic build root"))
	entries := []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs", "usr/sbin/rpc.nfsd", "usr/sbin/rpc.statd", "usr/sbin/sm-notify"}
	var files []File
	var objects []map[string]any
	for _, name := range append(append([]string{}, entries...), "lib/libfixed.so") {
		file := exampleFile(name)
		files = append(files, file)
		bindings := []string{name}
		if name == "lib/libfixed.so" {
			bindings = append(bindings, "lib/libfixed.so.1")
		}
		objects = append(objects, map[string]any{"path": name, "sha256": hex.EncodeToString(file.SHA256[:]), "size": file.Size, "bindings": bindings})
	}
	data, err := json.Marshal(map[string]any{"format": "phantowd-nfs-runtime-candidate", "schema_version": 1,
		"root_digest_sha256": hex.EncodeToString(root[:]), "expected_entries": entries,
		"static_dependencies_resolved": true, "runtime_qualified": false, "execution_authorized": false,
		"objects": objects, "total_bytes": 35, "limitations": []string{"synthetic inert metadata only"}})
	if err != nil {
		t.Fatal(err)
	}
	want, err := NewPlan(files, []Alias{{Path: "lib/libfixed.so.1", Target: "lib/libfixed.so"}})
	if err != nil {
		t.Fatal(err)
	}
	return data, root, want
}

func TestNFSExpectedQEMUProducesOnlyDetachedInertPlan(t *testing.T) {
	data, root, want := nfsExpectedFixture(t)
	got, err := DecodeNFSExpectedQEMU(data, root)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("six programs/shared library did not produce the expected code-only plan", err)
	}
	reordered := nfsExpectedChanged(t, data, func(d map[string]any) {
		objects := d["objects"].([]any)
		slices.Reverse(objects)
		for _, object := range objects {
			slices.Reverse(object.(map[string]any)["bindings"].([]any))
		}
	})
	if again, err := DecodeNFSExpectedQEMU(reordered, root); err != nil || !reflect.DeepEqual(again, want) {
		t.Fatal("code ordering changed the plan", err)
	}
	clear(data)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("plan retained mutable JSON input")
	}
	if _, err := json.Marshal(got); err == nil {
		t.Fatal("internal code plan became serializable authority")
	}
}

func TestNFSExpectedQEMURequiresSeparateMatchingRootObservation(t *testing.T) {
	data, _, _ := nfsExpectedFixture(t)
	for name, root := range map[string][32]byte{"missing": {}, "foreign": sha256.Sum256([]byte("other root"))} {
		t.Run(name, func(t *testing.T) {
			plan, err := DecodeNFSExpectedQEMU(data, root)
			if plan != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("report supplied its own expected root", err)
			}
		})
	}
}

func nfsExpectedChanged(t *testing.T, data []byte, change func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if json.Unmarshal(data, &document) != nil {
		t.Fatal("invalid test document")
	}
	change(document)
	result, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNFSExpectedQEMURefusesIncompleteOrDifferentProfile(t *testing.T) {
	data, root, _ := nfsExpectedFixture(t)
	bad := map[string]any{"format": "other", "schema_version": 2, "expected_entries": []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs"},
		"static_dependencies_resolved": false, "runtime_qualified": true, "execution_authorized": true,
		"failed_entry": "usr/sbin/rpc.nfsd", "reason": "incomplete", "limitations": []string{}}
	for field, value := range bad {
		t.Run(field, func(t *testing.T) {
			changed := nfsExpectedChanged(t, data, func(d map[string]any) { d[field] = value })
			if plan, err := DecodeNFSExpectedQEMU(changed, root); plan != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("partial, legacy or authorized report accepted", err)
			}
		})
	}
	for _, field := range []string{"format", "schema_version", "root_digest_sha256", "expected_entries", "static_dependencies_resolved", "runtime_qualified", "execution_authorized", "limitations", "objects", "total_bytes"} {
		t.Run("missing-"+field, func(t *testing.T) {
			changed := nfsExpectedChanged(t, data, func(d map[string]any) { delete(d, field) })
			if plan, err := DecodeNFSExpectedQEMU(changed, root); plan != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("missing required metadata accepted", err)
			}
		})
	}
}

func TestNFSExpectedQEMURequiresCompleteUnambiguousJSON(t *testing.T) {
	data, root, _ := nfsExpectedFixture(t)
	text := string(data)
	cases := map[string]string{"empty": "", "trailing": text + "{}", "unknown": `{"other":0,` + text[1:],
		"duplicate": `{"format":"other",` + text[1:], "field-case": strings.Replace(text, `"format"`, `"Format"`, 1),
		"null":        string(nfsExpectedChanged(t, data, func(d map[string]any) { d["runtime_qualified"] = nil })),
		"over-budget": strings.Repeat(" ", (128<<10)+1) + text}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if plan, err := DecodeNFSExpectedQEMU([]byte(input), root); plan != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("ambiguous or unbounded metadata accepted", err)
			}
		})
	}
	exact := strings.Repeat(" ", (128<<10)-len(data)) + text
	if plan, err := DecodeNFSExpectedQEMU([]byte(exact), root); plan == nil || err != nil {
		t.Fatal("valid exact input bound refused", err)
	}
}

func TestNFSExpectedQEMUBoundsWholeCodeSet(t *testing.T) {
	data, root, _ := nfsExpectedFixture(t)
	for _, kind := range []string{"files", "bindings", "bytes"} {
		for over := range 2 {
			t.Run(fmt.Sprintf("%s-over-%d", kind, over), func(t *testing.T) {
				changed := nfsExpectedChanged(t, data, func(d map[string]any) {
					objects := d["objects"].([]any)
					library := objects[6].(map[string]any)
					switch kind {
					case "files":
						for index := range 256 - len(objects) + over {
							name := fmt.Sprintf("lib/extra-%d.so", index)
							objects = append(objects, map[string]any{"path": name, "sha256": library["sha256"], "size": 5, "bindings": []string{name}})
						}
						d["objects"], d["total_bytes"] = objects, 5*len(objects)
					case "bindings":
						bindings := library["bindings"].([]any)
						for index := range 1024 - 8 + over {
							bindings = append(bindings, fmt.Sprintf("lib/alias-%d.so", index))
						}
						library["bindings"] = bindings
					case "bytes":
						library["size"], d["total_bytes"] = (64<<20)-30+over, (64<<20)+over
					}
				})
				plan, err := DecodeNFSExpectedQEMU(changed, root)
				if over == 0 && (plan == nil || err != nil) || over == 1 && (plan != nil || !errors.Is(err, ErrInvalid)) {
					t.Fatal("whole-set boundary not enforced", err)
				}
			})
		}
	}
}

func TestNFSExpectedQEMURefusesUnobservedOrInconsistentCodeSet(t *testing.T) {
	data, root, _ := nfsExpectedFixture(t)
	for _, fault := range []string{"total", "total-budget", "missing-entry", "canonical-binding", "duplicate-binding", "missing-binding", "uppercase-hash"} {
		t.Run(fault, func(t *testing.T) {
			changed := nfsExpectedChanged(t, data, func(d map[string]any) {
				objects := d["objects"].([]any)
				first, library := objects[0].(map[string]any), objects[6].(map[string]any)
				switch fault {
				case "total":
					d["total_bytes"] = 34
				case "total-budget":
					d["total_bytes"] = maxBytes + 1
				case "missing-entry":
					d["objects"], d["total_bytes"] = objects[1:], 30
				case "canonical-binding":
					library["bindings"] = []string{"lib/libfixed.so.1"}
				case "duplicate-binding":
					first["bindings"] = []string{first["path"].(string), first["path"].(string)}
				case "missing-binding":
					delete(first, "bindings")
				case "uppercase-hash":
					first["sha256"] = strings.ToUpper(first["sha256"].(string))
				}
			})
			if plan, err := DecodeNFSExpectedQEMU(changed, root); plan != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("inconsistent code set published a partial or complete plan", err)
			}
		})
	}
}
