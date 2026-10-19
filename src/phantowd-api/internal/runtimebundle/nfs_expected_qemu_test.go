//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func nfsExpectedFixture(t *testing.T) map[string]any {
	t.Helper()
	entries := []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs"}
	objects := []any{}
	for _, name := range append(append([]string{}, entries...), "lib/ld-linux.so.3") {
		objects = append(objects, map[string]any{"path": name, "sha256": strings.Repeat("a", 64), "size": 100, "bindings": []any{name}})
	}
	return map[string]any{"format": "phantowd-nfs-runtime-candidate", "schema_version": 1,
		"root_digest_sha256": strings.Repeat("b", 64), "expected_entries": entries,
		"static_dependencies_resolved": true, "runtime_qualified": false, "execution_authorized": false,
		"total_bytes": 400, "objects": objects, "limitations": []string{"unsigned test-only expectations"}}
}

func nfsExpectedJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestNFSExpectedPlanAcceptsCompleteUnsignedCodeExpectationsOnly(t *testing.T) {
	plan, err := runtimebundle.NFSExpectedPlanQEMU(nfsExpectedJSON(t, nfsExpectedFixture(t)))
	if err != nil || plan == nil {
		t.Fatal("complete code expectations refused", err)
	}
	if _, err := json.Marshal(plan); !errors.Is(err, runtimebundle.ErrInvalid) {
		t.Fatal("code expectation became a serializable authority", err)
	}
}

func TestNFSExpectedPlanPreservesDeclaredLoaderAlias(t *testing.T) {
	value := nfsExpectedFixture(t)
	loader := value["objects"].([]any)[3].(map[string]any)
	loader["path"] = "lib/ld-real.so"
	loader["bindings"] = []any{"lib/ld-real.so", "lib/ld-linux.so.3"}
	if plan, err := runtimebundle.NFSExpectedPlanQEMU(nfsExpectedJSON(t, value)); err != nil || plan == nil {
		t.Fatal("declared direct loader alias was lost", err)
	}
}

func TestNFSExpectedPlanRefusesIncompleteOrBroadenedClaims(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"format":             func(v map[string]any) { v["format"] = "other" },
		"schema":             func(v map[string]any) { v["schema_version"] = 2 },
		"missing-resolved":   func(v map[string]any) { delete(v, "static_dependencies_resolved") },
		"missing-qualified":  func(v map[string]any) { delete(v, "runtime_qualified") },
		"missing-authorized": func(v map[string]any) { delete(v, "execution_authorized") },
		"partial":            func(v map[string]any) { v["static_dependencies_resolved"] = false },
		"claimed-runtime":    func(v map[string]any) { v["runtime_qualified"] = true },
		"claimed-execution":  func(v map[string]any) { v["execution_authorized"] = true },
		"failure":            func(v map[string]any) { v["failed_entry"] = "usr/sbin/exportfs" },
		"reason":             func(v map[string]any) { v["reason"] = "partial" },
		"wrong-roles":        func(v map[string]any) { v["expected_entries"] = []string{"usr/sbin/rpcbind"} },
		"wrong-total":        func(v map[string]any) { v["total_bytes"] = 399 },
		"invalid-digest":     func(v map[string]any) { v["root_digest_sha256"] = strings.Repeat("0", 64) },
		"no-limits":          func(v map[string]any) { delete(v, "limitations") },
		"unknown":            func(v map[string]any) { v["command"] = "not-allowed" },
		"missing-loader": func(v map[string]any) {
			loader := v["objects"].([]any)[3].(map[string]any)
			loader["path"], loader["bindings"] = "lib/other.so", []any{"lib/other.so"}
		},
		"zero-hash":        func(v map[string]any) { v["objects"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64) },
		"oversized-object": func(v map[string]any) { v["objects"].([]any)[0].(map[string]any)["size"] = 64<<20 + 1 },
		"duplicate-binding": func(v map[string]any) {
			v["objects"].([]any)[0].(map[string]any)["bindings"] = []any{"usr/sbin/rpcbind", "usr/sbin/rpcbind"}
		},
		"no-canonical": func(v map[string]any) { v["objects"].([]any)[0].(map[string]any)["bindings"] = []any{"usr/sbin/other"} },
		"parent-path": func(v map[string]any) {
			v["objects"].([]any)[0].(map[string]any)["bindings"] = []any{"usr/sbin/rpcbind", "../outside"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := nfsExpectedFixture(t)
			mutate(value)
			if plan, err := runtimebundle.NFSExpectedPlanQEMU(nfsExpectedJSON(t, value)); err == nil || plan != nil {
				t.Fatal("incomplete/broadened expectations escaped", err)
			}
		})
	}
}

func TestNFSExpectedPlanRefusesAmbiguousJSONWithoutPartialResult(t *testing.T) {
	valid := string(nfsExpectedJSON(t, nfsExpectedFixture(t)))
	for _, data := range []string{
		`{"format":"duplicate",` + valid[1:],
		strings.Replace(valid, `"runtime_qualified":false`, `"runtime_qualified":null`, 1),
		strings.Replace(valid, `"format":`, `"FORMAT":`, 1),
		valid + "{}", strings.Repeat(" ", 128<<10) + valid, "null", "{}",
	} {
		if plan, err := runtimebundle.NFSExpectedPlanQEMU([]byte(data)); err == nil || plan != nil {
			t.Fatal("ambiguous JSON produced code expectations", err)
		}
	}
}
