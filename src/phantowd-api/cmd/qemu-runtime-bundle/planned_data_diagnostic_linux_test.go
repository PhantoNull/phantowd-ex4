//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

// Static wiring coverage complements the runtime observer/formatter tests.
// It does not claim that a guest has exercised a particular failure boundary.
func TestPlannedDataDiagnosticsShareDirectAndFaultWiring(t *testing.T) {
	for _, caller := range []struct {
		file, function string
		callees        []string
	}{
		{"planned_startup_linux.go", "nativePlannedServiceFixtureQEMU", []string{"plannedDataRefusalDiagnosticQEMU"}},
		{"planned_fault_diagnostic_linux.go", "plannedFaultFailureDiagnosticQEMU", []string{"plannedDataRefusalDiagnosticQEMU"}},
		{"planned_fault_diagnostic_linux.go", "plannedDataRefusalDiagnosticQEMU", []string{
			"plannedAccessStageDiagnosticQEMU", "plannedAccessContextDiagnosticQEMU", "plannedAccessCostDiagnosticQEMU",
			"plannedDataFailureDiagnosticQEMU", "plannedDataCostDiagnosticQEMU", "plannedCheckCostDiagnosticQEMU",
		}},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), caller.file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found, calls := false, make(map[string]int)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != caller.function {
				continue
			}
			found = true
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if ok {
					name, ok := call.Fun.(*ast.Ident)
					if ok {
						calls[name.Name]++
					}
				}
				return true
			})
		}
		for _, callee := range caller.callees {
			if !found || calls[callee] != 1 {
				t.Errorf("%s must call %s exactly once; found=%t calls=%d", caller.function, callee, found, calls[callee])
			}
		}
	}
}

func TestPlannedDataDiagnosticsDoNotInventObservationsOrSerializeCause(t *testing.T) {
	private := errors.New("private-cause-must-not-be-logged")
	for _, err := range []error{nil, private, context.DeadlineExceeded,
		errors.Join(private, context.Canceled, runtimebundle.ErrReviewRequired)} {
		if got := plannedDataRefusalDiagnosticQEMU(err); got != "" {
			t.Fatalf("untyped refusal or success invented data observations: %q", got)
		}
	}
	cause := errors.Join(private, context.DeadlineExceeded, runtimebundle.ErrReviewRequired)
	const want = "PHANTOWD_QEMU_PLANNED_FAULT_FAILURE phase=data deadline=true review=true scope=diagnostic-only\n"
	if got := plannedFaultFailureDiagnosticQEMU("data", cause); got != want {
		t.Fatalf("shared formatter changed or disclosed original fault classification: %q", got)
	}
	if !errors.Is(cause, private) || !errors.Is(cause, context.DeadlineExceeded) || !errors.Is(cause, runtimebundle.ErrReviewRequired) {
		t.Fatal("formatting changed the original refusal")
	}
}
