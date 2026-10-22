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
	"testing/synctest"
	"time"
)

func TestPlannedFixedBudgetsExpireAndCancel(t *testing.T) {
	for _, profile := range []struct {
		name string
		open func() (context.Context, context.CancelFunc)
		want time.Duration
	}{
		{"data", plannedDataContextQEMU, 40 * time.Second},
		{"fault-subprocess", plannedFaultContextQEMU, 120 * time.Second},
	} {
		t.Run(profile.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := time.Now()
				ctx, cancel := profile.open()
				defer cancel()
				deadline, ok := ctx.Deadline()
				if !ok || deadline.Sub(started) != profile.want {
					t.Fatalf("fixed deadline=%v, want %v", deadline.Sub(started), profile.want)
				}
				time.Sleep(profile.want - time.Nanosecond)
				if ctx.Err() != nil {
					t.Fatal("fixture expired before its fixed deadline")
				}
				<-ctx.Done()
				if !errors.Is(ctx.Err(), context.DeadlineExceeded) || time.Since(started) != profile.want {
					t.Fatalf("fixed deadline not enforced: elapsed=%v error=%v", time.Since(started), ctx.Err())
				}
			})
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := profile.open()
				cancel()
				if !errors.Is(ctx.Err(), context.Canceled) {
					t.Fatal("explicit cancellation ignored")
				}
			})
		})
	}
}

// Wiring is checked separately: exercising a detached timer would not cover
// the actual orchestration. Full guest checks remain the integration evidence.
func TestPlannedFixedBudgetsUseRealCallsites(t *testing.T) {
	for _, site := range []struct{ file, caller, callee string }{
		{"planned_startup_linux.go", "nativePlannedServiceFixtureQEMU", "plannedDataContextQEMU"},
		{"planned_source_fault_linux.go", "nativePlannedFaultSubprocessQEMU", "plannedFaultContextQEMU"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), site.file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != site.caller {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if ok {
					name, ok := call.Fun.(*ast.Ident)
					if ok && name.Name == site.callee {
						calls++
						if len(call.Args) != 0 {
							t.Fatal("caller-selectable fixture deadline")
						}
					}
				}
				return true
			})
		}
		if calls != 1 {
			t.Errorf("%s must call %s once, got %d", site.caller, site.callee, calls)
		}
	}
}
