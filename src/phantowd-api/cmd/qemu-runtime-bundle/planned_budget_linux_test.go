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
	"os"
	"strings"
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
		{"supervision", plannedSupervisionContextQEMU, 40 * time.Second},
		{"fault-subprocess", plannedFaultContextQEMU, 150 * time.Second},
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
		{"planned_startup_linux.go", "nativePlannedServiceFixtureQEMU", "plannedSupervisionContextQEMU"},
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

// A counted call alone could be detached from the actual action. Check the
// returned context, its cancellation and every fixed qualifier consumer too.
// This structural guard supplements, never replaces, real ARM guest evidence.
func plannedSupervisionWiredForTestQEMU(source []byte) bool {
	file, err := parser.ParseFile(token.NewFileSet(), "planned_startup_linux.go", source, 0)
	if err != nil {
		return false
	}
	ident := func(expression ast.Expr, want string) bool {
		name, ok := expression.(*ast.Ident)
		return ok && name.Name == want
	}
	wired := 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "nativePlannedServiceFixtureQEMU" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			block, ok := node.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for index, statement := range block.List {
				assignment, ok := statement.(*ast.AssignStmt)
				if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 ||
					!ident(assignment.Lhs[0], "superviseCtx") || !ident(assignment.Lhs[1], "cancelSupervise") {
					continue
				}
				constructor, ok := assignment.Rhs[0].(*ast.CallExpr)
				if !ok || !ident(constructor.Fun, "plannedSupervisionContextQEMU") || len(constructor.Args) != 0 || index+2 >= len(block.List) {
					continue
				}
				cancellation, ok := block.List[index+1].(*ast.DeferStmt)
				if !ok || !ident(cancellation.Call.Fun, "cancelSupervise") || len(cancellation.Call.Args) != 0 {
					continue
				}
				rebind, ok := block.List[index+2].(*ast.AssignStmt)
				if !ok || rebind.Tok != token.ASSIGN || len(rebind.Lhs) != 1 || len(rebind.Rhs) != 1 ||
					!ident(rebind.Lhs[0], "ctx") || !ident(rebind.Rhs[0], "superviseCtx") {
					continue
				}
				consumers := map[string]int{
					"qualify": 0, "qualifyPlannedOpenFileQEMU": 0,
					"qualifyPlannedHeldCancellationQEMU": 0, "qualifyPlannedSupervisionQEMU": 0,
				}
				detached := false
				for _, remaining := range block.List[index+3:] {
					ast.Inspect(remaining, func(node ast.Node) bool {
						if assignment, ok := node.(*ast.AssignStmt); ok {
							for _, target := range assignment.Lhs {
								if ident(target, "ctx") {
									detached = true
								}
							}
						}
						call, ok := node.(*ast.CallExpr)
						if !ok {
							return true
						}
						name, ok := call.Fun.(*ast.Ident)
						if !ok {
							return true
						}
						if _, required := consumers[name.Name]; required {
							if len(call.Args) == 0 || !ident(call.Args[0], "ctx") {
								detached = true
							} else {
								consumers[name.Name]++
							}
						}
						return true
					})
				}
				for _, count := range consumers {
					if count != 1 {
						detached = true
					}
				}
				if !detached {
					wired++
				}
			}
			return true
		})
	}
	return wired == 1
}

func TestPlannedSupervisionContextFeedsRealQualifiers(t *testing.T) {
	source, err := os.ReadFile("planned_startup_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if !plannedSupervisionWiredForTestQEMU(source) {
		t.Fatal("fixed supervision context is detached from cancellation or qualifiers")
	}
	for _, mutation := range []struct{ name, old, replacement string }{
		{"inline-timer", "superviseCtx, cancelSupervise := plannedSupervisionContextQEMU()", "superviseCtx, cancelSupervise := context.WithTimeout(context.Background(), 20*time.Second)"},
		{"wrong-context", "ctx = superviseCtx", "ctx = context.Background()"},
		{"wrong-cancel", "defer cancelSupervise()", "defer cancel()"},
		{"detached-qualifier", "qualify(ctx, service, runtime, owner, handoff)", "qualify(context.Background(), service, runtime, owner, handoff)"},
		{"late-rebind", "phase = \"supervision\"", "ctx = context.Background(); phase = \"supervision\""},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := strings.Replace(string(source), mutation.old, mutation.replacement, 1)
			if changed == string(source) {
				t.Fatal("negative control did not mutate the actual source")
			}
			if plannedSupervisionWiredForTestQEMU([]byte(changed)) {
				t.Fatal("detached supervision control accepted")
			}
		})
	}
}
