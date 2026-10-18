// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAPIStartupRejectsOptionsBeforeStateOpen(t *testing.T) {
	const childVariable = "PHANTOWD_STARTUP_PREFLIGHT_CHILD"
	const rootVariable = "PHANTOWD_STARTUP_PREFLIGHT_ROOT"
	if os.Getenv(childVariable) == "1" {
		root := os.Getenv(rootVariable)
		state := filepath.Join(root, "not-account-storage")
		info, err := os.Lstat(state)
		if !filepath.IsAbs(root) || !strings.HasPrefix(root, filepath.Clean(os.TempDir())+string(os.PathSeparator)) ||
			err != nil || !info.Mode().IsRegular() || info.Size() != 1 ||
			(os.Getenv("PHANTOWD_STATE_DIR") != "" && os.Getenv("PHANTOWD_STATE_DIR") != state) {
			t.Fatal("startup child requires its own regular-file fixture, never a state directory")
		}
		// Call the actual command entry point, with no experimental modes and
		// no ability to open a state directory or successfully start a listener.
		flag.CommandLine = flag.NewFlagSet("startup-fixture", flag.ExitOnError)
		os.Args = []string{"startup-fixture"}
		main()
		t.Fatal("invalid startup unexpectedly returned")
	}
	if os.Geteuid() == 0 {
		t.Skip("the unchanged root refusal precedes the non-root startup path")
	}
	root := t.TempDir()
	state := filepath.Join(root, "not-account-storage")
	if err := os.WriteFile(state, []byte{'x'}, 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, expected string
		environment    []string
	}{
		{"bad-listener", "API transport configuration is invalid", []string{"PHANTOWD_LISTEN_ADDR=not-an-address"}},
		{"unpaired-tls", "API transport configuration is invalid", []string{"PHANTOWD_TLS_CERT_FILE=" + filepath.Join(root, "not-a-certificate")}},
		{"two-policy-authorities", "service configuration options are invalid", []string{
			"PHANTOWD_SHARE_STATE_DIR=" + filepath.Join(root, "shares"),
			"PHANTOWD_SERVICE_STATE_DIR=" + filepath.Join(root, "services"),
		}},
		{"valid-options-reach-state-refusal", "account state is unavailable or insecure", nil},
		{"missing-account-option", "account state directory is not configured", []string{"PHANTOWD_STATE_DIR="}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAPIStartupRejectsOptionsBeforeStateOpen$")
			for _, variable := range os.Environ() {
				if !strings.HasPrefix(strings.ToUpper(variable), "PHANTOWD_") {
					command.Env = append(command.Env, variable)
				}
			}
			command.Env = append(command.Env, childVariable+"=1", rootVariable+"="+root, "PHANTOWD_STATE_DIR="+state)
			command.Env = append(command.Env, test.environment...)
			output, err := command.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || ctx.Err() != nil || !strings.Contains(string(output), test.expected) ||
				strings.Contains(string(output), root) {
				t.Fatalf("startup did not refuse at the expected fixed boundary: %v, %q", err, output)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(state) {
				t.Fatal("startup touched synthetic storage entries")
			}
			contents, err := os.ReadFile(state)
			if err != nil || string(contents) != "x" {
				t.Fatal("startup changed the regular-file fixture")
			}
		})
	}
}
