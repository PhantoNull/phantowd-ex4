// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestVolumeRegistryOperatorProcess(t *testing.T) {
	if os.Getenv("PHANTOWD_REGISTRY_OPERATOR_TEST") != "1" {
		return
	}
	args := append([]string{"phantowd-api"}, flag.Args()...)
	flag.CommandLine = flag.NewFlagSet("phantowd-api", flag.ExitOnError)
	os.Args = args
	main()
	os.Exit(0)
}

func operatorRegistryCommand(t *testing.T, directory *os.File, document []byte, args ...string) (string, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestVolumeRegistryOperatorProcess$", "--"}, args...)...)
	command.Env = []string{"PHANTOWD_REGISTRY_OPERATOR_TEST=1"}
	if coverage := os.Getenv("GOCOVERDIR"); coverage != "" {
		command.Env = append(command.Env, "GOCOVERDIR="+coverage)
	}
	if directory != nil {
		command.ExtraFiles = []*os.File{directory}
	}
	command.Stdin = bytes.NewReader(document)
	var output, diagnostic bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostic
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatal("operator command exceeded its test deadline")
	}
	return output.String(), diagnostic.String(), err
}

func operatorRegistryFixture(t *testing.T) (*os.File, volumeregistry.Document) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { directory.Close() })
	return directory, volumeregistry.Document{
		Format: volumeregistry.Format, SchemaVersion: volumeregistry.SchemaVersion, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "operator-books", FilesystemUUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}},
	}
}

func operatorRegistryPayload(t *testing.T, document volumeregistry.Document) []byte {
	t.Helper()
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestVolumeRegistryOperatorPersistsExplicitClaims(t *testing.T) {
	directory, wanted := operatorRegistryFixture(t)
	output, diagnostic, err := operatorRegistryCommand(t, directory, operatorRegistryPayload(t, wanted),
		"--commit-volume-registry", "--expected-registry-revision=0")
	if err != nil || output != "revision=1 claims=1\n" || diagnostic != "" {
		t.Fatalf("operator commit failed: output=%q diagnostic=%q error=%v", output, diagnostic, err)
	}
	reader, err := volumeregistry.Open(directory)
	if err != nil {
		t.Fatal("committed registry could not be reopened", err)
	}
	defer reader.Close()
	snapshot, err := reader.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	actual, err := snapshot.Claims()
	if err != nil || actual.Revision != wanted.Revision || len(actual.Volumes) != 1 || actual.Volumes[0] != wanted.Volumes[0] {
		t.Fatal("operator's explicit claims did not persist", actual, err)
	}
}

func TestVolumeRegistryOperatorRespectsReaderThenAppends(t *testing.T) {
	directory, first := operatorRegistryFixture(t)
	if output, diagnostic, err := operatorRegistryCommand(t, directory, operatorRegistryPayload(t, first),
		"--commit-volume-registry", "--expected-registry-revision=0"); err != nil {
		t.Fatal(output, diagnostic, err)
	}
	reader, err := volumeregistry.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	snapshot, err := reader.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := first
	next.Revision = 2
	next.Volumes = append(append([]shareconfig.Volume{}, first.Volumes...), shareconfig.Volume{
		ID: "operator-audio", FilesystemUUID: "11111111-2222-3333-4444-555555555555"})
	payload := operatorRegistryPayload(t, next)
	output, diagnostic, err := operatorRegistryCommand(t, directory, payload,
		"--commit-volume-registry", "--expected-registry-revision=1")
	if err == nil || output != "" || !strings.Contains(diagnostic, "registry state busy") {
		t.Fatal("operator disturbed a protected reader", output, diagnostic, err)
	}
	if err := reader.Recheck(context.Background(), snapshot); err != nil {
		t.Fatal("refused operator invalidated existing reader", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	output, diagnostic, err = operatorRegistryCommand(t, directory, payload,
		"--commit-volume-registry", "--expected-registry-revision=1")
	if err != nil || output != "revision=2 claims=2\n" || diagnostic != "" {
		t.Fatal("explicit append failed", output, diagnostic, err)
	}
	reopened, err := volumeregistry.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	observed, err := reopened.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	actual, err := observed.Claims()
	if err != nil || actual.Revision != 2 || len(actual.Volumes) != 2 {
		t.Fatal("append did not persist", actual, err)
	}
	bindings := make(map[shareconfig.VolumeID]shareconfig.FilesystemUUID)
	for _, volume := range actual.Volumes {
		bindings[volume.ID] = volume.FilesystemUUID
	}
	for _, volume := range next.Volumes {
		if bindings[volume.ID] != volume.FilesystemUUID {
			t.Fatal("append changed an explicit binding")
		}
	}
}

func TestVolumeRegistryOperatorPreservesCommittedClaimsOnRefusal(t *testing.T) {
	for _, mutation := range []string{"remove", "rename", "rebind", "stale"} {
		t.Run(mutation, func(t *testing.T) {
			directory, initial := operatorRegistryFixture(t)
			if _, diagnostic, err := operatorRegistryCommand(t, directory, operatorRegistryPayload(t, initial),
				"--commit-volume-registry", "--expected-registry-revision=0"); err != nil {
				t.Fatal(diagnostic, err)
			}
			next := initial
			next.Revision = 2
			next.Volumes = append([]shareconfig.Volume{}, initial.Volumes...)
			expected, refusal := "1", "registry commit refused"
			switch mutation {
			case "remove":
				next.Volumes = []shareconfig.Volume{}
			case "rename":
				next.Volumes[0].ID = "different-logical-id"
			case "rebind":
				next.Volumes[0].FilesystemUUID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"
			case "stale":
				next.Revision = 1
				expected, refusal = "0", "registry revision conflict"
			}
			output, diagnostic, err := operatorRegistryCommand(t, directory, operatorRegistryPayload(t, next),
				"--commit-volume-registry", "--expected-registry-revision="+expected)
			if err == nil || output != "" || !strings.Contains(diagnostic, refusal) {
				t.Fatal("operator accepted identity mutation", output, diagnostic, err)
			}
			reader, err := volumeregistry.Open(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			snapshot, err := reader.Read(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			actual, err := snapshot.Claims()
			if err != nil || actual.Revision != 1 || len(actual.Volumes) != 1 || actual.Volumes[0] != initial.Volumes[0] {
				t.Fatal("refused mutation changed committed claims", actual, err)
			}
		})
	}
}

func TestVolumeRegistryOperatorInvalidInvocationHasNoWritesOrInputEcho(t *testing.T) {
	for _, refusal := range []string{"no-grant", "missing-revision", "noncanonical-revision", "wrong-next",
		"malformed", "oversized", "mixed-mode", "orphan-revision", "unsafe-directory"} {
		t.Run(refusal, func(t *testing.T) {
			directory, document := operatorRegistryFixture(t)
			payload := operatorRegistryPayload(t, document)
			grant := directory
			args := []string{"--commit-volume-registry", "--expected-registry-revision=0"}
			message := "invalid explicit registry document"
			switch refusal {
			case "no-grant":
				grant, message = nil, "inherited registry directory unavailable"
			case "missing-revision":
				args, message = args[:1], "invalid explicit registry revision"
			case "noncanonical-revision":
				args[1], message = "--expected-registry-revision=00", "invalid explicit registry revision"
			case "wrong-next":
				document.Revision = 2
				payload = operatorRegistryPayload(t, document)
			case "malformed":
				payload = []byte("PRIVATE_OPERATOR_INPUT_DO_NOT_ECHO")
			case "oversized":
				payload = append(payload, bytes.Repeat([]byte(" "), volumeregistry.MaxInputBytes)...)
			case "mixed-mode":
				args, message = append(args, "--storage-broker"), "unexpected arguments"
			case "orphan-revision":
				args, message = args[1:], "registry revision requires commit mode"
			case "unsafe-directory":
				if err := os.Chmod(directory.Name(), 0755); err != nil {
					t.Fatal(err)
				}
				message = "registry state unavailable"
			}
			output, diagnostic, err := operatorRegistryCommand(t, grant, payload, args...)
			if err == nil || output != "" || !strings.Contains(diagnostic, message) ||
				strings.Contains(diagnostic, directory.Name()) || strings.Contains(diagnostic, "PRIVATE_OPERATOR_INPUT_DO_NOT_ECHO") {
				t.Fatal("unsafe operator refusal", output, diagnostic, err)
			}
			files, err := os.ReadDir(directory.Name())
			if err != nil || len(files) != 0 {
				t.Fatal("invalid invocation changed registry directory", files, err)
			}
		})
	}
}
