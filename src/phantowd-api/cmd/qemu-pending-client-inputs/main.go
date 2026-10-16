//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Fixed disposable fixture metadata/staging/retention only. Never product init.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

type fixtureFile = runtimebundle.PendingExpectedFileQEMU
type fixtureManifest = runtimebundle.PendingExpectedManifestQEMU

func decodeManifest(data []byte) (fixtureManifest, error) {
	return runtimebundle.DecodePendingExpectedQEMU(data)
}

func plan(files []fixtureFile, aliases []runtimebundle.Alias) (*runtimebundle.Plan, error) {
	return runtimebundle.PendingExpectedPlanQEMU(files, aliases)
}

func root(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "fixed-pending-fixture-root"), nil
}

func run() error {
	// Fixed metadata-only host mode has no filesystem reads or runtime authority.
	if len(os.Args) == 2 && os.Args[1] == "documents" {
		return json.NewEncoder(os.Stdout).Encode(runtimebundle.PendingClientDocumentsQEMU())
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" || os.Getuid() != 0 || os.Geteuid() != 0 ||
		os.Getgid() != 0 || os.Getegid() != 0 || len(os.Args) != 2 ||
		(os.Args[1] != "stage" && os.Args[1] != "retain" && os.Args[1] != "preclose-input-loss") {
		return errors.New("fixture guard")
	}
	file, err := os.Open("/usr/lib/phantowd/qemu-pending-client-inputs.json")
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	if closeErr := file.Close(); readErr != nil || closeErr != nil || len(data) > 128<<10 {
		return errors.New("fixture manifest budget")
	}
	manifest, err := decodeManifest(data)
	if err != nil {
		return err
	}
	client, err := plan(manifest.RootFiles, manifest.RootAliases)
	if err != nil {
		return err
	}
	bootstrap, err := plan(manifest.BootstrapFiles, nil)
	if err != nil {
		return err
	}
	clientRoot, err := root("/run/phantowd-pending-client-input")
	if err != nil {
		return err
	}
	defer clientRoot.Close()
	bootstrapRoot, err := root("/run/phantowd-pending-client-bootstrap")
	if err != nil {
		return err
	}
	defer bootstrapRoot.Close()
	if os.Args[1] == "stage" {
		source, err := root("/usr/lib/phantowd/pending-source")
		if err != nil {
			return err
		}
		defer source.Close()
		if err := client.StageQEMU(context.Background(), source, clientRoot); err != nil {
			return err
		}
		return bootstrap.StageQEMU(context.Background(), source, bootstrapRoot)
	}
	if os.Args[1] == "preclose-input-loss" {
		return client.ProbePendingClientOwnerInputLossQEMU(context.Background(), bootstrap, clientRoot, bootstrapRoot)
	}
	if err := client.ProbePendingClientInputsQEMU(context.Background(), bootstrap, clientRoot, bootstrapRoot); err != nil {
		return err
	}
	return client.ProbePendingClientOwnerQEMU(context.Background(), bootstrap, clientRoot, bootstrapRoot)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_PENDING_INPUTS_FAILED")
		os.Exit(1)
	}
}
