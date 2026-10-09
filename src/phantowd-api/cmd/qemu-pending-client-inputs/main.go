//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Fixed disposable fixture metadata/staging/retention only. Never product init.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

type fixtureFile struct {
	Path, SHA256 string
	Size         int64
	Mode         uint32
}

type fixtureManifest struct {
	Format         string
	RootFiles      []fixtureFile
	RootAliases    []runtimebundle.Alias
	BootstrapFiles []fixtureFile
}

func decodeManifest(data []byte) (fixtureManifest, error) {
	var manifest fixtureManifest
	if len(data) > 128<<10 {
		return manifest, errors.New("fixture manifest budget")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Format != "phantowd-qemu-pending-client-inputs-v1" {
		return fixtureManifest{}, errors.New("fixture manifest")
	}
	return manifest, nil
}

func plan(files []fixtureFile, aliases []runtimebundle.Alias) (*runtimebundle.Plan, error) {
	var result []runtimebundle.File
	for _, file := range files {
		decoded, err := hex.DecodeString(file.SHA256)
		if err != nil || len(decoded) != 32 {
			return nil, errors.New("fixture digest")
		}
		var digest [32]byte
		copy(digest[:], decoded)
		result = append(result, runtimebundle.File{Path: file.Path, SHA256: digest, Size: file.Size, Mode: file.Mode})
	}
	return runtimebundle.NewPlan(result, aliases)
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
		os.Getgid() != 0 || os.Getegid() != 0 || len(os.Args) != 2 || (os.Args[1] != "stage" && os.Args[1] != "retain") {
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
	return client.ProbePendingClientInputsQEMU(context.Background(), bootstrap, clientRoot, bootstrapRoot)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_PENDING_INPUTS_FAILED")
		os.Exit(1)
	}
}
