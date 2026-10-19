//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle_test

import (
	"io"
	"os"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

// Explicit host integration only. The bounded validation harness owns a private
// TMPDIR and generates this fixed report there; no user path/ELF is executed.
func TestNFSExpectedGeneratedBuildArtifact(t *testing.T) {
	if os.Getenv("PHANTOWD_NFS_EXPECTED_FIXTURE") != "1" {
		t.Skip("explicit generated-build metadata fixture not requested")
	}
	root, err := os.OpenRoot(os.TempDir())
	if err != nil {
		t.Fatal("cannot open private fixture root")
	}
	defer root.Close()
	const name = "phantowd-nfs-runtime-candidate.json"
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 128<<10 {
		t.Fatal("fixture report is not a bounded regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		t.Fatal("cannot open generated report")
	}
	after, statErr := file.Stat()
	data, readErr := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	closeErr := file.Close()
	if statErr != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || readErr != nil || closeErr != nil || len(data) != int(before.Size()) {
		t.Fatal("generated report observation failed")
	}
	if plan, err := runtimebundle.NFSExpectedPlanQEMU(data); err != nil || plan == nil {
		t.Fatal("actual generated Buildroot code expectations refused", err)
	}
	t.Log("generated Buildroot NFS expectations accepted; retained_authority=false execution=false")
}
