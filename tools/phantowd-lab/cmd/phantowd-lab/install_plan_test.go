// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInstallPlanCLIAdmitsVersionsBeforeOpeningFiles(t *testing.T) {
	base := []string{"plan-install", "--manifest", "not-opened", "--signature", "not-opened", "--public-key", "not-opened",
		"--artifacts", "not-opened", "--model", "wd-my-cloud-ex4", "--revision", "board-r1", "--channel", "nightly"}
	for _, versions := range [][2]string{{"", "v0.0.9"}, {"invalid", ""}, {"v0.1.0", "invalid"}} {
		args := append(append([]string(nil), base...), "--installer-version", versions[0], "--current-version", versions[1])
		var output bytes.Buffer
		code, err := run(args, &output)
		if code != 1 || err == nil || output.Len() != 0 || !strings.Contains(err.Error(), "version") || strings.Contains(err.Error(), "not-opened") {
			t.Fatal("CLI opened files or emitted a partial plan before version admission", code, err)
		}
	}
}
