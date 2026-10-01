//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// testparm validates the combined internal plan in a private temporary file.
// No live Samba configuration is read, overwritten or reloaded. Host-side
// QEMU-tagged contract tests skip the native parser; the ARMv5 guest executes it.
func validateQEMUPlanSambaWithTestparm(candidate, volumeID string) error {
	if runtime.GOARCH != "arm" || strings.Split(buildARMLevel(), ",")[0] != "5" {
		return nil
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("QEMU combined Samba parser requires the Versatile PB guest")
	}
	dir, err := os.MkdirTemp("", "phantowd-file-service-plan-")
	if err != nil {
		return errors.New("QEMU plan parser fixture could not create temporary directory")
	}
	defer os.RemoveAll(dir)
	name := filepath.Join(dir, "smb.conf")
	const global = "[global]\n    server role = standalone server\n    security = user\n    map to guest = Never\n    interfaces = lo\n    bind interfaces only = yes\n    server min protocol = SMB3_00\n    server max protocol = SMB3_11\n    load printers = no\n    printing = bsd\n    printcap name = /dev/null\n"
	if err := os.WriteFile(name, []byte(global+candidate), 0600); err != nil {
		return errors.New("QEMU plan parser fixture could not write temporary candidate")
	}
	for _, parameter := range []struct{ name, want string }{
		{"path", shareconfig.VolumeMountRoot + "/" + volumeID + "/books"},
		{"valid users", "alice"}, {"write list", "alice"}, {"read only", "Yes"}, {"guest ok", "No"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		command := exec.CommandContext(ctx, "/usr/bin/testparm", "-s", "--section-name=Books", "--parameter-name="+parameter.name, name)
		output, commandErr := command.Output()
		cancel()
		if commandErr != nil || strings.TrimSpace(string(output)) != parameter.want {
			return fmt.Errorf("QEMU combined Samba plan failed testparm policy check: %s", parameter.name)
		}
	}
	return nil
}
