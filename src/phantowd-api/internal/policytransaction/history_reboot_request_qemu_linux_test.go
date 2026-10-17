//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"strings"
	"testing"
)

type historyRebootRequest struct {
	phase, nonce, root, previous string
}

func validHistoryBootID(id string) bool {
	return len(id) == 36 && id[8] == '-' && id[13] == '-' && id[18] == '-' && id[23] == '-' && validChallenge(strings.ReplaceAll(id, "-", ""))
}

func decodeHistoryRebootRequest(line string) (historyRebootRequest, error) {
	if len(line) > 4096 {
		return historyRebootRequest{}, ErrInvalid
	}
	values := make(map[string]string)
	const prefix = "phantowd_history_reboot_"
	for _, field := range strings.Fields(line) {
		if !strings.HasPrefix(field, prefix) {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(field, prefix), "=")
		if !ok || value == "" || key != "phase" && key != "nonce" && key != "root" && key != "previous" {
			return historyRebootRequest{}, ErrInvalid
		}
		if _, exists := values[key]; exists {
			return historyRebootRequest{}, ErrInvalid
		}
		values[key] = value
	}
	r := historyRebootRequest{values["phase"], values["nonce"], values["root"], values["previous"]}
	if !validChallenge(r.nonce) || r.phase != "produce" && r.phase != "observe" {
		return historyRebootRequest{}, ErrInvalid
	}
	if r.phase == "produce" {
		if len(values) != 2 {
			return historyRebootRequest{}, ErrInvalid
		}
	} else if len(values) != 4 || !validHistoryMediaRoot(r.root) || !validHistoryBootID(r.previous) {
		return historyRebootRequest{}, ErrInvalid
	}
	return r, nil
}

func TestHistoryRebootRequestBindsClosedBootPhase(t *testing.T) {
	const nonce = "11111111222233334444555555555555"
	const boot = "11111111-2222-3333-4444-555555555555"
	const root = historyExt4Root + "/phantowd-transaction-fixed"
	produce := "console=ttyAMA0 phantowd_history_reboot_phase=produce phantowd_history_reboot_nonce=" + nonce
	observe := "phantowd_history_reboot_phase=observe phantowd_history_reboot_nonce=" + nonce + " phantowd_history_reboot_root=" + root + " phantowd_history_reboot_previous=" + boot
	for _, line := range []string{produce, observe} {
		r, err := decodeHistoryRebootRequest(line)
		if err != nil || r.nonce != nonce || (r.phase == "produce" && (r.root != "" || r.previous != "")) || (r.phase == "observe" && (r.root != root || r.previous != boot)) {
			t.Fatal("closed reboot request refused", err)
		}
	}
	for _, bad := range []string{"", "phantowd_history_reboot_phase=produce", produce + " phantowd_history_reboot_phase=produce",
		produce + " phantowd_history_reboot_nonce=" + nonce, produce + " phantowd_history_reboot_root=" + root,
		produce + " phantowd_history_reboot_previous=" + boot, produce + " phantowd_history_reboot_foreign=1",
		strings.Replace(observe, "phase=observe", "phase=resume", 1), strings.Replace(observe, root, "/tmp/phantowd-transaction-fixed", 1),
		strings.Replace(observe, boot, strings.ToUpper(boot[:8])+"x"+boot[9:], 1), strings.Replace(observe, nonce, strings.Repeat("0", 32), 1),
		strings.Repeat("x", 4097)} {
		if _, err := decodeHistoryRebootRequest(bad); err != ErrInvalid {
			t.Fatal("invalid boot request admitted")
		}
	}
}
