//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestServerCaptureProfileSeparatesFixedReadOnlyAuthenticatedDocuments(t *testing.T) {
	old := serverObserverDocumentsQEMU()
	docs := serverCaptureDocumentsQEMU()
	for _, name := range []string{"passwd", "group", "nsswitch.conf"} {
		if docs[name] != old[name] {
			t.Fatal("capture changed the fixed Unix identity boundary")
		}
	}
	configuration := docs["samba/smb.conf"]
	for _, required := range []string{"server min protocol = SMB3_02\n", "server max protocol = SMB3_11\n",
		"server signing = mandatory\n", "[readonly]\n", "read only = yes\n", "guest ok = no\n",
		"valid users = nobody\n", "vfs objects = phantowd_open_qemu\n"} {
		if !strings.Contains(configuration, required) {
			t.Fatal("fixed authenticated capture requirement missing", required)
		}
	}
	if len(docs) != 4 || strings.Contains(old["samba/smb.conf"], "phantowd_open_qemu") ||
		!strings.Contains(old["samba/smb.conf"], "server max protocol = SMB3_02\n") {
		t.Fatal("old negotiated-only profile was widened")
	}
	docs["passwd"] = "caller replacement"
	if serverCaptureDocumentsQEMU()["passwd"] != old["passwd"] {
		t.Fatal("caller changed later fixed construction documents")
	}
}

func TestServerCaptureRuntimeRefusesHostBeforeCollectingOriginals(t *testing.T) {
	if serverObserverCodeGuardQEMU() == nil {
		t.Skip("host refusal; actual lifetime separately tested in guest")
	}
	plan, err := NewPlan([]File{exampleFile("usr/sbin/smbd")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		owned, err := newServerCaptureRuntimeQEMU(context.Background(), plan, caller, caller, caller, [2]*os.File{caller, caller})
		if owned != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("host acquired capture runtime", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("refusal leaked descriptors", err)
	}
	if _, err := caller.Stat(); err != nil {
		t.Fatal("caller consumed on refusal", err)
	}
}
