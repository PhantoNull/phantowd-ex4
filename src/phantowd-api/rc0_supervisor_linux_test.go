// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

func TestRC0OpenRoleRefusesSymlinksAndUsesOriginalRoot(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root := mustOpenRC0Fixture(t, dir)
	if err := os.Mkdir(filepath.Join(dir, "accounts"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("accounts", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, filepath.Join(base, "retained")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	role, err := openRC0Role(root, "accounts", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		t.Fatalf("original state root was not retained: %v", err)
	}
	defer role.Close()
	if role, err := openRC0Role(root, "link", unix.O_PATH|unix.O_DIRECTORY); err == nil {
		role.Close()
		t.Fatal("symbolic link accepted as a state role")
	}
}

func TestRC0PolicyAdmissionRequiresIndependentExactConfirmation(t *testing.T) {
	const installation = "c71c2ba76bd04d29816335c13c31a380"
	dir := privateProvisioningDirectory(t)
	root := mustOpenRC0Fixture(t, dir)
	policy := naspolicy.Config{
		Format: naspolicy.Format, SchemaVersion: 1, Revision: 1,
		FileServices: fileservice.Config{
			Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1,
			Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
				Volumes: []shareconfig.Volume{}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}},
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1, Exports: []nfsconfig.Export{}},
		},
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
			Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}},
	}
	known, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := naspolicystore.ProvisionInitial(root, installation, known); err != nil {
		t.Fatal(err)
	}
	role := mustOpenRC0Fixture(t, filepath.Join(dir, "nas-policy"))
	current := mustOpenRC0Fixture(t, filepath.Join(dir, "nas-policy", "nas-services.json"))
	var info unix.Stat_t
	if err := unix.Fstat(int(current.Fd()), &info); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if owner, err := admitRC0Policy(ctx, role, installation, known, info); owner != nil || err == nil {
		t.Fatal("current policy was accepted as its own confirmation")
	}
	proofPath := filepath.Join(t.TempDir(), "separate-proof.json")
	if err := os.WriteFile(proofPath, known, 0600); err != nil {
		t.Fatal(err)
	}
	proof := mustOpenRC0Fixture(t, proofPath)
	confirmed, info, err := readPrivateStartupFile(proof, uint32(os.Geteuid()), naspolicy.MaxInputBytes)
	if err != nil {
		t.Fatal(err)
	}
	if owner, err := admitRC0Policy(ctx, role, installation, append(confirmed, '\n'), info); owner != nil || err == nil {
		t.Fatal("different confirmation bytes were accepted")
	}
	owner, err := admitRC0Policy(ctx, role, installation, confirmed, info)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if snapshot, err := owner.Snapshot(ctx); err != nil || snapshot.Revision != 1 {
		t.Fatalf("original policy was not admitted: %v", err)
	}
}

func TestManagementAPIPeerRequiresExpectedProcessAndCredentials(t *testing.T) {
	dir, err := os.MkdirTemp("", "rc0-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(dir) })
	addr := &net.UnixAddr{Name: filepath.Join(dir, "channel"), Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	pid, uid, gid := os.Getpid(), uint32(os.Getuid()), uint32(os.Getgid())
	if !managementAPIPeer(peer, pid, uid, gid) || managementAPIPeer(peer, pid+1, uid, gid) ||
		managementAPIPeer(peer, pid, uid+1, gid) || managementAPIPeer(peer, pid, uid, gid+1) {
		t.Fatal("wrong peer credentials admitted or original rejected")
	}
}

func mustOpenRC0Fixture(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return file
}
