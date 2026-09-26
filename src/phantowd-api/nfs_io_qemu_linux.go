//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func exerciseQEMUNFSMount(mode string) error {
	relative, client := qemuNFSWritablePath, "rw-client"
	if mode == "mount-ro" {
		relative, client = "read-only", "ro-client"
	} else if mode == "denied-client" {
		relative, client = "denied-client", "denied-client"
	} else if mode != "mount-rw" && mode != "guard" {
		return errors.New("unknown NFS mount probe")
	}
	source := "127.0.0.1:/srv/phantowd/volumes/" + qemuNFSVolumeUUID + "/" + relative
	target := "/srv/phantowd-nfs-policy-smoke/" + client
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// No shell, no user-supplied arguments, no background mount retries.
	command := exec.CommandContext(ctx, "/sbin/mount.nfs", source, target, "-o", "vers=3,proto=tcp,sec=sys,nolock,rw,soft,timeo=5,retrans=1,retry=0")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	if mode == "mount-rw" || mode == "mount-ro" {
		if err != nil {
			return fmt.Errorf("NFS fixture mount %s failed: %s", mode, strings.TrimSpace(string(output)))
		}
		return nil
	}
	if err == nil {
		// Never leave an unexpectedly accepted negative-test mount behind.
		_ = syscall.Unmount(target, 0)
		return errors.New("NFS negative-test mount unexpectedly succeeded")
	}
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) {
		return errors.New("NFS negative-test probe did not receive a server rejection")
	}
	text := string(output)
	denied := strings.Contains(text, "access denied by server")
	if mode == "guard" {
		denied = denied || strings.Contains(text, "reason given by server: No such file or directory")
	}
	if !denied {
		return fmt.Errorf("NFS negative-test probe failed for an unexpected reason: %s", strings.TrimSpace(text))
	}
	return nil
}

// Paths exist only inside the disposable QEMU fixture, never selected by API
// input. Both client mounts are rw: EROFS must come from the server export.
func exerciseQEMUNFSIO() error {
	const workspace = "/srv/phantowd-nfs-policy-smoke"
	const anchor = "/srv/phantowd/volumes/" + qemuNFSVolumeUUID
	payload := []byte("phantowd-generated-nfs-policy-v1\n")
	client := filepath.Join(workspace, "rw-client", "created")
	file, err := os.OpenFile(client, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("generated NFS rw export rejected file creation")
	}
	_, writeErr := file.Write(payload)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("generated NFS write/sync/close failed")
	}
	server := filepath.Join(anchor, qemuNFSWritablePath, "created")
	content, err := os.ReadFile(server)
	if err != nil || !bytes.Equal(content, payload) {
		return errors.New("generated NFS server-side content mismatch")
	}
	info, err := os.Lstat(server)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("generated NFS server-side file is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 101000 || stat.Gid != 101000 {
		return errors.New("generated NFS anonymous UID/GID mapping mismatch")
	}
	content, err = os.ReadFile(filepath.Join(workspace, "ro-client", "marker"))
	if err != nil || string(content) != "phantowd-nfs-ro-marker\n" {
		return errors.New("generated NFS read-only export cannot be read")
	}
	denied := filepath.Join(workspace, "ro-client", "must-not-exist")
	file, err = os.OpenFile(denied, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, syscall.EROFS) {
		return errors.New("generated NFS ro export did not deny write with EROFS")
	}
	if _, err := os.Lstat(filepath.Join(anchor, "read-only", "must-not-exist")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("generated NFS rejected write left a server-side file")
	}
	return nil
}
