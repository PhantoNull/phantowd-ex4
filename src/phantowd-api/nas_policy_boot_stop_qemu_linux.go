//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func holdQEMUNASBootProcess(path, command string, uid uint32) (int, int, error) {
	data, err := os.ReadFile(path)
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || parseErr != nil || pid <= 1 {
		return 0, -1, errors.New("boot pidfile refused")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return 0, -1, err
	}
	cmd, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	var st unix.Stat_t
	if err != nil || string(cmd) != command || unix.Stat(fmt.Sprintf("/proc/%d", pid), &st) != nil || st.Uid != uid {
		unix.Close(fd)
		return 0, -1, errors.New("boot process identity refused")
	}
	return pid, fd, nil
}

func pollQEMUNASBootFD(fd, timeout int, dead bool) bool {
	if fd < 0 {
		return false
	}
	p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(p, timeout)
	return err == nil && (dead && n == 1 && p[0].Revents&unix.POLLIN != 0 && p[0].Revents & ^int16(unix.POLLIN|unix.POLLHUP) == 0 || !dead && n == 0)
}

func exerciseQEMUNASBootStop(ctx context.Context, h *qemuNASMainHTTP) error {
	uid, gid, err := qemuIdentityOwnerAPIIdentity()
	if err != nil {
		return err
	}
	api, apiFD, err := holdQEMUNASBootProcess("/run/phantowd-api.pid", "/usr/bin/phantowd-api\x00", uid)
	if err != nil {
		return err
	}
	defer unix.Close(apiFD)
	provider, providerFD, err := holdQEMUNASBootProcess("/run/phantowd-nas-policy-owner.pid", "/usr/bin/phantowd-api\x00--qemu-nas-policy-owner-service\x00", 0)
	if err != nil {
		return err
	}
	defer unix.Close(providerFD)
	poll := pollQEMUNASBootFD
	if !poll(apiFD, 0, false) || !poll(providerFD, 0, false) {
		return errors.New("original boot processes not live")
	}
	if err := exec.CommandContext(ctx, "/etc/init.d/S49phantowd-nas-policy-owner", "stop").Run(); err != nil {
		return fmt.Errorf("provider init stop: %w", err)
	}
	absent := func() bool {
		for _, path := range []string{nasBootRoot + "/channel", nasBootRoot + "/ready", "/run/phantowd-nas-policy-owner.pid", fmt.Sprintf("/proc/%d", provider)} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return false
			}
		}
		return true
	}
	if !poll(providerFD, 0, true) || !poll(apiFD, 0, false) || !absent() {
		return errors.New("provider stop was not verified")
	}
	fmt.Println("PHANTOWD_NAS_BOOT_STOP_READY provider_exited=true api_pid_unchanged=true socket_absent=true pidfile_absent=true readiness_absent=true")
	// A protected replacement only observes pending connections; it never accepts
	// or serves authority. A reconnect would make this listening fd readable.
	probe, err := net.ListenUnix("unix", &net.UnixAddr{Name: nasBootRoot + "/channel", Net: "unix"})
	if err != nil {
		return err
	}
	defer probe.Close()
	if err := errors.Join(os.Chown(nasBootRoot+"/channel", 0, int(gid)), os.Chmod(nasBootRoot+"/channel", 0660)); err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, h.origin+nasStatePath, nil)
		if err != nil {
			return err
		}
		r.Header.Set("Origin", h.origin)
		response, err := h.client.Do(r)
		if err != nil {
			return err
		}
		data, err := readSelfTestResponse(response, 1024)
		var body map[string]string
		if err != nil || response.StatusCode != 503 || response.Header.Get("Retry-After") != "" || response.Header.Get("Cache-Control") != "no-store" ||
			json.Unmarshal(data, &body) != nil || len(body) != 1 || body["error"] != "nas_configuration_reconciliation_required" {
			return errors.New("stopped provider did not return stable reconciliation refusal")
		}
	}
	raw, err := probe.SyscallConn()
	if err != nil {
		return err
	}
	quiet := false
	if err := raw.Control(func(fd uintptr) { quiet = poll(int(fd), 0, false) }); err != nil || !quiet {
		return errors.New("API attempted provider reconnect")
	}
	if err := probe.Close(); err != nil || !absent() || !poll(apiFD, 0, false) {
		return errors.New("stop observation changed original authority")
	}
	pid, err := os.ReadFile("/run/phantowd-api.pid")
	if err != nil || strings.TrimSpace(string(pid)) != strconv.Itoa(api) {
		return errors.New("API pidfile changed")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		cmd, err := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			continue // A process that exited during the census is not a live service.
		}
		if err != nil {
			return err
		}
		program := filepath.Base(strings.Split(string(cmd), "\x00")[0])
		if strings.Contains(string(cmd), "--qemu-nas-policy-owner-service") || program == "smbd" || program == "rpcbind" || program == "rpc.mountd" || program == "rpc.nfsd" {
			return errors.New("unexpected provider or data service process")
		}
	}
	if threads, err := os.ReadFile("/proc/fs/nfsd/threads"); !errors.Is(err, os.ErrNotExist) && (err != nil || strings.TrimSpace(string(threads)) != "0") {
		return errors.New("unexpected NFSD activation")
	}
	if _, err := os.Lstat("/sys/kernel/config/target"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("unexpected target configuration")
	}
	fmt.Printf("NAS_BOOT_PROCESS_IDS provider=%d api_before=%d api_after=%d\n", provider, api, api)
	fmt.Println("PHANTOWD_NAS_BOOT_REFUSED_READY https=verified authenticated=true first=503 second=503 code=nas_configuration_reconciliation_required reconnects=0 respawn=false")
	if err := exec.CommandContext(ctx, "/etc/init.d/S50phantowd-api", "stop").Run(); err != nil || !poll(apiFD, 3000, true) {
		return errors.New("API init stop not verified")
	}
	var status unix.WaitStatus
	pidNumber, err := unix.Wait4(api, &status, unix.WNOHANG, nil)
	if err != nil || pidNumber != api || !status.Exited() || status.ExitStatus() != 0 || !absent() {
		return errors.New("API did not exit cleanly after provider loss")
	}
	if _, err := os.Lstat("/run/phantowd-api.pid"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("API pidfile retained after stop")
	}
	fmt.Println("PHANTOWD_NAS_BOOT_API_STOP_READY exited=true close_error=false services_activated=false")
	return nil
}
