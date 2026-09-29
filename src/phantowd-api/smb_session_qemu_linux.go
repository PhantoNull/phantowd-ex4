//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type qemuSMBServerID struct {
	PID uint32
}

// parseQEMUSMBStatusTable is a QEMU-only compatibility parser for Buildroot's
// Samba package, which is currently compiled with --without-json. Samba's
// pinned text layout exposes only a PID, so this parser deliberately returns
// no generation token; callers must keep PID-only shutdown in the disposable
// fixture and must not promote it to the product owner.
func parseQEMUSMBStatusTable(output []byte, username string) ([]qemuSMBServerID, error) {
	if username == "" {
		return nil, errors.New("SMB fixture account is missing")
	}
	const sessionHeader = "PID Username Group Machine Protocol Version Encryption Signing"
	headerFound := false
	separatorFound := false
	seen := make(map[uint32]struct{})
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if !headerFound {
			if strings.Join(strings.Fields(line), " ") == sessionHeader {
				headerFound = true
			}
			continue
		}
		if !separatorFound {
			if trimmed == "" {
				continue
			}
			if strings.Trim(trimmed, "-") == "" {
				separatorFound = true
				continue
			}
			return nil, errors.New("SMB fixture session table separator is missing")
		}
		if trimmed == "" {
			break
		}
		if strings.Trim(trimmed, "-") == "" {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, errors.New("SMB fixture session table row is incomplete")
		}
		pid, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil || pid == 0 {
			return nil, errors.New("SMB fixture session table PID is invalid")
		}
		if fields[1] == username {
			seen[uint32(pid)] = struct{}{}
		}
	}
	if !headerFound || !separatorFound {
		return nil, errors.New("SMB fixture session table is unavailable or changed")
	}
	result := make([]qemuSMBServerID, 0, len(seen))
	for pid := range seen {
		result = append(result, qemuSMBServerID{PID: pid})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PID < result[j].PID })
	return result, nil
}

func qemuSMBStatusExcerpt(output []byte) string {
	if len(output) > 512 {
		output = output[:512]
	}
	return string(output)
}

type qemuSMBActiveClient struct {
	command   *exec.Cmd
	stdin     io.WriteCloser
	output    string
	done      chan error
	cancel    context.CancelFunc
	exited    bool
	exitError error
}

func startQEMUSMBActiveClient(authFile, logName string) (*qemuSMBActiveClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	command := exec.CommandContext(ctx, "/usr/bin/smbclient", "-t", "5", "-m", "SMB3_11", "-p", "1445", "-A", authFile, "//127.0.0.1/PolicyShare")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.WaitDelay = time.Second
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		return nil, errors.New("SMB fixture could not open an interactive client")
	}
	outputPath := smbFixtureRoot + "/" + logName + ".log"
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = input.Close()
		cancel()
		return nil, errors.New("SMB fixture could not create an interactive-client log")
	}
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		_ = output.Close()
		_ = input.Close()
		cancel()
		return nil, errors.New("SMB fixture interactive client did not start")
	}
	if err := output.Close(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = input.Close()
		cancel()
		return nil, errors.New("SMB fixture could not close the interactive-client log handle")
	}
	client := &qemuSMBActiveClient{command: command, stdin: input, output: outputPath, done: make(chan error, 1), cancel: cancel}
	go func() { client.done <- command.Wait() }()
	return client, nil
}

func (client *qemuSMBActiveClient) checkExited() bool {
	if client.exited {
		return true
	}
	select {
	case client.exitError = <-client.done:
		client.exited = true
		return true
	default:
		return false
	}
}

func (client *qemuSMBActiveClient) send(command string) error {
	if client == nil || client.stdin == nil || client.checkExited() {
		return errors.New("SMB fixture interactive client exited before its command")
	}
	if _, err := io.WriteString(client.stdin, command+"\n"); err != nil {
		return errors.New("SMB fixture interactive command could not be sent")
	}
	return nil
}

func (client *qemuSMBActiveClient) close() error {
	if client == nil {
		return nil
	}
	if client.stdin != nil {
		_ = client.stdin.Close()
		client.stdin = nil
	}
	if client.checkExited() {
		client.cancel()
		return nil
	}
	select {
	case <-client.done:
		client.exited = true
		client.cancel()
		return nil
	case <-time.After(2 * time.Second):
		client.cancel()
		if client.command.Process != nil {
			_ = client.command.Process.Kill()
		}
		select {
		case <-client.done:
			client.exited = true
			return errors.New("SMB fixture interactive client required forced termination")
		case <-time.After(time.Second):
			return errors.New("SMB fixture interactive client could not be reaped")
		}
	}
}

func qemuSMBStatusSessions(config, username string) ([]qemuSMBServerID, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := smbFixtureCommandContext(ctx, "", "/usr/bin/smbstatus", "-s", config)
	if err != nil {
		return nil, errors.New("SMB fixture could not obtain the live session inventory")
	}
	sessions, err := parseQEMUSMBStatusTable(output, username)
	if err != nil {
		return nil, fmt.Errorf("SMB fixture could not parse live session inventory: %q", qemuSMBStatusExcerpt(output))
	}
	return sessions, nil
}

func waitForQEMUSMBStatusSessions(config, username string, want int) ([]qemuSMBServerID, error) {
	deadline := time.Now().Add(5 * time.Second)
	var observed []qemuSMBServerID
	for time.Now().Before(deadline) {
		var err error
		observed, err = qemuSMBStatusSessions(config, username)
		if err != nil {
			return nil, err
		}
		if len(observed) == want {
			return observed, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("SMB fixture observed %d live sessions for the target, want %d", len(observed), want)
}

func sameQEMUSMBServerIDs(left, right []qemuSMBServerID) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func waitForQEMUFileContent(path string, expected []byte) error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && bytes.Equal(data, expected) {
			return nil
		}
		if err != nil && !os.IsNotExist(err) {
			return errors.New("SMB fixture result file could not be observed")
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("SMB fixture result file did not reach its expected content")
}

// exerciseQEMUSMBSessionRevocation characterizes the disabled-account boundary
// and tests PID-only worker shutdown in a controlled disposable server. This
// pinned Samba build has no process-generation identity in its status output;
// this fixture must never be reused as a product revocation implementation.
// It does not define whether product Disable should revoke sessions separately
// or as part of the same user action.
func exerciseQEMUSMBSessionRevocation(config, writerAuth, readerAuth, shared, upload string, payload []byte) (result error) {
	writerA, err := startQEMUSMBActiveClient(writerAuth, "active-writer-a")
	if err != nil {
		return err
	}
	writerB, err := startQEMUSMBActiveClient(writerAuth, "active-writer-b")
	if err != nil {
		_ = writerA.close()
		return err
	}
	reader, err := startQEMUSMBActiveClient(readerAuth, "active-reader")
	if err != nil {
		_ = writerB.close()
		_ = writerA.close()
		return err
	}
	defer func() {
		result = errors.Join(result, writerA.close(), writerB.close(), reader.close())
	}()
	targetBefore, err := waitForQEMUSMBStatusSessions(config, "qpwriter", 2)
	if err != nil {
		return err
	}
	peerBefore, err := waitForQEMUSMBStatusSessions(config, "qpreader", 1)
	if err != nil {
		return err
	}
	if output, err := smbFixtureCommand("", "/usr/bin/smbpasswd", "-d", "-c", config, "qpwriter"); err != nil {
		return fmt.Errorf("SMB fixture could not disable the active account: %s", output)
	}
	targetAfterDisable, err := waitForQEMUSMBStatusSessions(config, "qpwriter", len(targetBefore))
	if err != nil {
		return errors.New("disabling the account unexpectedly removed its authenticated sessions")
	}
	if !sameQEMUSMBServerIDs(targetBefore, targetAfterDisable) {
		return errors.New("disabling the account changed its active worker identities")
	}
	output, err := smbFixtureCommand("", "/usr/bin/smbclient", "-t", "2", "-m", "SMB3_11", "-p", "1445", "-A", writerAuth, "//127.0.0.1/PolicyShare", "-c", "ls")
	if !smbFixtureDenied(output, err, "NT_STATUS_ACCOUNT_DISABLED") {
		return errors.New("disabled account accepted a new SMB connection")
	}
	activeWrite := shared + "/disabled-active-session-write"
	if _, err := os.Lstat(activeWrite); !os.IsNotExist(err) {
		return errors.New("SMB active-session test path was not fresh")
	}
	defer func() {
		if err := os.Remove(activeWrite); err != nil && !os.IsNotExist(err) {
			result = errors.Join(result, errors.New("SMB active-session test file cleanup failed"))
		}
	}()
	if err := writerA.send("put " + upload + " disabled-active-session-write"); err != nil {
		return errors.New("disabling the account revoked an existing writer before explicit shutdown")
	}
	if err := waitForQEMUFileContent(activeWrite, payload); err != nil {
		return errors.New("disabled account's existing SMB session could not complete its write")
	}

	for _, serverID := range targetBefore {
		// This fixture's pinned Buildroot Samba lacks Jansson, so its human
		// status output cannot provide unique_id. PID-only targeting is used here
		// only as a test stimulus against a disposable server; product code must
		// not reuse it or infer that PID-reuse safety has been established.
		destination := strconv.FormatUint(uint64(serverID.PID), 10)
		output, err := smbFixtureCommand("", "/usr/bin/smbcontrol", "-s", config, destination, "shutdown")
		if err != nil {
			return fmt.Errorf("SMB fixture could not signal target PID: %s", output)
		}
	}
	if _, err := waitForQEMUSMBStatusSessions(config, "qpwriter", 0); err != nil {
		return errors.New("target account sessions remained after QEMU-only PID shutdown")
	}
	peerAfter, err := waitForQEMUSMBStatusSessions(config, "qpreader", 1)
	if err != nil || !sameQEMUSMBServerIDs(peerBefore, peerAfter) {
		return errors.New("session shutdown disturbed an unrelated account from the same client IP")
	}
	peerDownload := smbFixtureRoot + "/active-reader-after-targeted-shutdown"
	if _, err := os.Lstat(peerDownload); !os.IsNotExist(err) {
		return errors.New("SMB peer download path was not fresh")
	}
	defer func() {
		if err := os.Remove(peerDownload); err != nil && !os.IsNotExist(err) {
			result = errors.Join(result, errors.New("SMB peer download cleanup failed"))
		}
	}()
	if err := reader.send("get created " + peerDownload); err != nil {
		return errors.New("unrelated existing SMB session could not receive its command")
	}
	if err := waitForQEMUFileContent(peerDownload, payload); err != nil {
		return errors.New("unrelated existing SMB session stopped working after targeted shutdown")
	}
	fmt.Println("PHANTOWD_SMB_CONNECTION_REVOCATION_READY disable_preserves_active_write=true target_connections=2 target_sessions_absent=true same_ip_peer_preserved=true peer_session_verified=true fresh_login_denied=true process_generation_available=false pid_targeting=qemu-only open_handles=false durable_reconnect=false scope=isolated-qemu-only")
	return nil
}
