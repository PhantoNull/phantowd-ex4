//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"syscall"
	"time"
)

type qemuSMBServerID struct {
	PID      uint32
	UniqueID uint64
}

// parseQEMUSMBStatusJSON consumes the pinned Samba 4.22.11 sessions JSON
// shape. The target includes both PID and Samba's process unique_id; incomplete
// or incompatible identities fail closed before any process signal is sent.
func parseQEMUSMBStatusJSON(output []byte, username string) ([]qemuSMBServerID, error) {
	if username == "" {
		return nil, errors.New("SMB fixture account is missing")
	}
	decodeString := func(fields map[string]json.RawMessage, name string) (string, bool) {
		raw, exists := fields[name]
		if !exists {
			return "", false
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", false
		}
		return value, true
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(output, &root); err != nil || root == nil {
		return nil, errors.New("SMB fixture session JSON is unavailable or changed")
	}
	rawSessions, exists := root["sessions"]
	if !exists {
		return nil, errors.New("SMB fixture session JSON has no sessions object")
	}
	var sessions map[string]json.RawMessage
	if err := json.Unmarshal(rawSessions, &sessions); err != nil || sessions == nil {
		return nil, errors.New("SMB fixture session JSON has an invalid sessions object")
	}

	const nonclusterVNN = ^uint32(0)
	const unqualifiedUniqueID = ^uint64(0)
	result := make([]qemuSMBServerID, 0, len(sessions))
	for id, rawSession := range sessions {
		var session map[string]json.RawMessage
		if err := json.Unmarshal(rawSession, &session); err != nil || session == nil {
			return nil, errors.New("SMB fixture session record is invalid")
		}
		sessionID, sessionIDOK := decodeString(session, "session_id")
		sessionUsername, usernameOK := decodeString(session, "username")
		rawServerID, serverIDOK := session["server_id"]
		if !sessionIDOK || id == "" || sessionID != id || !usernameOK ||
			sessionUsername == "" || !serverIDOK {
			return nil, errors.New("SMB fixture session record is incomplete")
		}
		var serverID map[string]json.RawMessage
		if err := json.Unmarshal(rawServerID, &serverID); err != nil || serverID == nil {
			return nil, errors.New("SMB fixture session process identity is invalid")
		}
		pidText, pidOK := decodeString(serverID, "pid")
		taskText, taskOK := decodeString(serverID, "task_id")
		vnnText, vnnOK := decodeString(serverID, "vnn")
		uniqueText, uniqueOK := decodeString(serverID, "unique_id")
		pid, pidErr := strconv.ParseUint(pidText, 10, 32)
		taskID, taskErr := strconv.ParseUint(taskText, 10, 32)
		vnn, vnnErr := strconv.ParseUint(vnnText, 10, 32)
		uniqueID, uniqueErr := strconv.ParseUint(uniqueText, 10, 64)
		if !pidOK || pidErr != nil || pid == 0 || !taskOK || taskErr != nil ||
			taskID != 0 || !vnnOK || vnnErr != nil || uint32(vnn) != nonclusterVNN ||
			!uniqueOK || uniqueErr != nil || uniqueID == unqualifiedUniqueID {
			return nil, errors.New("SMB fixture session has no usable process generation")
		}
		if sessionUsername == username {
			result = append(result, qemuSMBServerID{PID: uint32(pid), UniqueID: uniqueID})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].PID == result[j].PID {
			return result[i].UniqueID < result[j].UniqueID
		}
		return result[i].PID < result[j].PID
	})
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
	output, err := smbFixtureCommandContext(ctx, "", "/usr/bin/smbstatus", "-j", "-s", config)
	if err != nil {
		return nil, errors.New("SMB fixture could not obtain the live session inventory")
	}
	sessions, err := parseQEMUSMBStatusJSON(output, username)
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
// and tests generation-qualified worker shutdown in a controlled disposable
// server. This remains QEMU-only qualification, not product policy: it does not
// define whether product Disable should revoke sessions separately or as part
// of the same user action, and it does not address open handles or reconnect.
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

	signaled := make(map[qemuSMBServerID]struct{}, len(targetBefore))
	for _, serverID := range targetBefore {
		if _, exists := signaled[serverID]; exists {
			continue
		}
		signaled[serverID] = struct{}{}
		destination := strconv.FormatUint(uint64(serverID.PID), 10) + "/" +
			strconv.FormatUint(serverID.UniqueID, 10)
		output, err := smbFixtureCommand("", "/usr/bin/smbcontrol", "-s", config, destination, "shutdown")
		if err != nil {
			return fmt.Errorf("SMB fixture could not signal target process generation: %s", output)
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
	fmt.Println("PHANTOWD_SMB_CONNECTION_REVOCATION_READY disable_preserves_active_write=true target_connections=2 target_sessions_absent=true same_ip_peer_preserved=true peer_session_verified=true fresh_login_denied=true process_generation_available=true generation_targeting=qemu-only pid_targeting=false open_handles=false durable_reconnect=false scope=isolated-qemu-only")
	return nil
}
