//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package smbexec is a narrow root-side Samba passdb executor. It implements
// only the journaled account lifecycle required by smbprovision.
package smbexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

const (
	pdbeditPath                    = "/usr/bin/pdbedit"
	smbpasswdPath                  = "/usr/bin/smbpasswd"
	smbstatusPath                  = "/usr/bin/smbstatus"
	smbcontrolPath                 = "/usr/bin/smbcontrol"
	testparmPath                   = "/usr/bin/testparm"
	configArgument                 = "@PHANTOWD_TRUSTED_SMB_CONFIG@"
	childConfigPath                = "/proc/self/fd/3"
	maxConfigBytes                 = 1 << 20
	maxObserveBytes                = 1 << 20
	configCheckTimeout             = 5 * time.Second
	commandTimeout                 = 10 * time.Second
	commandWaitDelay               = time.Second
	sessionPollInterval            = 100 * time.Millisecond
	sessionStatusTimeout           = 2 * time.Second
	sessionRevocationTimeout       = 5 * time.Second
	stableAbsentSessionInventories = 2
	allowedAccountOps              = "NDHTUMWSLXI "
)

var (
	ErrInvalid     = errors.New("invalid trusted Samba executor configuration or identity")
	ErrUnavailable = errors.New("trusted Samba command failed or is unavailable")
)

type commandRunner interface {
	Run(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error)
}

type commandRunnerFunc func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error)

func (f commandRunnerFunc) Run(ctx context.Context, executable string, args []string, config *os.File, stdin []byte, capture bool) ([]byte, error) {
	return f(ctx, executable, args, config, stdin, capture)
}

// Backend is constructed once by trusted root startup code and then bound to
// one identityowner.Owner. The validated root-owned config file is pinned for
// the backend lifetime and passed to each child through an inherited descriptor.
type Backend struct {
	mu       sync.RWMutex
	config   *os.File
	runner   commandRunner
	closed   bool
	closeErr error
}

// New creates a production command adapter for one trusted Samba config path.
// The path is a startup dependency, never a request or registry field.
func New(configPath string) (*Backend, error) {
	config, err := openConfig(configPath)
	if err != nil {
		return nil, ErrInvalid
	}
	if err := validateConfig(config); err != nil {
		_ = config.Close()
		return nil, ErrInvalid
	}
	return &Backend{config: config, runner: commandRunnerFunc(runCommand)}, nil
}

func newBackend(configPath string, runner commandRunner) (*Backend, error) {
	if runner == nil {
		return nil, ErrInvalid
	}
	config, err := openConfig(configPath)
	if err != nil {
		return nil, ErrInvalid
	}
	return &Backend{config: config, runner: runner}, nil
}

// Close releases the pinned configuration descriptor after operations drain.
// Its first error is terminal: retain uncertainty, never retry release or report
// later success. A failed close does not prove that the descriptor remains open.
func (b *Backend) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return b.closeErr
	}
	b.closed = true // Fence every operation before attempting the release.
	if b.config == nil {
		return nil
	}
	if err := b.config.Close(); err != nil {
		b.closeErr = err
		return err
	}
	b.config = nil
	return nil
}

// Observe returns only the requested account's Unix name, owner-supplied UID/GID,
// SID and disabled bit. Password hashes and command output never escape.
func (b *Backend) Observe(ctx context.Context, account serviceaccounts.Account) (smbprovision.Observation, error) {
	observations, err := b.ObserveAccounts(ctx, []serviceaccounts.Account{account})
	if err != nil {
		return smbprovision.Observation{}, err
	}
	return observations[0], nil
}

// ObserveAccounts obtains one bounded passdb listing and returns only the
// requested identities in caller order. The full command output, including
// password hashes emitted by pdbedit, is cleared before returning.
func (b *Backend) ObserveAccounts(ctx context.Context, accounts []serviceaccounts.Account) ([]smbprovision.Observation, error) {
	if b == nil || ctx == nil || len(accounts) > serviceaccounts.MaxLive {
		return nil, ErrInvalid
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return nil, ErrInvalid
	}
	observations := make([]smbprovision.Observation, len(accounts))
	if len(accounts) == 0 {
		return observations, nil
	}
	seenIDs, seenNames := make(map[string]bool, len(accounts)), make(map[string]bool, len(accounts))
	for _, account := range accounts {
		if !validObservedAccount(account) || seenIDs[account.ID] || seenNames[account.Name] {
			return nil, ErrInvalid
		}
		seenIDs[account.ID], seenNames[account.Name] = true, true
	}
	if b.runner == nil || b.config == nil {
		return nil, ErrInvalid
	}
	output, err := b.runner.Run(ctx, pdbeditPath, []string{"-L", "-v", "-s", configArgument}, b.config, nil, true)
	if err != nil {
		clear(output)
		return nil, ErrUnavailable
	}
	defer clear(output)
	observations, err = parseObservations(output, accounts)
	if err != nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return observations, nil
}

// CreateDisabled adds one existing Unix identity to passdb without supplying
// a password, using the fixed Samba CLI and config. It never enables the entry.
func (b *Backend) CreateDisabled(ctx context.Context, account serviceaccounts.Account) error {
	if b == nil || ctx == nil || !validAccount(account) {
		return ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.runner == nil || b.config == nil {
		return ErrInvalid
	}
	output, err := b.runner.Run(ctx, smbpasswdPath,
		[]string{"-a", "-d", "-c", configArgument, account.Name}, b.config, []byte{}, false)
	clear(output)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

// SetPasswordDisabled sends the bounded secret only over stdin to the pinned
// root-only Samba command; it is absent from argv, environment and diagnostics.
func (b *Backend) SetPasswordDisabled(ctx context.Context, account serviceaccounts.Account, secret []byte) error {
	if b == nil || ctx == nil || !validAccount(account) || !smbprovision.ValidPassword(secret) {
		return ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.runner == nil || b.config == nil {
		return ErrInvalid
	}
	input := make([]byte, 0, len(secret)*2+2)
	input = append(input, secret...)
	input = append(input, '\n')
	input = append(input, secret...)
	input = append(input, '\n')
	defer clear(input)
	output, err := b.runner.Run(ctx, smbpasswdPath,
		[]string{"-s", "--set-password-disabled", "-c", configArgument, account.Name},
		b.config, input, false)
	clear(output)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

// Enable performs the separate explicit enable operation. The parent journal
// requires a confirmed disabled account/credential, records intent before this
// call, and verifies the same SID is enabled before reporting success.
func (b *Backend) Enable(ctx context.Context, account serviceaccounts.Account) error {
	if b == nil || ctx == nil || !validAccount(account) {
		return ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.runner == nil || b.config == nil {
		return ErrInvalid
	}
	output, err := b.runner.Run(ctx, smbpasswdPath,
		[]string{"-e", "-c", configArgument, account.Name}, b.config, []byte{}, false)
	clear(output)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

// Disable disables the passdb identity, logs off that user's current SMB
// sessions, and returns only after bounded smbstatus observations confirm the
// target session set is empty. The parent journal durably records intent before
// this composite operation; any uncertain command or incomplete observation
// is returned as failure so the journal can quarantine it without replay.
func (b *Backend) Disable(ctx context.Context, account serviceaccounts.Account) error {
	return b.disableWithProfile(ctx, account, commandRevocationProfile)
}

// Only trusted adapters select one fixed profile, never request-supplied
// durations. The command profile preserves its original limits exactly.
func (b *Backend) disableWithProfile(ctx context.Context, account serviceaccounts.Account, profile revocationProfile) error {
	limits, valid := profile.limits()
	if b == nil || ctx == nil || !validAccount(account) || !valid {
		return ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.runner == nil || b.config == nil {
		return ErrInvalid
	}
	output, err := b.runner.Run(ctx, smbpasswdPath,
		[]string{"-d", "-c", configArgument, account.Name}, b.config, []byte{}, false)
	clear(output)
	if err != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return b.revokeUserSessions(ctx, account.Name, limits)
}

// revokeUserSessions invokes Samba's account-scoped session-logoff control at
// most once, then requires two consecutive complete inventories without the
// target account. Read-only status polling is bounded; ambiguous output,
// timeout, cancellation or a failed control command is never retried here.
func (b *Backend) revokeUserSessions(ctx context.Context, username string, limits revocationLimits) error {
	if ctx == nil || username == "" {
		return ErrInvalid
	}
	deadline := time.Now().Add(limits.total)
	controlSent := false
	stableAbsent := 0
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 || ctx.Err() != nil {
			return ErrUnavailable
		}
		statusTimeout := limits.status
		if remaining < statusTimeout {
			statusTimeout = remaining
		}
		statusCtx, cancel := context.WithTimeout(ctx, statusTimeout)
		output, err := b.runner.Run(statusCtx, smbstatusPath,
			[]string{"-j", "-s", configArgument}, b.config, []byte{}, true)
		statusCtxErr := statusCtx.Err()
		cancel()
		if err != nil || statusCtxErr != nil || ctx.Err() != nil {
			clear(output)
			return ErrUnavailable
		}
		present, parseErr := parseSMBStatusHasUser(output, username)
		clear(output)
		if parseErr != nil {
			return ErrUnavailable
		}
		if present {
			stableAbsent = 0
			if !controlSent {
				controlTimeout := time.Until(deadline)
				if controlTimeout <= 0 {
					return ErrUnavailable
				}
				if controlTimeout > limits.control {
					controlTimeout = limits.control
				}
				controlCtx, cancel := context.WithTimeout(ctx, controlTimeout)
				controlOutput, controlErr := b.runner.Run(controlCtx, smbcontrolPath,
					[]string{"-s", configArgument, "smbd", "logoff-user", username},
					b.config, []byte{}, false)
				controlCtxErr := controlCtx.Err()
				cancel()
				clear(controlOutput)
				if controlErr != nil || controlCtxErr != nil || ctx.Err() != nil {
					return ErrUnavailable
				}
				controlSent = true
			}
		} else {
			stableAbsent++
			if stableAbsent >= stableAbsentSessionInventories {
				return nil
			}
		}

		remaining = time.Until(deadline)
		if remaining <= 0 {
			return ErrUnavailable
		}
		wait := sessionPollInterval
		if remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ErrUnavailable
		case <-timer.C:
		}
	}
}

type smbStatusServerID struct {
	PID      string `json:"pid"`
	TaskID   string `json:"task_id"`
	VNN      string `json:"vnn"`
	UniqueID string `json:"unique_id"`
}

type smbStatusSession struct {
	SessionID string            `json:"session_id"`
	Username  string            `json:"username"`
	ServerID  smbStatusServerID `json:"server_id"`
}

// parseSMBStatusHasUser accepts only the pinned 4.22 JSON inventory shape and
// validates every session, not only the target record: partial/ambiguous state
// must never be mistaken for a successful revocation.
func parseSMBStatusHasUser(output []byte, username string) (bool, error) {
	if len(output) == 0 || len(output) > maxObserveBytes || username == "" {
		return false, ErrInvalid
	}
	if err := validateUniqueJSONKeys(output); err != nil {
		return false, ErrInvalid
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(output, &root); err != nil || root == nil {
		return false, ErrInvalid
	}
	rawSessions, ok := root["sessions"]
	if !ok {
		return false, ErrInvalid
	}
	var sessions map[string]json.RawMessage
	if err := json.Unmarshal(rawSessions, &sessions); err != nil || sessions == nil {
		return false, ErrInvalid
	}
	const nonclusterVNN = ^uint32(0)
	const unqualifiedUniqueID = ^uint64(0)
	targetPresent := false
	for key, raw := range sessions {
		var session smbStatusSession
		if err := json.Unmarshal(raw, &session); err != nil || session.SessionID == "" ||
			session.SessionID != key || session.Username == "" || strings.ContainsAny(session.Username, "\x00\r\n") {
			return false, ErrInvalid
		}
		id, err := strconv.ParseUint(session.SessionID, 10, 64)
		if err != nil || id == 0 || strconv.FormatUint(id, 10) != session.SessionID {
			return false, ErrInvalid
		}
		pid, pidErr := strconv.ParseUint(session.ServerID.PID, 10, 32)
		taskID, taskErr := strconv.ParseUint(session.ServerID.TaskID, 10, 32)
		vnn, vnnErr := strconv.ParseUint(session.ServerID.VNN, 10, 32)
		uniqueID, uniqueErr := strconv.ParseUint(session.ServerID.UniqueID, 10, 64)
		if pidErr != nil || pid == 0 || taskErr != nil || taskID != 0 ||
			vnnErr != nil || uint32(vnn) != nonclusterVNN ||
			uniqueErr != nil || uniqueID == 0 || uniqueID == unqualifiedUniqueID {
			return false, ErrInvalid
		}
		if session.Username == username {
			targetPresent = true
		}
	}
	return targetPresent, nil
}

func validateUniqueJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanSMBStatusJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func scanSMBStatusJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return ErrInvalid
			}
			if _, exists := seen[key]; exists {
				return ErrInvalid
			}
			seen[key] = struct{}{}
			if err := scanSMBStatusJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for decoder.More() {
			if err := scanSMBStatusJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validAccount(account serviceaccounts.Account) bool {
	r, err := serviceaccounts.New(account.UID, account.UID)
	if err != nil {
		return false
	}
	r.Accounts = []serviceaccounts.Account{account}
	return r.Validate() == nil && account.State == serviceaccounts.Disabled
}

// Read-only passdb observation must accept the registry's current desired
// enabled state as well as disabled identities. Mutating executor operations
// continue to require the immutable disabled native-journal account instead.
func validObservedAccount(account serviceaccounts.Account) bool {
	if account.State != serviceaccounts.Disabled && account.State != serviceaccounts.Enabled {
		return false
	}
	account.State = serviceaccounts.Disabled
	return validAccount(account)
}

type passdbRecord struct {
	sid, flags       string
	hasSID, hasFlags bool
	requested        bool
	index            int
}

func parseObservation(output []byte, account serviceaccounts.Account) (smbprovision.Observation, error) {
	observations, err := parseObservations(output, []serviceaccounts.Account{account})
	if err != nil {
		return smbprovision.Observation{}, err
	}
	return observations[0], nil
}

func parseObservations(output []byte, accounts []serviceaccounts.Account) ([]smbprovision.Observation, error) {
	wanted, foldedWanted := make(map[string]int, len(accounts)), make(map[string]int, len(accounts))
	for i, account := range accounts {
		if !validObservedAccount(account) {
			return nil, smbprovision.ErrObservation
		}
		folded := strings.ToLower(account.Name)
		if _, exists := wanted[account.Name]; exists {
			return nil, smbprovision.ErrObservation
		}
		if _, exists := foldedWanted[folded]; exists {
			return nil, smbprovision.ErrObservation
		}
		wanted[account.Name] = i
		foldedWanted[folded] = i
	}
	observations := make([]smbprovision.Observation, len(accounts))
	found := make([]bool, len(accounts))
	seenSIDs := make(map[string]bool, len(accounts))
	var current *passdbRecord
	finish := func() error {
		if current == nil || !current.requested {
			current = nil
			return nil
		}
		if !current.hasSID || !validSID(current.sid) || !current.hasFlags || !validAccountFlags(current.flags) ||
			found[current.index] || seenSIDs[current.sid] {
			return smbprovision.ErrObservation
		}
		flags := strings.ReplaceAll(current.flags, " ", "")
		account := accounts[current.index]
		observations[current.index] = smbprovision.Observation{
			Present: true, Name: account.Name, UID: account.UID, GID: account.GID,
			SID: current.sid, Disabled: strings.Contains(flags, "D"),
		}
		found[current.index], seenSIDs[current.sid] = true, true
		current = nil
		return nil
	}
	for _, rawLine := range bytes.Split(output, []byte{'\n'}) {
		line := bytes.TrimSpace(rawLine)
		if bytes.HasPrefix(line, []byte("Unix username:")) {
			if err := finish(); err != nil {
				return nil, err
			}
			name := strings.TrimSpace(string(bytes.TrimSpace(bytes.TrimPrefix(line, []byte("Unix username:")))))
			if name == "" || strings.ContainsAny(name, "\x00\r\n") {
				return nil, smbprovision.ErrObservation
			}
			index, requested := wanted[name]
			if !requested {
				if _, caseCollision := foldedWanted[strings.ToLower(name)]; caseCollision {
					return nil, smbprovision.ErrObservation
				}
			}
			current = &passdbRecord{requested: requested, index: index}
			continue
		}
		if current == nil || !current.requested {
			continue
		}
		if bytes.HasPrefix(line, []byte("User SID:")) {
			if current.hasSID {
				return nil, smbprovision.ErrObservation
			}
			current.sid = strings.TrimSpace(string(bytes.TrimSpace(bytes.TrimPrefix(line, []byte("User SID:")))))
			current.hasSID = true
		}
		if bytes.HasPrefix(line, []byte("Account Flags:")) {
			if current.hasFlags {
				return nil, smbprovision.ErrObservation
			}
			value := strings.TrimSpace(string(bytes.TrimSpace(bytes.TrimPrefix(line, []byte("Account Flags:")))))
			start, end := strings.IndexByte(value, '['), strings.LastIndexByte(value, ']')
			if start < 0 || end <= start || strings.TrimSpace(value[end+1:]) != "" {
				return nil, smbprovision.ErrObservation
			}
			current.flags = value[start+1 : end]
			current.hasFlags = true
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}
	return observations, nil
}

func validAccountFlags(flags string) bool {
	seen := map[rune]bool{}
	user := false
	for _, flag := range flags {
		if flag == ' ' {
			continue
		}
		if !strings.ContainsRune(allowedAccountOps, flag) || seen[flag] {
			return false
		}
		seen[flag] = true
		if flag == 'U' {
			user = true
		}
	}
	return user
}

func validSID(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 8 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" || parts[3] != "21" {
		return false
	}
	for _, part := range parts[4:] {
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != part {
			return false
		}
	}
	return true
}

func openConfig(path string) (*os.File, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, ErrInvalid
	}
	file := os.NewFile(uintptr(fd), "smb.conf")
	if file == nil {
		unix.Close(fd)
		return nil, ErrInvalid
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 ||
		st.Mode&0022 != 0 || st.Size <= 0 || st.Size > maxConfigBytes {
		file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

// validateConfig parses the same pinned inode that commands will use. A bad
// or unavailable testparm binary fails closed before the backend is bound to an
// Owner or any identity operation can create journal state.
func validateConfig(config *os.File) error {
	if config == nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), configCheckTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, testparmPath, "-s", childConfigPath)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	command.ExtraFiles = []*os.File{config}
	command.Stdin = bytes.NewReader(nil)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = commandWaitDelay
	if err := command.Run(); err != nil || ctx.Err() != nil {
		return ErrInvalid
	}
	return nil
}

func runCommand(ctx context.Context, executable string, args []string, config *os.File, stdin []byte, capture bool) ([]byte, error) {
	if ctx == nil || config == nil || os.Getuid() != 0 || os.Geteuid() != 0 ||
		(executable != pdbeditPath && executable != smbpasswdPath && executable != smbstatusPath && executable != smbcontrolPath) {
		return nil, ErrInvalid
	}
	if !replaceConfigArgument(args) {
		return nil, ErrInvalid
	}
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, executable, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	command.ExtraFiles = []*os.File{config}
	command.Stdin = bytes.NewReader(stdin)
	command.Stderr = io.Discard
	command.WaitDelay = commandWaitDelay
	var output limitedBuffer
	if capture {
		output.limit = maxObserveBytes
		command.Stdout = &output
	} else {
		command.Stdout = io.Discard
	}
	if err := command.Run(); err != nil || commandCtx.Err() != nil || output.exceeded {
		clear(output.buffer.Bytes())
		return nil, ErrUnavailable
	}
	return output.buffer.Bytes(), nil
}

func replaceConfigArgument(args []string) bool {
	replaced := false
	for index, arg := range args {
		if arg != configArgument {
			continue
		}
		if replaced {
			return false
		}
		args[index] = childConfigPath
		replaced = true
	}
	return replaced
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - b.buffer.Len()
	if remaining < len(value) {
		if remaining > 0 {
			_, _ = b.buffer.Write(value[:remaining])
		}
		b.exceeded = true
		return len(value), nil
	}
	return b.buffer.Write(value)
}
