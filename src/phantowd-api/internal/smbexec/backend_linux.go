//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package smbexec is a narrow root-side Samba passdb executor. It implements
// only the journaled account lifecycle required by smbprovision.
package smbexec

import (
	"bytes"
	"context"
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
	pdbeditPath        = "/usr/bin/pdbedit"
	smbpasswdPath      = "/usr/bin/smbpasswd"
	testparmPath       = "/usr/bin/testparm"
	configArgument     = "@PHANTOWD_TRUSTED_SMB_CONFIG@"
	childConfigPath    = "/proc/self/fd/3"
	maxConfigBytes     = 1 << 20
	maxObserveBytes    = 1 << 20
	configCheckTimeout = 5 * time.Second
	commandTimeout     = 10 * time.Second
	commandWaitDelay   = time.Second
	allowedAccountOps  = "NDHTUMWSLXI "
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
	mu     sync.RWMutex
	config *os.File
	runner commandRunner
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

// Close releases the pinned configuration descriptor. identityowner closes
// it only after draining operations under its lifetime lock.
func (b *Backend) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.config == nil {
		return nil
	}
	err := b.config.Close()
	b.config = nil
	return err
}

// Observe returns only the requested account's Unix name, owner-supplied UID/GID,
// SID and disabled bit. Password hashes and command output never escape.
func (b *Backend) Observe(ctx context.Context, account serviceaccounts.Account) (smbprovision.Observation, error) {
	if b == nil || ctx == nil || !validAccount(account) {
		return smbprovision.Observation{}, ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.runner == nil || b.config == nil {
		return smbprovision.Observation{}, ErrInvalid
	}
	output, err := b.runner.Run(ctx, pdbeditPath, []string{"-L", "-v", "-s", configArgument}, b.config, nil, true)
	if err != nil {
		clear(output)
		return smbprovision.Observation{}, ErrUnavailable
	}
	defer clear(output)
	return parseObservation(output, account)
}

// CreateDisabled adds one existing Unix identity to passdb without supplying
// a password, using the fixed Samba CLI and config. It never enables the entry.
func (b *Backend) CreateDisabled(ctx context.Context, account serviceaccounts.Account) error {
	if b == nil || ctx == nil || !validAccount(account) {
		return ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.runner == nil || b.config == nil {
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
	if b.runner == nil || b.config == nil {
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
	if b.runner == nil || b.config == nil {
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

// Disable performs the separate passdb disable operation. The parent journal
// records intent before this call and confirms that the same SID is disabled
// afterward. Existing SMB sessions are not revoked by this command.
func (b *Backend) Disable(ctx context.Context, account serviceaccounts.Account) error {
	if b == nil || ctx == nil || !validAccount(account) {
		return ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.runner == nil || b.config == nil {
		return ErrInvalid
	}
	output, err := b.runner.Run(ctx, smbpasswdPath,
		[]string{"-d", "-c", configArgument, account.Name}, b.config, []byte{}, false)
	clear(output)
	if err != nil {
		return ErrUnavailable
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

type passdbRecord struct {
	name, sid, flags string
	hasSID, hasFlags bool
}

func parseObservation(output []byte, account serviceaccounts.Account) (smbprovision.Observation, error) {
	var matches []passdbRecord
	var current *passdbRecord
	finish := func() error {
		if current == nil {
			return nil
		}
		if current.name == account.Name {
			if !current.hasSID || !validSID(current.sid) || !current.hasFlags || !validAccountFlags(current.flags) {
				return smbprovision.ErrObservation
			}
			matches = append(matches, *current)
		}
		current = nil
		return nil
	}
	for _, rawLine := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "Unix username:") {
			if err := finish(); err != nil {
				return smbprovision.Observation{}, err
			}
			name := strings.TrimSpace(strings.TrimPrefix(line, "Unix username:"))
			if name == "" || strings.ContainsAny(name, "\x00\r\n") {
				return smbprovision.Observation{}, smbprovision.ErrObservation
			}
			current = &passdbRecord{name: name}
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "User SID:") {
			if current.hasSID {
				if current.name == account.Name {
					return smbprovision.Observation{}, smbprovision.ErrObservation
				}
				continue
			}
			current.sid = strings.TrimSpace(strings.TrimPrefix(line, "User SID:"))
			current.hasSID = true
		}
		if strings.HasPrefix(line, "Account Flags:") {
			if current.hasFlags {
				if current.name == account.Name {
					return smbprovision.Observation{}, smbprovision.ErrObservation
				}
				continue
			}
			value := strings.TrimSpace(strings.TrimPrefix(line, "Account Flags:"))
			start, end := strings.IndexByte(value, '['), strings.LastIndexByte(value, ']')
			if start < 0 || end <= start || strings.TrimSpace(value[end+1:]) != "" {
				if current.name == account.Name {
					return smbprovision.Observation{}, smbprovision.ErrObservation
				}
				continue
			}
			current.flags = value[start+1 : end]
			current.hasFlags = true
		}
	}
	if err := finish(); err != nil {
		return smbprovision.Observation{}, err
	}
	if len(matches) == 0 {
		return smbprovision.Observation{}, nil
	}
	if len(matches) != 1 {
		return smbprovision.Observation{}, smbprovision.ErrObservation
	}
	flags := strings.ReplaceAll(matches[0].flags, " ", "")
	return smbprovision.Observation{
		Present: true, Name: account.Name, UID: account.UID, GID: account.GID,
		SID: matches[0].sid, Disabled: strings.Contains(flags, "D"),
	}, nil
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
		(executable != pdbeditPath && executable != smbpasswdPath) {
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
