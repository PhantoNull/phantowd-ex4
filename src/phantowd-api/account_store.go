// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/passwordhash"
)

const (
	accountFileName       = "accounts.json"
	accountStateVersion   = 1
	maxAccountStateBytes  = 4096
	minimumPasswordRunes  = 15
	maximumUsernameLength = 32
)

var (
	errAccountConfigured = errors.New("administrator account already configured")
	errAccountMissing    = errors.New("administrator account is not configured")
	errCredentials       = errors.New("invalid credentials")
	errInvalidUsername   = errors.New("invalid username")
	errShortPassword     = errors.New("password does not meet the minimum length")
)

type storedAccount struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type accountDocument struct {
	Version int           `json:"version"`
	Admin   storedAccount `json:"admin"`
}

type accountStore struct {
	mu    sync.Mutex
	dir   string
	file  string
	admin *storedAccount
}

func openAccountStore(dir string) (*accountStore, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errors.New("account state directory must be an absolute clean path")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, errors.New("account state directory is unavailable")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !privatePermissions(info.Mode(), 0o700) {
		return nil, errors.New("account state directory is not private")
	}
	store := &accountStore{dir: dir, file: filepath.Join(dir, accountFileName)}
	document, err := store.loadLocked()
	if err == nil {
		store.admin = &document.Admin
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("account state is invalid or inaccessible")
	}
	return store, nil
}

func (s *accountStore) configured() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.admin != nil, nil
}

func (s *accountStore) setup(ctx context.Context, username, password string) error {
	if !validUsername(username) {
		return errInvalidUsername
	}
	if !validSetupPassword(password) {
		return errShortPassword
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.admin != nil {
		return errAccountConfigured
	}
	verifier, err := passwordhash.Hash(ctx, []byte(password))
	if err != nil {
		return err
	}
	document := accountDocument{Version: accountStateVersion, Admin: storedAccount{
		Username: username, PasswordHash: verifier,
	}}
	return s.writeLocked(document)
}

func (s *accountStore) authenticate(ctx context.Context, username, password string) (bool, error) {
	if !validSetupPassword(password) {
		return false, errCredentials
	}
	s.mu.Lock()
	admin := s.admin
	s.mu.Unlock()
	if admin == nil {
		return false, errAccountMissing
	}
	if !validUsername(username) || username != admin.Username {
		_, err := passwordhash.Hash(ctx, []byte(password))
		return false, err
	}
	return passwordhash.Verify(ctx, []byte(password), admin.PasswordHash)
}

func (s *accountStore) loadLocked() (accountDocument, error) {
	var document accountDocument
	info, err := os.Lstat(s.file)
	if err != nil {
		return document, err
	}
	if !info.Mode().IsRegular() || !privatePermissions(info.Mode(), 0o600) || info.Size() > maxAccountStateBytes {
		return document, errors.New("account state file is not private or has invalid size")
	}
	file, err := os.Open(s.file)
	if err != nil {
		return document, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxAccountStateBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxAccountStateBytes {
		return document, errors.New("account state file cannot be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return accountDocument{}, errors.New("account state JSON is invalid")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return accountDocument{}, errors.New("account state has trailing data")
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, data) || document.Version != accountStateVersion ||
		!validUsername(document.Admin.Username) || passwordhash.ValidateVerifier(document.Admin.PasswordHash) != nil {
		return accountDocument{}, errors.New("account state schema or verifier is invalid")
	}
	return document, nil
}

func (s *accountStore) writeLocked(document accountDocument) error {
	data, err := json.Marshal(document)
	if err != nil || len(data) > maxAccountStateBytes {
		return errors.New("account state cannot be encoded")
	}
	file, err := os.CreateTemp(s.dir, ".accounts-*.tmp")
	if err != nil {
		return errors.New("account state cannot be staged")
	}
	tempName := file.Name()
	defer func() {
		if tempName != "" {
			_ = os.Remove(tempName)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return errors.New("account state permissions cannot be set")
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return errors.New("account state cannot be written")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("account state cannot be synchronized")
	}
	if err := file.Close(); err != nil {
		return errors.New("account state cannot be closed")
	}
	if _, err := os.Lstat(s.file); err == nil {
		return errAccountConfigured
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("account state destination is inaccessible")
	}
	if err := os.Link(tempName, s.file); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errAccountConfigured
		}
		return errors.New("account state cannot be committed")
	}
	s.admin = &document.Admin
	if err := os.Remove(tempName); err != nil {
		return errors.New("account state committed but temporary cleanup failed")
	}
	tempName = ""
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(s.dir)
	if err != nil {
		return errors.New("account state directory cannot be synchronized")
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("account state directory cannot be synchronized")
	}
	return nil
}

func privatePermissions(mode os.FileMode, ownerBits os.FileMode) bool {
	if runtime.GOOS == "windows" {
		// Windows does not expose POSIX owner/group/other mode bits through os.Stat.
		// Firmware builds target Linux, where these checks are enforced.
		return true
	}
	return mode.Perm()&0o077 == 0 && mode.Perm()&ownerBits == ownerBits
}

func validUsername(username string) bool {
	if username == "" || len(username) > maximumUsernameLength {
		return false
	}
	for _, character := range username {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._-", character)) {
			return false
		}
	}
	return true
}

func validSetupPassword(password string) bool {
	return utf8.ValidString(password) && len(password) <= passwordhash.MaxPasswordLength &&
		utf8.RuneCountInString(password) >= minimumPasswordRunes
}
