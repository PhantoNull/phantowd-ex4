// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package passwordhash provides bounded Argon2id password verifiers.
// The QEMU-only prototype auth flow uses this package; EX4 KDF tuning remains
// unverified and production authentication is not enabled.
package passwordhash

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	defaultMemoryKiB  uint32 = 19 * 1024
	defaultIterations uint32 = 2
	defaultThreads    uint8  = 1
	keyLength                = 32
	saltLength               = 16
	maxPasswordLength        = 1024
	maxPHCLength             = 256
	maxMemoryKiB      uint32 = 64 * 1024
	maxIterations     uint32 = 4
	maxThreads        uint8  = 4
)

// MaxPasswordLength is the maximum password size accepted as UTF-8 bytes.
const MaxPasswordLength = maxPasswordLength

var (
	errInvalidPassword = errors.New("password must contain 1 to 1024 bytes")
	errInvalidVerifier = errors.New("invalid password verifier")
)

type parameters struct {
	memoryKiB  uint32
	iterations uint32
	threads    uint8
	salt       []byte
	key        []byte
}

// Hash creates a PHC-format Argon2id verifier with a fresh 128-bit salt.
// Its OWASP-floor parameters are provisional and must be benchmarked on the
// EX4 before this primitive is used by a released login flow. Calls share one
// process-wide KDF slot to bound concurrent memory use. A queued call may be
// cancelled; an Argon2 operation already running cannot be interrupted.
func Hash(ctx context.Context, password []byte) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", errInvalidPassword
	}
	var encoded string
	err := withKDFSlot(ctx, func() error {
		var err error
		encoded, err = hashValidated(password)
		return err
	})
	return encoded, err
}

func hashValidated(password []byte) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("secure random salt unavailable")
	}
	key := argon2.IDKey(password, salt, defaultIterations, defaultMemoryKiB, defaultThreads, keyLength)
	return "$argon2id$v=" + strconv.FormatUint(uint64(argon2.Version), 10) +
		"$m=" + strconv.FormatUint(uint64(defaultMemoryKiB), 10) +
		",t=" + strconv.FormatUint(uint64(defaultIterations), 10) +
		",p=" + strconv.FormatUint(uint64(defaultThreads), 10) +
		"$" + base64.RawStdEncoding.EncodeToString(salt) +
		"$" + base64.RawStdEncoding.EncodeToString(key), nil
}

// Verify checks password against a bounded PHC-format Argon2id verifier.
// Malformed or out-of-policy verifiers fail before any KDF work is performed.
func Verify(ctx context.Context, password []byte, encoded string) (bool, error) {
	if err := validatePassword(password); err != nil {
		return false, errInvalidPassword
	}
	p, err := parse(encoded)
	if err != nil {
		return false, err
	}
	verified := false
	err = withKDFSlot(ctx, func() error {
		verified = verifyParsed(password, p)
		return nil
	})
	return verified, err
}

// ValidateVerifier checks whether encoded uses the bounded PHC format accepted
// by Verify without running Argon2 work.
func ValidateVerifier(encoded string) error {
	_, err := parse(encoded)
	return err
}

func verifyParsed(password []byte, p parameters) bool {
	actual := argon2.IDKey(password, p.salt, p.iterations, p.memoryKiB, p.threads, keyLength)
	return subtle.ConstantTimeCompare(actual, p.key) == 1
}

func validatePassword(password []byte) error {
	if len(password) == 0 || len(password) > maxPasswordLength {
		return errInvalidPassword
	}
	return nil
}

func parse(encoded string) (parameters, error) {
	invalid := parameters{}
	if len(encoded) == 0 || len(encoded) > maxPHCLength {
		return invalid, errInvalidVerifier
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" ||
		parts[2] != "v="+strconv.FormatUint(uint64(argon2.Version), 10) {
		return invalid, errInvalidVerifier
	}
	parameterParts := strings.Split(parts[3], ",")
	if len(parameterParts) != 3 {
		return invalid, errInvalidVerifier
	}
	memoryKiB, ok := parseBoundedUint(parameterParts[0], "m=", 32)
	if !ok || memoryKiB < uint64(defaultMemoryKiB) || memoryKiB > uint64(maxMemoryKiB) {
		return invalid, errInvalidVerifier
	}
	iterations, ok := parseBoundedUint(parameterParts[1], "t=", 32)
	if !ok || iterations < uint64(defaultIterations) || iterations > uint64(maxIterations) {
		return invalid, errInvalidVerifier
	}
	threads, ok := parseBoundedUint(parameterParts[2], "p=", 8)
	if !ok || threads < uint64(defaultThreads) || threads > uint64(maxThreads) {
		return invalid, errInvalidVerifier
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < saltLength || len(salt) > 32 {
		return invalid, errInvalidVerifier
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) != keyLength {
		return invalid, errInvalidVerifier
	}
	return parameters{
		memoryKiB:  uint32(memoryKiB),
		iterations: uint32(iterations),
		threads:    uint8(threads),
		salt:       salt,
		key:        key,
	}, nil
}

func parseBoundedUint(field, prefix string, bitSize int) (uint64, bool) {
	if !strings.HasPrefix(field, prefix) {
		return 0, false
	}
	valueText := strings.TrimPrefix(field, prefix)
	value, err := strconv.ParseUint(valueText, 10, bitSize)
	if err != nil || strconv.FormatUint(value, 10) != valueText {
		return 0, false
	}
	return value, true
}
