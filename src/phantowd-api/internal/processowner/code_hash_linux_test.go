//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func codeHashFixture(t *testing.T) (*os.File, *os.File, []*os.File, []string) {
	t.Helper()
	path := os.Getenv("PHANTOWD_CODE_HASH_TEST_HELPER")
	if path == "" || os.Geteuid() != 0 {
		t.Skip("requires disposable root fixture with static helper")
	}
	program, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = program.Close() })
	dir := t.TempDir()
	paths := []string{dir + "/empty", dir + "/a", dir + "/b"}
	contents := [][]byte{nil, []byte("abc"), bytes.Repeat([]byte("code"), 1000)}
	var all []*os.File
	for index, path := range paths {
		if err := os.WriteFile(path, contents[index], 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, file)
		t.Cleanup(func() { _ = file.Close() })
	}
	return program, all[0], all[1:], paths[1:]
}

func TestCodeHashReaderRetainsOriginalInputs(t *testing.T) {
	program, input, files, _ := codeHashFixture(t)
	want := [][]byte{[]byte("abc"), bytes.Repeat([]byte("code"), 1000)}
	reader, err := NewCodeHashReader(context.Background(), program, input, files, expectedCodeHashProgram(t, program))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(context.Background()) })
	_ = program.Close()
	_ = input.Close()
	for index, file := range files {
		_ = file.Close()
		files[index] = nil
	}
	observed, err := reader.Read(context.Background())
	if err != nil || len(observed) != len(want) {
		t.Fatal("bound reader failed", err)
	}
	for index, content := range want {
		if observed[index].Size != int64(len(content)) || observed[index].SHA256 != sha256.Sum256(content) {
			t.Fatal("different source/digest")
		}
	}
	if got, err := reader.Read(context.Background()); got != nil || !errors.Is(err, ErrCaptureConsumed) {
		t.Fatal("reader repeated", err)
	}
	if settled, err := reader.Settled(context.Background()); err != nil || !settled {
		t.Fatal("unsettled reader", err)
	}
	if err := reader.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.Read(context.Background()); got != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed reader reused", err)
	}
}

func TestCodeHashReaderRefusesChangedFile(t *testing.T) {
	program, input, files, paths := codeHashFixture(t)
	reader, err := NewCodeHashReader(context.Background(), program, input, files, expectedCodeHashProgram(t, program))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(context.Background()) })
	if err := os.WriteFile(paths[0], []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.Read(context.Background()); got != nil || !errors.Is(err, ErrReviewRequired) {
		t.Fatal("changed input accepted", err)
	}
}

func TestCodeHashFrameAllOrError(t *testing.T) {
	good := make([]byte, 12+40)
	copy(good, "PHWDHS01")
	binary.LittleEndian.PutUint32(good[8:12], 1)
	binary.LittleEndian.PutUint64(good[12:20], 3)
	digest := sha256.Sum256([]byte("abc"))
	copy(good[20:], digest[:])
	if got, err := decodeCodeHashes(good, []int64{3}); err != nil || len(got) != 1 || got[0].SHA256 != digest {
		t.Fatal("valid frame refused", err)
	}
	for _, bad := range [][]byte{nil, good[:11], good[:len(good)-1], append(append([]byte{}, good...), 0), append([]byte("WRONGMAG"), good[8:]...)} {
		if got, err := decodeCodeHashes(bad, []int64{3}); got != nil || err == nil {
			t.Fatal("partial or malformed frame accepted")
		}
	}
	if got, err := decodeCodeHashes(good, []int64{4}); got != nil || err == nil {
		t.Fatal("wrong size accepted")
	}
	if got, err := decodeCodeHashes(good, []int64{3, 3}); got != nil || err == nil {
		t.Fatal("wrong count accepted")
	}
}

func TestCodeHashReaderCanceledBeforeReadDoesNotConsume(t *testing.T) {
	program, input, files, _ := codeHashFixture(t)
	reader, err := NewCodeHashReader(context.Background(), program, input, files, expectedCodeHashProgram(t, program))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(context.Background()) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := reader.Read(ctx); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled read published", err)
	}
	if got, err := reader.Read(context.Background()); err != nil || len(got) != 2 {
		t.Fatal("pre-effect cancel consumed reader", err)
	}
}

func TestCodeHashReaderRefusesUnsafeInputs(t *testing.T) {
	program, input, files, paths := codeHashFixture(t)
	writable, err := os.OpenFile(paths[0], os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writable.Close()
	for _, bad := range [][]*os.File{nil, {nil}, {input}, {writable}, {files[0], files[0]}, make([]*os.File, 257)} {
		if reader, err := NewCodeHashReader(context.Background(), program, input, bad, expectedCodeHashProgram(t, program)); reader != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe input accepted", err)
		}
	}
}

func TestCodeHashReaderChildRefusalsAreSticky(t *testing.T) {
	_, input, files, _ := codeHashFixture(t)
	base := strings.TrimSuffix(os.Getenv("PHANTOWD_CODE_HASH_TEST_HELPER"), "phantowd-code-hash")
	for index := 1; index <= 4; index++ {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			program, err := os.Open(base + "phantowd-code-hash-refusal-" + strconv.Itoa(index))
			if err != nil {
				t.Fatal(err)
			}
			defer program.Close()
			reader, err := NewCodeHashReader(context.Background(), program, input, files, expectedCodeHashProgram(t, program))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := reader.Read(ctx)
			if got != nil || !errors.Is(err, ErrReviewRequired) {
				t.Fatal("uncertain child published", err)
			}
			if index == 4 && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("deadline not preserved", err)
			}
			if got, err := reader.Read(context.Background()); got != nil || !errors.Is(err, ErrReviewRequired) {
				t.Fatal("uncertain read repeated", err)
			}
			if settled, err := reader.Settled(context.Background()); err != nil || !settled {
				t.Fatal("child still active", err)
			}
			if err := reader.Close(context.Background()); err != nil {
				t.Fatal("settled close", err)
			}
		})
	}
}

func TestCodeHashReaderUncertainCloseNeverRetriesOrConsumesCallerInputs(t *testing.T) {
	program, input, files, _ := codeHashFixture(t)
	reader, err := NewCodeHashReader(context.Background(), program, input, files, expectedCodeHashProgram(t, program))
	if err != nil {
		t.Fatal(err)
	}
	// Test-only os.File close fault: no raw descriptor race or child starts.
	if err := reader.capture.input.Close(); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := reader.Close(context.Background()); !errors.Is(err, ErrReviewRequired) {
			t.Fatal("close uncertainty forgotten", err)
		}
		for _, original := range append([]*os.File{program, input}, files...) {
			if _, err := original.Stat(); err != nil {
				t.Fatal("borrowed original released", err)
			}
		}
	}
	if got, err := reader.Read(context.Background()); got != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed close allowed read", err)
	}
	if settled, err := reader.Settled(context.Background()); err != nil || !settled {
		t.Fatal("absence observation", err)
	}
	if err := reader.Close(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("observation cleared uncertainty", err)
	}
}

// Expected fixture hashes are bound by the host builder before guest boot;
// do not derive the expected digest from the program being admitted.
func expectedCodeHashProgram(t *testing.T, program *os.File) (digest [32]byte) {
	t.Helper()
	slot := "0"
	if strings.Contains(program.Name(), "-refusal-") {
		slot = program.Name()[len(program.Name())-1:]
	}
	raw, err := hex.DecodeString(os.Getenv("PHANTOWD_CODE_HASH_TEST_SHA256_" + slot))
	if err != nil || len(raw) != len(digest) {
		t.Fatal("missing builder-owned fixture digest")
	}
	copy(digest[:], raw)
	return digest
}

func TestCodeHashReaderRefusesUnadmittedProgram(t *testing.T) {
	program, input, files, _ := codeHashFixture(t)
	expected := expectedCodeHashProgram(t, program)
	expected[0] ^= 1
	reader, err := NewCodeHashReader(context.Background(), program, input, files, expected)
	if reader != nil {
		t.Cleanup(func() { _ = reader.Close(context.Background()) })
	}
	if reader != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("unadmitted program accepted", err)
	}
}
