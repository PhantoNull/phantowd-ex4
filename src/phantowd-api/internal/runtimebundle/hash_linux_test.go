//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// These files are calculation fixtures, not admitted code trees or device
// inputs. The digest helper does not bypass the production metadata/census gate.
func runtimeHashFixture(t testing.TB, data []byte) *os.File {
	t.Helper()
	name := filepath.Join(t.TempDir(), "digest-input")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestRuntimeFileHashChunkBoundariesAndLengthFence(t *testing.T) {
	for _, size := range []int{1, 32767, 32768, 32769, 65537} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{byte(size % 251)}, size)
			file := runtimeHashFixture(t, data)
			digest, count, err := hashRuntimeFile(context.Background(), file, int64(size), make([]byte, runtimeHashScratchSize))
			if err != nil || count != int64(size) || digest != sha256.Sum256(data) {
				t.Fatal("bounded digest differs", count, err)
			}
		})
	}
	data := bytes.Repeat([]byte{0x5a}, 65537)
	file := runtimeHashFixture(t, data)
	digest, count, err := hashRuntimeFile(context.Background(), file, 32768, make([]byte, runtimeHashScratchSize))
	if err != nil || count != 32769 || digest != sha256.Sum256(data[:32769]) {
		t.Fatal("size+1 overlength fence changed", count, err)
	}
	short := runtimeHashFixture(t, []byte("short"))
	_, count, err = hashRuntimeFile(context.Background(), short, 32, make([]byte, runtimeHashScratchSize))
	if err != nil || count != 5 {
		t.Fatal("short-file count changed", count, err)
	}
}

type cancelHashContext struct {
	context.Context
	checks int
}

func (c *cancelHashContext) Err() error {
	c.checks++
	if c.checks >= 3 {
		return context.Canceled
	}
	return nil
}

func TestRuntimeFileHashCancellationAndReadFailureAreNotObservations(t *testing.T) {
	file := runtimeHashFixture(t, bytes.Repeat([]byte{0xa5}, 65537))
	ctx := &cancelHashContext{Context: context.Background()}
	digest, count, err := hashRuntimeFile(ctx, file, 65537, make([]byte, runtimeHashScratchSize))
	if !errors.Is(err, context.Canceled) || digest != ([32]byte{}) || count != 0 {
		t.Fatal("canceled hash returned a partial observation", count, err)
	}
	if offset, err := file.Seek(0, 1); err != nil || offset != 65536 {
		t.Fatal("chunk cancellation boundary changed", offset, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	digest, count, err = hashRuntimeFile(context.Background(), file, 1, make([]byte, runtimeHashScratchSize))
	if !errors.Is(err, ErrUnavailable) || digest != ([32]byte{}) || count != 0 {
		t.Fatal("failed read returned a partial observation", count, err)
	}
	for _, size := range []int64{0, -1, maxBytes + 1} {
		if _, _, err := hashRuntimeFile(context.Background(), file, size, make([]byte, runtimeHashScratchSize)); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid digest length accepted", size, err)
		}
	}
}

func TestRuntimeFileHashScratchReuseDoesNotReuseDigestOrOldBytes(t *testing.T) {
	scratch := make([]byte, runtimeHashScratchSize)
	for _, size := range []int{65537, 1, 32769, 17} {
		data := bytes.Repeat([]byte{byte(size % 251)}, size)
		file := runtimeHashFixture(t, data)
		digest, count, err := hashRuntimeFile(context.Background(), file, int64(size), scratch)
		if err != nil || count != int64(size) || digest != sha256.Sum256(data) {
			t.Fatal("scratch reuse changed digest or length", size, count, err)
		}
	}
	file := runtimeHashFixture(t, []byte("unread"))
	for _, invalid := range [][]byte{nil, make([]byte, 1), make([]byte, runtimeHashScratchSize+1)} {
		digest, count, err := hashRuntimeFile(context.Background(), file, 6, invalid)
		if !errors.Is(err, ErrInvalid) || digest != ([32]byte{}) || count != 0 {
			t.Fatal("invalid scratch returned an observation", count, err)
		}
	}
	if offset, err := file.Seek(0, 1); err != nil || offset != 0 {
		t.Fatal("invalid scratch read a file", offset, err)
	}
}

// Allocation evidence for the real digest loop only, not complete admission,
// ARMv5/EX4 throughput or a diagnosis of the lifecycle timeout.
func TestRuntimeFileHashBatchHasNoPerFileScratchAllocation(t *testing.T) {
	const files = 64
	file := runtimeHashFixture(t, bytes.Repeat([]byte{0x37}, 4096))
	allocations := testing.AllocsPerRun(3, func() {
		scratch := make([]byte, runtimeHashScratchSize)
		for index := 0; index < files; index++ {
			if _, err := file.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			if _, _, err := hashRuntimeFile(context.Background(), file, 4096, scratch); err != nil {
				t.Fatal(err)
			}
		}
	})
	// One batch scratch plus per-file digest Sum; allow bounded fixed runtime/
	// race bookkeeping overhead, not another scratch allocation per file.
	// This is a digest-loop allocation contract, not an Inspector admission test.
	if allocations > files+8 {
		t.Fatalf("per-file scratch allocations remain: got %.0f, maximum %d", allocations, files+8)
	}
}

func BenchmarkRuntimeFileHashBatch(b *testing.B) {
	const files = 114
	data := bytes.Repeat([]byte{0x37}, 4096)
	file := runtimeHashFixture(b, data)
	want := sha256.Sum256(data)
	b.ReportAllocs()
	b.SetBytes(files * int64(len(data)))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		scratch := make([]byte, runtimeHashScratchSize)
		for index := 0; index < files; index++ {
			if _, err := file.Seek(0, 0); err != nil {
				b.Fatal(err)
			}
			digest, count, err := hashRuntimeFile(context.Background(), file, int64(len(data)), scratch)
			if err != nil || count != int64(len(data)) || digest != want {
				b.Fatal("digest batch changed", count, err)
			}
		}
	}
}
