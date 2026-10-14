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
	"io"
	"os"
	"testing"
)

// Calculation-only control: vary the read/write schedule, not the algorithm.
// This is deliberately test-only and cannot inspect or admit a runtime tree.
// Different chunk sizes also change cancellation/read-ahead granularity; a
// faster control is not itself permission to replace the production helper.
func runtimeHashScheduleControl(ctx context.Context, file *os.File, size int64, scratch []byte) ([32]byte, int64, error) {
	if ctx == nil || file == nil || size <= 0 || size > maxBytes || len(scratch) == 0 {
		return [32]byte{}, 0, ErrInvalid
	}
	hash := sha256.New()
	reader := io.LimitReader(file, size+1)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return [32]byte{}, 0, err
		}
		count, err := reader.Read(scratch)
		if count > 0 {
			_, _ = hash.Write(scratch[:count])
			total += int64(count)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return [32]byte{}, 0, ErrUnavailable
		}
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(scratch[:0]))
	if err := ctx.Err(); err != nil {
		return [32]byte{}, 0, err
	}
	return digest, total, nil
}

func TestRuntimeFileHashScheduleControlMatchesBoundedProductionDigest(t *testing.T) {
	for _, chunk := range []int{32 << 10, 64 << 10, 128 << 10, 256 << 10} {
		for _, length := range []int{1, chunk - 1, chunk, chunk + 1, 2*chunk + 17} {
			for _, declared := range []int{1, length, length + 17} {
				t.Run(fmt.Sprintf("%d/%d/%d", chunk, length, declared), func(t *testing.T) {
					data := bytes.Repeat([]byte{0x37}, length)
					file := runtimeHashFixture(t, data)
					want, wantCount, wantErr := hashRuntimeFile(context.Background(), file, int64(declared), make([]byte, runtimeHashScratchSize))
					if _, err := file.Seek(0, 0); err != nil {
						t.Fatal(err)
					}
					got, gotCount, gotErr := runtimeHashScheduleControl(context.Background(), file, int64(declared), make([]byte, chunk))
					if wantErr != nil || gotErr != nil || got != want || gotCount != wantCount {
						t.Fatal("calculation control differs", wantCount, gotCount, wantErr, gotErr)
					}
				})
			}
		}
	}
}

func BenchmarkRuntimeFileHashReadSchedule(b *testing.B) {
	data := bytes.Repeat([]byte{0x37}, 16<<20)
	want := sha256.Sum256(data)
	for _, lane := range []string{"Original32KiB", "Control32KiB", "Control64KiB", "Control128KiB", "Control256KiB"} {
		b.Run(lane, func(b *testing.B) {
			chunk := map[string]int{"Original32KiB": runtimeHashScratchSize, "Control32KiB": 32 << 10,
				"Control64KiB": 64 << 10, "Control128KiB": 128 << 10, "Control256KiB": 256 << 10}[lane]
			file := runtimeHashFixture(b, data)
			scratch := make([]byte, chunk)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := file.Seek(0, 0); err != nil {
					b.Fatal(err)
				}
				var digest [32]byte
				var count int64
				var err error
				if lane == "Original32KiB" {
					digest, count, err = hashRuntimeFile(context.Background(), file, int64(len(data)), scratch)
				} else {
					digest, count, err = runtimeHashScheduleControl(context.Background(), file, int64(len(data)), scratch)
				}
				if err != nil || digest != want || count != int64(len(data)) {
					b.Fatal("bounded schedule digest changed", count, err)
				}
			}
		})
	}
}
