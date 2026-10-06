// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"golang.org/x/sys/unix"
)

func TestBundleFailureNeverPublishesSplitComponents(t *testing.T) {
	codec := Codec[fileservice.Config]{CurrentName: "file-services.json", PendingName: ".file-services.pending",
		MaxBytes: fileservice.MaxConfigBytes, Decode: fileservice.DecodeConfig, Validate: fileservice.Config.Validate,
		Revision: func(c fileservice.Config) uint64 { return c.Revision }}
	makePolicy := func(r uint64) fileservice.Config {
		return fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: r, Shares: policy(r),
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: r, VolumeRevision: r, Exports: []nfsconfig.Export{}}}
	}
	for _, stage := range []string{"write", "sync", "close", "rename", "rename-after-publication", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			s, err := OpenWithCodec(dir, codec)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.Commit(0, makePolicy(1)); err != nil {
				t.Fatal(err)
			}
			wantError, revision := ErrIO, uint64(1)
			switch stage {
			case "write":
				s.io.write = func(f *os.File, data []byte) (int, error) { n, _ := f.Write(data[:8]); return n, unix.ENOSPC }
			case "sync":
				s.io.sync = func(*os.File) error { return unix.EIO }
			case "close":
				s.io.close = func(f *os.File) error { f.Close(); return unix.EIO }
			case "rename":
				wantError = ErrUncertain
				s.io.rename = func(int, string, int, string) error { return unix.EIO }
			case "rename-after-publication":
				wantError, revision = ErrUncertain, 2
				s.io.rename = func(a int, b string, c int, d string) error {
					if err := unix.Renameat(a, b, c, d); err != nil {
						t.Fatal(err)
					}
					return unix.EIO
				}
			case "directory-sync":
				wantError, revision = ErrUncertain, 2
				s.io.syncDir = func(int) error { return unix.EIO }
			}
			if err := s.Commit(1, makePolicy(2)); !errors.Is(err, wantError) {
				t.Fatal(err)
			}
			if wantError == ErrUncertain {
				if _, err := s.Load(); !errors.Is(err, ErrUncertain) {
					t.Fatal("uncertainty lost", err)
				}
				if err := s.Commit(2, makePolicy(3)); !errors.Is(err, ErrUncertain) {
					t.Fatal("retry accepted", err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenWithCodec(dir, codec)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			got, err := reopened.Load()
			if err != nil || !reflect.DeepEqual(got, makePolicy(revision)) {
				t.Fatal("split or unexpected policy", got, err)
			}
		})
	}
}
