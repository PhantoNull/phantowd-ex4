//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func sampleStat() unix.Statx_t {
	return unix.Statx_t{Mask: unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE,
		Mnt_id: 17, Ino: 23, Mode: unix.S_IFREG | 0600, Nlink: 1, Uid: 1000, Gid: 1000, Size: 4096, Blocks: 8}
}

func TestObservedRequiresCompleteRegularSingleLinkMetadata(t *testing.T) {
	fs := unix.Statfs_t{Type: unix.EXT4_SUPER_MAGIC}
	for _, bit := range []uint32{unix.STATX_TYPE, unix.STATX_INO, unix.STATX_MNT_ID_UNIQUE, unix.STATX_MODE,
		unix.STATX_NLINK, unix.STATX_UID, unix.STATX_GID, unix.STATX_SIZE, unix.STATX_BLOCKS} {
		st := sampleStat()
		st.Mask &^= bit
		if id, obs, err := observed(st, fs, true); !errors.Is(err, ErrUnavailable) || id != (identity{}) || obs != (Observation{}) {
			t.Fatalf("missing bit %x: %v", bit, err)
		}
	}
	for _, mutate := range []func(*unix.Statx_t){
		func(s *unix.Statx_t) { s.Mnt_id = 0 }, func(s *unix.Statx_t) { s.Ino = 0 },
		func(s *unix.Statx_t) { s.Mode = unix.S_IFDIR }, func(s *unix.Statx_t) { s.Mode = unix.S_IFIFO },
		func(s *unix.Statx_t) { s.Mode = unix.S_IFLNK }, func(s *unix.Statx_t) { s.Mode = unix.S_IFBLK },
		func(s *unix.Statx_t) { s.Nlink = 0 }, func(s *unix.Statx_t) { s.Nlink = 2 },
		func(s *unix.Statx_t) { s.Size = math.MaxInt64 + 1 }, func(s *unix.Statx_t) { s.Blocks = math.MaxInt64/512 + 1 },
	} {
		st := sampleStat()
		mutate(&st)
		if id, obs, err := observed(st, fs, true); !errors.Is(err, ErrUnavailable) || id != (identity{}) || obs != (Observation{}) {
			t.Fatalf("invalid metadata: %v", err)
		}
	}
	st := sampleStat()
	id, obs, err := observed(st, fs, true)
	if err != nil || obs.SizeBytes() != 4096 || obs.AllocatedBytes() != 4096 || obs.FilesystemReadOnly() {
		t.Fatalf("observation: %+v %v", obs, err)
	}
	// Same-sized writes/allocation are not identity drift or content immutability.
	st.Blocks = 0
	st.Ctime.Sec++
	st.Mtime.Sec++
	changed, sparse, err := observed(st, fs, true)
	if err != nil || id != changed || sparse.AllocatedBytes() != 0 {
		t.Fatal("allocation/content time is not file identity")
	}
	fs.Flags = unix.ST_RDONLY
	ro, obs, err := observed(st, fs, true)
	if err != nil || ro == id || !obs.FilesystemReadOnly() || sameMount(id, ro) {
		t.Fatal("read-only flags must change identity")
	}
	for _, change := range []func(*identity){
		func(i *identity) { i.mount++ }, func(i *identity) { i.major++ }, func(i *identity) { i.minor++ }, func(i *identity) { i.filesystem++ },
	} {
		other := id
		change(&other)
		if sameMount(id, other) {
			t.Fatal("different mount accepted")
		}
	}
	st = sampleStat()
	st.Mode = unix.S_IFDIR
	if _, _, err := observed(st, fs, false); err != nil {
		t.Fatal(err)
	}
	st.Mode = unix.S_IFREG
	if _, _, err := observed(st, fs, false); !errors.Is(err, ErrUnavailable) {
		t.Fatal("regular parent accepted")
	}
}

// This is not a qualified filesystem. Native tests exercise lifecycle plumbing
// with actual O_PATH/statx; the real mountguard/UUID test runs separately in QEMU.
type testRoot struct {
	mu     sync.Mutex
	path   string
	failed bool
	calls  int
}

func (r *testRoot) Verify() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed {
		return ErrUnavailable
	}
	return nil
}
func (r *testRoot) OpenDirectory(relative string) (*os.File, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.failed {
		return nil, ErrUnavailable
	}
	fd, err := unix.Open(r.path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	child, err := unix.Openat2(fd, relative, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(child), "native-test-root"), nil
}
func nativeRoot(t *testing.T) *testRoot {
	t.Helper()
	r := &testRoot{path: t.TempDir()}
	f, err := r.OpenDirectory(".")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st unix.Statx_t
	if err := unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mask&unix.STATX_MNT_ID_UNIQUE == 0 {
		t.Skip("native kernel lacks unique mount IDs; mandatory real-root ARMv5 fixture covers positive lifecycle")
	}
	return r
}
func backing(t *testing.T, name string) {
	t.Helper()
	if err := os.WriteFile(name, make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
}
func pinned(t *testing.T, r *testRoot, relative string) *Pin {
	t.Helper()
	p, obs, err := openWith(r, relative, 4096)
	if err != nil || p == nil || obs.SizeBytes() != 4096 {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestInvalidSelectionHasNoEffects(t *testing.T) {
	if _, err := json.Marshal(Pin{}); err == nil {
		t.Fatal("pin value serializable")
	}
	r := &testRoot{}
	for _, relative := range []string{"", ".", "..", "/file", "a/../file", "a//file", "a\\file", "file\x00"} {
		if p, obs, err := openWith(r, relative, 4096); p != nil || obs != (Observation{}) || !errors.Is(err, ErrInvalid) {
			t.Fatalf("path %q: %v", relative, err)
		}
	}
	for _, size := range []uint64{0, 1, 511, 513, math.MaxUint64} {
		if _, _, err := openWith(r, "file", size); !errors.Is(err, ErrInvalid) {
			t.Fatal(size, err)
		}
	}
	if r.calls != 0 {
		t.Fatal("invalid input opened root")
	}
	if _, _, err := Open(nil, "file", 4096); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestUnsafeObjectsAndMissingBackingNeverCreate(t *testing.T) {
	r := nativeRoot(t)
	backing(t, filepath.Join(r.path, "file"))
	if err := os.Symlink("file", filepath.Join(r.path, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(r.path, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("directory", filepath.Join(r.path, "parent-link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(r.path, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "link", "directory", "fifo", "parent-link/file"} {
		if p, obs, err := openWith(r, name, 4096); p != nil || obs != (Observation{}) || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(r.path, "missing")); !os.IsNotExist(err) {
		t.Fatal("missing backing recreated")
	}
	if _, _, err := openWith(r, "file", 8192); !errors.Is(err, ErrUnavailable) {
		t.Fatal("wrong capacity accepted")
	}
	if err := os.Link(filepath.Join(r.path, "file"), filepath.Join(r.path, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openWith(r, "file", 4096); !errors.Is(err, ErrUnavailable) {
		t.Fatal("hardlinked file accepted")
	}
}

func TestMetadataPinCannotReadWriteAndCloseIsSerialized(t *testing.T) {
	r := nativeRoot(t)
	backing(t, filepath.Join(r.path, "file"))
	p := pinned(t, r, "file")
	if _, err := unix.Read(int(p.file.Fd()), make([]byte, 1)); !errors.Is(err, unix.EBADF) {
		t.Fatal("O_PATH read:", err)
	}
	if _, err := unix.Write(int(p.file.Fd()), []byte{1}); !errors.Is(err, unix.EBADF) {
		t.Fatal("O_PATH write:", err)
	}
	if err := os.WriteFile(filepath.Join(r.path, "file"), make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(); err != nil {
		t.Fatal("same size content write is not identity drift:", err)
	}
	for _, value := range []any{p, Observation{}, &Observation{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private handle serializable")
		}
	}
	if err := json.Unmarshal([]byte(`{}`), p); err == nil {
		t.Fatal("pin deserializable")
	}
	var obs Observation
	if err := json.Unmarshal([]byte(`{}`), &obs); err == nil {
		t.Fatal("observation deserializable")
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, err := p.Verify()
				if err != nil && !errors.Is(err, ErrClosed) {
					t.Error(err)
				}
			}
			if err := p.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if obs, err := p.Verify(); obs != (Observation{}) || !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := r.Verify(); err != nil {
		t.Fatal("borrowed root closed")
	}
	var nilPin *Pin
	if err := nilPin.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := nilPin.Verify(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestObservedDriftPermanentlyQuarantinesRetainedPin(t *testing.T) {
	for _, kind := range []string{"replace", "unlink", "truncate", "mode", "hardlink", "parent", "root"} {
		t.Run(kind, func(t *testing.T) {
			r := nativeRoot(t)
			dir := filepath.Join(r.path, "parent")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "file")
			backing(t, file)
			p := pinned(t, r, "parent/file")
			var err error
			switch kind {
			case "replace":
				err = os.Rename(file, file+".old")
				if err == nil {
					backing(t, file)
				}
			case "unlink":
				err = os.Remove(file)
			case "truncate":
				err = os.Truncate(file, 8192)
			case "mode":
				err = os.Chmod(file, 0640)
			case "hardlink":
				err = os.Link(file, file+".alias")
			case "parent":
				err = os.Rename(dir, dir+".old")
				if err == nil {
					err = os.Mkdir(dir, 0700)
				}
				if err == nil {
					backing(t, file)
				}
			case "root":
				r.mu.Lock()
				r.failed = true
				r.mu.Unlock()
			}
			if err != nil {
				t.Fatal(err)
			}
			if obs, err := p.Verify(); obs != (Observation{}) || !errors.Is(err, ErrReview) {
				t.Fatalf("%s: %v", kind, err)
			}
			if p.parent == nil || p.file == nil {
				t.Fatal("quarantine released retained references")
			}
			var st unix.Statx_t
			if err := unix.Statx(int(p.file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_TYPE, &st); err != nil {
				t.Fatal("retained reference closed", err)
			}
			switch kind {
			case "replace":
				err = os.Remove(file)
				if err == nil {
					err = os.Rename(file+".old", file)
				}
			case "truncate":
				err = os.Truncate(file, 4096)
			case "mode":
				err = os.Chmod(file, 0600)
			case "hardlink":
				err = os.Remove(file + ".alias")
			case "root":
				r.mu.Lock()
				r.failed = false
				r.mu.Unlock()
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Verify(); !errors.Is(err, ErrReview) {
				t.Fatal("restoration revived reviewed pin")
			}
		})
	}
}

func TestCloseUncertaintyRemainsExplicitWithoutRetry(t *testing.T) {
	r := nativeRoot(t)
	backing(t, filepath.Join(r.path, "file"))
	p, _, err := openWith(r, "file", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.file.Close(); err != nil {
		t.Fatal(err)
	} // Deliberate private test seam, not public API.
	if err := p.Close(); !errors.Is(err, ErrReview) {
		t.Fatal(err)
	}
	if err := p.Close(); !errors.Is(err, ErrReview) {
		t.Fatal("uncertain close silently rehabilitated", err)
	}
	if p.file != nil || p.parent != nil || p.root != nil {
		t.Fatal("closed pin retains references")
	}
}
