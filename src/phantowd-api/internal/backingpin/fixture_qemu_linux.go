//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"golang.org/x/sys/unix"
)

// RunQEMUFixture exercises actual retained O_PATH references below the caller's
// disposable qualified ext mount. The QEMU-only caller supplies the fixture,
// never HTTP, registry diagnostics, production storage or a target backend.
func RunQEMUFixture(root *mountguard.Root, anchor string) (result error) {
	workspace, err := os.MkdirTemp(anchor, "backing-pin-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(workspace)) }()
	parent := filepath.Base(workspace)
	write := func(file string) error { return os.WriteFile(file, make([]byte, 4096), 0600) }
	file := workspace + "/file"
	if err := write(file); err != nil {
		return err
	}
	p, observation, err := Open(root, parent+"/file", 4096)
	if err != nil || observation.SizeBytes() != 4096 {
		return fmt.Errorf("metadata pin open: %w", err)
	}
	defer func() { result = errors.Join(result, p.Close()) }()
	if _, err := unix.Read(int(p.file.Fd()), make([]byte, 1)); !errors.Is(err, unix.EBADF) {
		return errors.New("metadata pin could read data")
	}
	if _, err := unix.Write(int(p.file.Fd()), []byte{1}); !errors.Is(err, unix.EBADF) {
		return errors.New("metadata pin could write data")
	}
	if _, err := json.Marshal(p); err == nil {
		return errors.New("pin serializable")
	}
	if _, err := json.Marshal(Pin{}); err == nil {
		return errors.New("pin value serializable")
	}
	if _, err := json.Marshal(observation); err == nil {
		return errors.New("metadata serializable")
	}
	if err := write(file); err != nil {
		return err
	}
	if _, err := p.Verify(); err != nil {
		return errors.New("same-size content write misreported as identity drift")
	}
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				_, err := p.Verify()
				if err != nil && !errors.Is(err, ErrClosed) {
					failures <- err
					return
				}
			}
			if err := p.Close(); err != nil {
				failures <- err
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		return err
	}
	if _, err := p.Verify(); !errors.Is(err, ErrClosed) {
		return errors.New("closed pin usable")
	}
	if err := root.Verify(); err != nil {
		return errors.New("pin closed borrowed root")
	}
	if err := os.Symlink("file", workspace+"/link"); err != nil {
		return err
	}
	if err := os.Mkdir(workspace+"/directory", 0700); err != nil {
		return err
	}
	if err := os.Symlink("directory", workspace+"/parent-link"); err != nil {
		return err
	}
	if err := unix.Mkfifo(workspace+"/fifo", 0600); err != nil {
		return err
	}
	for _, name := range []string{"missing", "link", "directory", "fifo", "parent-link/file"} {
		other, obs, err := Open(root, parent+"/"+name, 4096)
		if other != nil {
			other.Close()
			return errors.New("unsafe backing accepted")
		}
		if !errors.Is(err, ErrUnavailable) || obs != (Observation{}) {
			return errors.New("unsafe backing result not redacted")
		}
	}
	if _, err := os.Lstat(workspace + "/missing"); !os.IsNotExist(err) {
		return errors.New("missing backing recreated")
	}
	if other, _, err := Open(root, parent+"/file", 8192); err == nil {
		other.Close()
		return errors.New("wrong backing capacity accepted")
	}
	for _, kind := range []string{"replace", "unlink", "truncate", "mode", "uid", "gid", "hardlink", "parent"} {
		dir := workspace + "/" + kind
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
		file := dir + "/file"
		if err := write(file); err != nil {
			return err
		}
		other, _, err := Open(root, parent+"/"+kind+"/file", 4096)
		if err != nil {
			return err
		}
		if err := exerciseFixtureDrift(other, dir, file, kind, write); err != nil {
			other.Close()
			return fmt.Errorf("metadata %s: %w", kind, err)
		}
		if err := other.Close(); err != nil {
			return err
		}
	}
	// Explicit uncertainty is sticky even after idempotent close, without retry.
	other, _, err := Open(root, parent+"/file", 4096)
	if err != nil {
		return err
	}
	if err := other.file.Close(); err != nil {
		other.Close()
		return err
	}
	if err := other.Close(); !errors.Is(err, ErrReview) {
		return errors.New("uncertain close not reviewed")
	}
	if err := other.Close(); !errors.Is(err, ErrReview) {
		return errors.New("uncertain close rehabilitated")
	}
	return nil
}

func exerciseFixtureDrift(p *Pin, dir, file, kind string, write func(string) error) error {
	var err error
	switch kind {
	case "replace":
		err = os.Rename(file, file+".old")
		if err == nil {
			err = write(file)
		}
	case "unlink":
		err = os.Remove(file)
	case "truncate":
		err = os.Truncate(file, 8192)
	case "mode":
		err = os.Chmod(file, 0640)
	case "uid":
		err = os.Chown(file, 1000, -1)
	case "gid":
		err = os.Chown(file, -1, 1000)
	case "hardlink":
		err = os.Link(file, file+".alias")
	case "parent":
		err = os.Rename(dir, dir+".old")
		if err == nil {
			err = os.Mkdir(dir, 0700)
		}
		if err == nil {
			err = write(file)
		}
	}
	if err != nil {
		return err
	}
	if obs, err := p.Verify(); !errors.Is(err, ErrReview) || obs != (Observation{}) {
		return errors.New("drift accepted")
	}
	var st unix.Statx_t
	if err := unix.Statx(int(p.file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_TYPE, &st); err != nil {
		return errors.New("review released retained reference")
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
	case "uid":
		err = os.Chown(file, 0, -1)
	case "gid":
		err = os.Chown(file, -1, 0)
	case "hardlink":
		err = os.Remove(file + ".alias")
	case "parent":
		err = os.Remove(file)
		if err == nil {
			err = os.Remove(dir)
		}
		if err == nil {
			err = os.Rename(dir+".old", dir)
		}
	}
	if err != nil {
		return err
	}
	if _, err := p.Verify(); !errors.Is(err, ErrReview) {
		return errors.New("restoration revived reviewed pin")
	}
	return nil
}
