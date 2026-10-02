//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Fixed disposable test only; never installed by a product package.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_RUNTIME_BUNDLE_FAILED")
		os.Exit(1)
	}
}

func run() error {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("fixture guard")
	}
	if len(os.Args) == 2 && os.Args[1] == "stage" && os.Getuid() == 0 && os.Geteuid() == 0 {
		return stageFixture()
	}
	if len(os.Args) != 1 || os.Getuid() != 1801 || os.Geteuid() != 1801 {
		return errors.New("fixture guard")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || len(status) > 64<<10 {
		return errors.New("credential evidence")
	}
	required := map[string]string{
		"CapInh:": "0000000000000000", "CapPrm:": "0000000000000000",
		"CapEff:": "0000000000000000", "CapBnd:": "0000000000000000",
		"CapAmb:": "0000000000000000", "NoNewPrivs:": "1",
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if expected, found := required[fields[0]]; found {
			if fields[1] != expected {
				return errors.New("unexpected authority")
			}
			delete(required, fields[0])
		}
	}
	if len(required) != 0 {
		return errors.New("incomplete authority evidence")
	}
	files, aliases, err := inputs()
	if err != nil {
		return err
	}
	p, err := runtimebundle.NewPlan(files, aliases)
	if err != nil {
		return err
	}
	root := os.NewFile(3, "fixed-readonly-runtime-root")
	defer root.Close()
	got, err := p.Inspect(context.Background(), root)
	if err != nil || got.Files != len(files) || got.Aliases != len(aliases) {
		return errors.Join(errors.New("positive inspection"), err)
	}
	var total int64
	for _, file := range files {
		total += file.Size
	}
	if got.Bytes != total {
		return errors.New("byte accounting")
	}
	refuse := func(f []runtimebundle.File, a []runtimebundle.Alias) error {
		bad, err := runtimebundle.NewPlan(f, a)
		if err != nil {
			return errors.New("negative input must itself be valid")
		}
		observation, err := bad.Inspect(context.Background(), root)
		if !errors.Is(err, runtimebundle.ErrMismatch) || observation != (runtimebundle.Observation{}) {
			return errors.New("negative inspection")
		}
		return nil
	}
	wrongHash := append([]runtimebundle.File(nil), files...)
	wrongHash[0].SHA256[0] ^= 1
	if err := refuse(wrongHash, aliases); err != nil {
		return err
	}
	wrongMode := append([]runtimebundle.File(nil), files...)
	wrongMode[0].Mode = 0444
	if err := refuse(wrongMode, aliases); err != nil {
		return err
	}
	wrongAlias := append([]runtimebundle.Alias(nil), aliases...)
	if len(wrongAlias) == 0 {
		return errors.New("actual aliases required")
	}
	for _, file := range files {
		if file.Path != wrongAlias[0].Target {
			wrongAlias[0].Target = file.Path
			break
		}
	}
	if err := refuse(files, wrongAlias); err != nil {
		return err
	}
	// Omit a real program and its aliases: undeclared existing runtime bytes must
	// refuse the entire observation, not return a partial dependency assessment.
	var missing []runtimebundle.File
	var remaining []runtimebundle.Alias
	for _, file := range files {
		if file.Path != "usr/sbin/smbd" {
			missing = append(missing, file)
		}
	}
	for _, alias := range aliases {
		if alias.Target != "usr/sbin/smbd" {
			remaining = append(remaining, alias)
		}
	}
	if len(missing) != len(files)-1 {
		return errors.New("fixed daemon path")
	}
	if err := refuse(missing, remaining); err != nil {
		return err
	}
	// A manifest may not reinterpret an actual symlink as a regular file.
	link := aliases[0]
	var target runtimebundle.File
	for _, file := range files {
		if file.Path == link.Target {
			target = file
		}
	}
	target.Path = link.Path
	retyped := append(append([]runtimebundle.File(nil), files...), target)
	if err := refuse(retyped, aliases[1:]); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if observation, err := p.Inspect(ctx, root); !errors.Is(err, context.Canceled) || observation != (runtimebundle.Observation{}) {
		return errors.New("cancellation")
	}
	fmt.Println("PHANTOWD_SAMBA_ROOT_BUNDLE_READY readonly=true complete_census=true hashes=true aliases=true refusals=5 scope=qemu-only")
	return nil
}

func inputs() ([]runtimebundle.File, []runtimebundle.Alias, error) {
	f, err := os.Open("/usr/lib/phantowd/qemu-samba-root.manifest")
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, (128<<10)+1))
	scanner.Buffer(make([]byte, 8192), 8192)
	objects := make(map[string]runtimebundle.File)
	bindings := make(map[string]bool)
	var aliases []runtimebundle.Alias
	bytes := 0
	for scanner.Scan() {
		line := scanner.Text()
		bytes += len(line) + 1
		fields := strings.Fields(line)
		if bytes > 128<<10 || len(fields) != 3 || len(bindings) >= 1024 ||
			!strings.HasPrefix(fields[1], "/") || !strings.HasPrefix(fields[2], "/") {
			return nil, nil, errors.New("bounded fixture manifest")
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != 32 {
			return nil, nil, errors.New("fixed digest")
		}
		canonical, alias := fields[1][1:], fields[2][1:]
		if bindings[alias] {
			return nil, nil, errors.New("duplicate binding")
		}
		bindings[alias] = true
		var hash [32]byte
		copy(hash[:], digest)
		if old, exists := objects[canonical]; exists {
			if old.SHA256 != hash {
				return nil, nil, errors.New("conflicting object")
			}
		} else {
			objects[canonical] = runtimebundle.File{Path: canonical, SHA256: hash, Size: 1, Mode: 0555}
		}
		if alias != canonical {
			aliases = append(aliases, runtimebundle.Alias{Path: alias, Target: canonical})
		}
	}
	if scanner.Err() != nil {
		return nil, nil, scanner.Err()
	}
	var files []runtimebundle.File
	for _, file := range objects {
		files = append(files, file)
	}
	// Validate all manifest paths/conflicts before any base-object lookup. The
	// placeholder sizes validate topology only; actual bounded sizes are checked
	// again by the final Plan. No canonical-file lookup may traverse a symlink.
	if _, err := runtimebundle.NewPlan(files, aliases); err != nil {
		return nil, nil, err
	}
	base, err := stageRoot("/")
	if err != nil {
		return nil, nil, err
	}
	defer base.Close()
	for i := range files {
		fd, err := unix.Openat2(int(base.Fd()), files[i].Path, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
		})
		if err != nil {
			return nil, nil, errors.New("base object lookup")
		}
		object := os.NewFile(uintptr(fd), "fixed-base-object")
		info, statErr := object.Stat()
		closeErr := object.Close()
		if statErr != nil || closeErr != nil || !info.Mode().IsRegular() {
			return nil, nil, errors.New("base object")
		}
		// This is the original guest base, not the copy under inspection. These
		// observed fixture sizes still do not authenticate a product manifest.
		files[i].Size = info.Size()
	}
	return files, aliases, nil
}
