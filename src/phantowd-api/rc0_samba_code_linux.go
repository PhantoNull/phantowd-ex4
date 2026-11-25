// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

const rc0SambaCodeBundle = "usr/lib/phantowd-samba-code"

func verifyRC0SambaCode(ctx context.Context) (result error) {
	if developmentBrowserEnrollment || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRC0Review
	}
	image, err := os.Open("/")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, image.Close()) }()
	bundle, err := openRC0Role(image, rc0SambaCodeBundle, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, bundle.Close()) }()
	manifest, err := openRC0Role(bundle, "manifest.json", unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, manifest.Close()) }()
	var st unix.Stat_t
	var fs unix.Statfs_t
	fd := int(manifest.Fd())
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0444 || st.Nlink != 1 ||
		st.Uid != 0 || st.Gid != 0 || st.Size <= 0 || st.Size > runtimebundle.SambaManifestLimit ||
		unix.Fstatfs(fd, &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 {
		return errRC0Review
	}
	plan, err := runtimebundle.DecodeSambaCodeManifest(manifest)
	if err != nil {
		return err
	}
	code, err := openRC0Role(bundle, "root", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, code.Close()) }()
	_, err = plan.Inspect(ctx, code)
	return err
}
