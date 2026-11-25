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

func verifyRC0SambaCode(ctx context.Context) error {
	code, err := openVerifiedRC0SambaCode(ctx)
	if err != nil {
		return err
	}
	return code.Close()
}

func openVerifiedRC0SambaCode(ctx context.Context) (verified *os.File, result error) {
	if developmentBrowserEnrollment || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, errRC0Review
	}
	image, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	bundle, err := openRC0Role(image, rc0SambaCodeBundle, unix.O_PATH|unix.O_DIRECTORY)
	if err := errors.Join(err, image.Close()); err != nil {
		if bundle != nil {
			err = errors.Join(err, bundle.Close())
		}
		return nil, err
	}
	defer func() {
		if err := bundle.Close(); err != nil {
			result = errors.Join(result, err)
			if verified != nil {
				result = errors.Join(result, verified.Close())
				verified = nil
			}
		}
	}()
	manifest, err := openRC0Role(bundle, "manifest.json", unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	fd := int(manifest.Fd())
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0444 || st.Nlink != 1 ||
		st.Uid != 0 || st.Gid != 0 || st.Size <= 0 || st.Size > runtimebundle.SambaManifestLimit ||
		unix.Fstatfs(fd, &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 {
		return nil, errors.Join(errRC0Review, manifest.Close())
	}
	plan, err := runtimebundle.DecodeSambaCodeManifest(manifest)
	if err := errors.Join(err, manifest.Close()); err != nil {
		return nil, err
	}
	code, err := openRC0Role(bundle, "root", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	if _, err := plan.Inspect(ctx, code); err != nil {
		return nil, errors.Join(err, code.Close())
	}
	return code, nil
}
