#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

# Supplement legal-info with the original archive already authenticated by the
# build driver. No download, extraction, legal-compliance claim or device path.
# The caller owns and serializes the input/output workspace directories.
archive=${1:?usage: collect-buildroot-source.sh ARCHIVE LEGAL_INFO VERSION SHA256}
legal_dir=${2:?legal-info directory required}
version=${3:?Buildroot version required}
expected_hash=${4:?pinned archive SHA256 required}

case "$version" in
    ''|*[!0-9.]*) echo 'Invalid Buildroot version' >&2; exit 1 ;;
esac
printf '%s\n' "$version" | grep -Eq '^[0-9]{4}\.[0-9]{2}(\.[0-9]{1,2})?$' || {
    echo 'Invalid Buildroot version' >&2
    exit 1
}
case "$expected_hash" in
    ''|*[!0-9a-f]*) echo 'Invalid pinned archive SHA256' >&2; exit 1 ;;
esac
[ "${#expected_hash}" -eq 64 ] || {
    echo 'Invalid pinned archive SHA256' >&2
    exit 1
}

name="buildroot-$version.tar.xz"
if [ "$(basename -- "$archive")" != "$name" ] ||
    [ ! -f "$archive" ] || [ -L "$archive" ]; then
    echo 'Buildroot archive is missing, symlinked or incorrectly named' >&2
    exit 1
fi
if [ ! -d "$legal_dir" ] || [ -L "$legal_dir" ]; then
    echo 'Existing real legal-info directory required' >&2
    exit 1
fi
for required in README buildroot.config manifest.csv host-manifest.csv; do
    if [ ! -f "$legal_dir/$required" ] || [ -L "$legal_dir/$required" ]; then
        echo 'Incomplete or symlinked legal-info metadata' >&2
        exit 1
    fi
done
printf '%s  %s\n' "$expected_hash" "$archive" | sha256sum --check --status || {
    echo 'Buildroot archive differs from its pinned hash' >&2
    exit 1
}

destination_dir="$legal_dir/phantowd-build-inputs"
if [ -e "$destination_dir" ] || [ -L "$destination_dir" ]; then
    if [ ! -d "$destination_dir" ] || [ -L "$destination_dir" ]; then
        echo 'Source collection directory is not a real directory' >&2
        exit 1
    fi
else
    mkdir -m 0755 -- "$destination_dir"
fi
destination="$destination_dir/$name"
if [ -e "$destination" ] || [ -L "$destination" ]; then
    if [ ! -f "$destination" ] || [ -L "$destination" ]; then
        echo 'Existing collected source is not a regular non-symlink file' >&2
        exit 1
    fi
    if ! printf '%s  %s\n' "$expected_hash" "$destination" | sha256sum --check --status; then
        echo 'Existing collected source differs; refusing replacement' >&2
        exit 1
    fi
else
    umask 077
    temporary=$(mktemp "$destination_dir/.buildroot-source.XXXXXX")
    trap 'rm -f -- "$temporary"' EXIT
    cp -- "$archive" "$temporary"
    # Check the copied bytes too, not just the earlier pathname observation.
    printf '%s  %s\n' "$expected_hash" "$temporary" | sha256sum --check --status || {
        echo 'Copied Buildroot source differs from its pinned hash' >&2
        exit 1
    }
    chmod 0644 "$temporary"
    # Same-filesystem hardlink publication is atomic and cannot replace a
    # concurrently created output. The owned temporary file is always removed.
    ln -T -- "$temporary" "$destination"
fi
printf 'PHANTOWD_BUILDROOT_SOURCE_COLLECTED version=%s sha256=%s compliance_qualified=false\n' \
    "$version" "$expected_hash"
