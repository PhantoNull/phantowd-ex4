#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Exercise the real pinned staging boundary, including the CI TMPDIR layout.
set -eu
[ "$#" -eq 2 ] || exit 1
debugfs=$1 source_dir=$2
fixture="$source_dir/support/tests/test-samba-root-staging.sh"
# This positive control must succeed before testing refusal-only paths. The
# parent supplies bounded tmpfs; do not fall back to a writable container layer.
sh "$fixture" "$debugfs" "$source_dir"
qualified=$(CDPATH='' cd -P "${TMPDIR:-/tmp}" && pwd -P)
scratch=$(mktemp -d "$qualified/phantowd-staging-env.XXXXXX")
mkdir "$scratch/nested"
ln -s /proc "$scratch/proc-link"
trap 'rm -f "$scratch/proc-link"; rmdir "$scratch/nested" "$scratch"' EXIT
# Descendants of the actual tmpfs are legitimate too.
TMPDIR="$scratch/nested" sh "$fixture" "$debugfs" "$source_dir"
for rejected in relative /proc /phantowd-staging-missing-directory \
    "$scratch/proc-link" "$scratch/../../proc"; do
    if TMPDIR="$rejected" sh "$fixture" "$debugfs" "$source_dir"; then
        echo 'Samba staging accepted an unqualified scratch directory' >&2
        exit 1
    fi
done
echo 'PHANTOWD_SAMBA_STAGING_ENV_READY supplied_tmpfs=true descendant=true relative_refused=true non_tmpfs_refused=true missing_refused=true symlink_escape_refused=true traversal_escape_refused=true scope=host-only'
