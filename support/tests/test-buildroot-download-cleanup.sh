#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -euo pipefail

# Execute the actual Buildroot function on disposable regular files, not a
# reimplementation. Its documented success contract removes CWD temporaries.
helper=${1:?usage: test-buildroot-download-cleanup.sh HELPERS}
[[ -f "$helper" && ! -L "$helper" ]] || exit 1
helper=$(realpath -- "$helper")
scratch=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-download-cleanup.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$scratch/input" "$scratch/cwd" "$scratch/output"
printf 'included archive input\n' >"$scratch/input/kept file"
printf 'excluded archive input\n' >"$scratch/input/excluded"
printf 'unrelated CWD file\n' >"$scratch/cwd/keep-me"
before=$(sha256sum "$scratch/input/kept file" "$scratch/input/excluded" \
    "$scratch/cwd/keep-me")
# shellcheck disable=SC1090
source "$helper"
export TAR=tar
cd "$scratch/cwd"
for attempt in 1 2; do
    mk_tar_gz "$scratch/input" 'fixture-1.0' \
        '1970-01-01T00:00:00Z' "$scratch/output/$attempt.tar.gz" 'excluded'
    if [[ "$(find . -mindepth 1 -maxdepth 1 -printf '%f\n')" != keep-me ]]; then
        echo 'Successful archive left undeclared CWD entries' >&2
        find . -mindepth 1 -maxdepth 1 -printf '%f\n' >&2
        exit 1
    fi
    [[ "$(tar tzf "$scratch/output/$attempt.tar.gz")" == \
        'fixture-1.0/kept file' ]]
    [[ "$(tar xOf "$scratch/output/$attempt.tar.gz" \
        'fixture-1.0/kept file')" == 'included archive input' ]]
done
cmp "$scratch/output/1.tar.gz" "$scratch/output/2.tar.gz"
[[ "$(sha256sum "$scratch/input/kept file" "$scratch/input/excluded" \
    "$scratch/cwd/keep-me")" == "$before" ]]
printf 'Buildroot archive success cleanup, content, exclusion and reproducibility passed\n'
