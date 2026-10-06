#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Apply the exact Buildroot 2025.02.18 util-linux patch set to a disposable
# extracted fixture tree. Never mutate the cached source or Buildroot tree.
set -eu
source_tree=${1:?disposable extracted util-linux source}
patch_dir=${2:?trusted Buildroot util-linux package directory}
export LC_ALL=C
expected=08c78836f0005d1432d7376ad5cc284fb09f9782471676fb754cee9a0f95ac65
actual=$(cd "$patch_dir" && sha256sum ./*.patch | sed 's|  ./|  |' | sha256sum)
test "${actual%% *}" = "$expected" || {
    echo 'Unexpected Buildroot util-linux patch set; fixture qualification refused' >&2
    exit 1
}
for file in "$patch_dir"/*.patch; do
    patch --directory "$source_tree" --strip=1 --fuzz=0 --batch --forward < "$file"
done
# Buildroot's package patches change configure.ac and Makefile inputs too.
# Regenerate them with the trusted baseline host tools supplied on PATH.
# Match Buildroot's no-documentation/no-translation autoreconf environment.
(cd "$source_tree" && GTKDOCIZE=/bin/true AUTOPOINT=/bin/true autoreconf -fi)
