#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

[ "$#" = 2 ] || exit 1
go_binary=$1
expected=$2
printf '%s\n' "$expected" | LC_ALL=C grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || exit 1
# Do not download another toolchain or use per-user Go configuration to hide
# the version installed by Buildroot. Run before native tests or target build.
actual=$(GOENV=off GOTOOLCHAIN=local GOWORK=off "$go_binary" version)
case "$actual" in
    "go version go$expected linux/386" | "go version go$expected linux/amd64" | \
    "go version go$expected linux/arm" | "go version go$expected linux/arm64" | \
    "go version go$expected linux/ppc64le" | "go version go$expected linux/s390x") ;;
    *) echo "Installed Go SDK does not match the selected Linux Go $expected pin" >&2; exit 1 ;;
esac
printf 'Selected Go SDK verified: %s\n' "$actual"
