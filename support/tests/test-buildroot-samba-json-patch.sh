#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

buildroot_source=${1:?usage: test-buildroot-samba-json-patch.sh BUILDROOT_SOURCE}
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
patch_file="$repo_root/support/buildroot-patches/2025.02.18/0002-samba4-json-without-ad-dc.patch"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-samba-json-patch.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM

mkdir -p "$temporary/package/samba4"
cp "$buildroot_source/package/samba4/Config.in" "$temporary/package/samba4/Config.in"
cp "$buildroot_source/package/samba4/samba4.mk" "$temporary/package/samba4/samba4.mk"

if grep -F -q -- 'SAMBA4_CONF_OPTS += --without-ad-dc --with-json' \
	"$temporary/package/samba4/samba4.mk"; then
	patch --directory "$temporary" --strip=1 --fuzz=0 --reverse --batch \
		< "$patch_file" >/dev/null
fi

first=$(sh "$repo_root/support/container/apply-buildroot-samba-json-patch.sh" \
	"$temporary" "$patch_file")
second=$(sh "$repo_root/support/container/apply-buildroot-samba-json-patch.sh" \
	"$temporary" "$patch_file")
[ "$first" = applied ]
[ "$second" = already-applied ]
grep -F 'select BR2_PACKAGE_JANSSON' "$temporary/package/samba4/Config.in" >/dev/null
grep -F 'SAMBA4_CONF_OPTS += --without-ad-dc --with-json' \
	"$temporary/package/samba4/samba4.mk" >/dev/null
grep -F 'cmocka e2fsprogs gnutls jansson popt zlib' \
	"$temporary/package/samba4/samba4.mk" >/dev/null
if grep -F -q 'SAMBA4_CONF_OPTS += --without-ad-dc --without-json' \
	"$temporary/package/samba4/samba4.mk"; then
	echo 'Samba JSON patch left JSON disabled' >&2
	exit 1
fi
if grep -Fx 'BR2_PACKAGE_SAMBA4_AD_DC=y' \
	"$repo_root/configs/phantowd_qemu_armv5_defconfig" >/dev/null; then
	echo 'QEMU profile must not enable the Active Directory Domain Controller' >&2
	exit 1
fi

printf 'Buildroot Samba JSON patch and idempotence checks passed\n'
