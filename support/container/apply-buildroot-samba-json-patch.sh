#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

buildroot_source=${1:?Buildroot source directory required}
patch_file=${2:?version-pinned Samba JSON patch required}
config_file="$buildroot_source/package/samba4/Config.in"
make_file="$buildroot_source/package/samba4/samba4.mk"

for file in "$config_file" "$make_file" "$patch_file"; do
	[ -f "$file" ] || {
		echo "Buildroot Samba patch input is missing: $file" >&2
		exit 1
	}
done

count_matches() {
	pattern=$1
	file=$2
	grep -F -c -- "$pattern" "$file" || true
}

original_option='SAMBA4_CONF_OPTS += --without-ad-dc --without-json'
patched_option='SAMBA4_CONF_OPTS += --without-ad-dc --with-json'
original_dependencies='cmocka e2fsprogs gnutls popt zlib'
patched_dependencies='cmocka e2fsprogs gnutls jansson popt zlib'
original_option_count=$(count_matches "$original_option" "$make_file")
patched_option_count=$(count_matches "$patched_option" "$make_file")
original_dependency_count=$(count_matches "$original_dependencies" "$make_file")
patched_dependency_count=$(count_matches "$patched_dependencies" "$make_file")
jansson_select_count=$(count_matches 'select BR2_PACKAGE_JANSSON' "$config_file")

if [ "$original_option_count" = 1 ] && [ "$patched_option_count" = 0 ] \
	&& [ "$original_dependency_count" = 1 ] && [ "$patched_dependency_count" = 0 ] \
	&& [ "$jansson_select_count" = 1 ]; then
	patch --directory "$buildroot_source" --strip=1 --fuzz=0 --forward \
		--batch --dry-run < "$patch_file" >/dev/null
	patch --directory "$buildroot_source" --strip=1 --fuzz=0 --forward \
		--batch < "$patch_file" >&2
	result=applied
elif [ "$original_option_count" = 0 ] && [ "$patched_option_count" = 1 ] \
	&& [ "$original_dependency_count" = 0 ] && [ "$patched_dependency_count" = 1 ] \
	&& [ "$jansson_select_count" = 2 ]; then
	result=already-applied
else
	echo 'Buildroot Samba package does not match either pinned patch state' >&2
	exit 1
fi

[ "$(count_matches "$original_option" "$make_file")" = 0 ]
[ "$(count_matches "$patched_option" "$make_file")" = 1 ]
[ "$(count_matches "$original_dependencies" "$make_file")" = 0 ]
[ "$(count_matches "$patched_dependencies" "$make_file")" = 1 ]
[ "$(count_matches 'select BR2_PACKAGE_JANSSON' "$config_file")" = 2 ]
printf '%s\n' "$result"
