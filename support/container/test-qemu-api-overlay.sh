#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Optional fast integration lane; never a release/image builder.
# Run in the development container with source/base/compiler mounted read-only
# and a disposable writable /tmp. No block device or privileged container.
set -eu

base=${1:?usage: test-qemu-api-overlay.sh BASE_ARTIFACT_DIR GO_BINARY SOURCE_DIR UTIL_LINUX_ARCHIVE TARGET_CC UTIL_LINUX_PATCH_DIR}
go_binary=${2:?Go compiler required}
source_dir=${3:?source directory required}
probe_archive=${4:?pinned util-linux archive required}
target_cc=${5:?pinned Buildroot ARM compiler required}
patch_dir=${6:?trusted Buildroot util-linux package directory required}
for input in "$base" "$go_binary" "$source_dir" "$probe_archive" "$target_cc" "$patch_dir"; do
    case "$input" in *[!a-zA-Z0-9_./-]*|'') echo 'Unsupported input path' >&2; exit 1 ;; esac
done
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
# This checks artifact integrity, not signing/provenance. Obtain the base from
# an exact trusted successful project CI run and record that run separately.
(cd "$base" && sha256sum -c SHA256SUMS)
temporary=$(mktemp -d /tmp/phantowd-qemu-overlay.XXXXXX)
export TMPDIR="$temporary"
mkdir "$temporary/images"
cp "$base/rootfs.ext2" "$base/zImage" "$base/versatile-pb.dtb" "$temporary/images/"
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5
export GOCACHE="$temporary/go-cache" GOPATH="$temporary/go-path"
"$go_binary" version
(cd "$source_dir/src/phantowd-api" && "$go_binary" build -tags=qemu -trimpath -ldflags='-s -w' -o "$temporary/phantowd-api" .)
image="$temporary/images/rootfs.ext2"
replace_file() {
    from=$1
    to=$2
    mode=$3
    # Only this temporary regular-file copy is edited; the base stays intact.
    debugfs -w -R "rm $to" "$image" >/dev/null 2>&1
    debugfs -w -R "write $from $to" "$image"
    debugfs -w -R "set_inode_field $to mode $mode" "$image"
    debugfs -R "dump $to $temporary/verify" "$image"
    cmp "$from" "$temporary/verify"
    rm "$temporary/verify"
}
replace_file "$temporary/phantowd-api" /usr/bin/phantowd-api 0100755
sh "$source_dir/support/container/build-volume-probe-fixture.sh" \
    "$source_dir" "$probe_archive" "$target_cc" "$temporary/phantowd-volume-probe" "$patch_dir"
debugfs -w -R 'mkdir /usr/libexec' "$image"
replace_file "$temporary/phantowd-volume-probe" /usr/libexec/phantowd-volume-probe 0100755
replace_file "$source_dir/board/qemu/armv5/rootfs-overlay/etc/init.d/S99phantowd-ready" /etc/init.d/S99phantowd-ready 0100755
debugfs -w -R 'mkdir /usr/lib/phantowd' "$image"
replace_file "$source_dir/board/qemu/armv5/rootfs-overlay/usr/lib/phantowd/qemu-nfs-policy-smoke.sh" /usr/lib/phantowd/qemu-nfs-policy-smoke.sh 0100644
replace_file "$source_dir/board/qemu/armv5/rootfs-overlay/usr/lib/phantowd/qemu-state-init.sh" /usr/lib/phantowd/qemu-state-init.sh 0100755
replace_file "$source_dir/src/phantowd-api/vendor/golang.org/x/sys/LICENSE" /usr/share/licenses/phantowd-api/Go-XSys-LICENSE 0100644
# shellcheck disable=SC1091 # project version-lock input
. "$source_dir/versions.env"
result=0
sh "$source_dir/support/qemu-smoke.sh" "$temporary/images" "$temporary/qemu.log" "$LINUX_VERSION" || result=$?
cat "$temporary/qemu.log"
if [ "$result" -eq 0 ]; then
    sh "$source_dir/support/qemu-state-reboot.sh" "$temporary/images" "$temporary/state-reboot.log" || result=$?
    cat "$temporary/state-reboot.log"
fi
sha256sum "$temporary/phantowd-api" "$temporary/phantowd-volume-probe" "$temporary/images/rootfs.ext2"
echo 'Overlay smoke uses the base kernel/packages; it does not replace clean Buildroot CI or regenerate SBOM/legal-info.'
# The calling ephemeral container owns /tmp; no recursive host cleanup.
exit "$result"
