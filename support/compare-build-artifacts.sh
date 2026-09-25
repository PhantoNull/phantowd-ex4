#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 BUILD-A-DIRECTORY BUILD-B-DIRECTORY" >&2
    exit 2
fi

left=$1
right=$2

expected_files=$(printf '%s\n' \
    source-commit.txt \
    ex4-dtb-research/SHA256SUMS \
    ex4-dtb-research/kirkwood-wd-mycloud-ex4.dtb \
    qemu-armv5/SHA256SUMS \
    qemu-armv5/buildroot-show-info.json \
    qemu-armv5/license-manifest.csv \
    qemu-armv5/phantowd-api \
    qemu-armv5/rootfs.ext2 \
    qemu-armv5/sbom.cdx.json \
    qemu-armv5/versatile-pb.dtb \
    qemu-armv5/zImage | LC_ALL=C sort)
expected_entries=$(
    {
        printf '%s\n' 'd ex4-dtb-research' 'd qemu-armv5'
        printf '%s\n' "$expected_files" | sed 's/^/f /'
    } | LC_ALL=C sort
)

validate_build_directory() {
    directory=$1
    if [ ! -d "$directory" ] || [ -L "$directory" ]; then
        echo "not a real build-artifact directory: $directory" >&2
        return 1
    fi
    if find "$directory" -type l -print -quit | grep -q .; then
        echo "symbolic links are not allowed in build-artifact sets: $directory" >&2
        return 1
    fi

    actual_entries=$(cd "$directory" && find . -mindepth 1 -printf '%y %P\n' | LC_ALL=C sort)
    if [ "$actual_entries" != "$expected_entries" ]; then
        echo "build-artifact inventory does not match the comparison allowlist: $directory" >&2
        return 1
    fi

    expected_qemu_manifest=$(cd "$directory/qemu-armv5" && sha256sum \
        zImage versatile-pb.dtb rootfs.ext2 phantowd-api \
        buildroot-show-info.json sbom.cdx.json license-manifest.csv)
    actual_qemu_manifest=$(cat "$directory/qemu-armv5/SHA256SUMS")
    if [ "$actual_qemu_manifest" != "$expected_qemu_manifest" ]; then
        echo "QEMU checksum manifest is invalid or outside the fixed allowlist: $directory/qemu-armv5/SHA256SUMS" >&2
        return 1
    fi

    expected_ex4_manifest=$(cd "$directory/ex4-dtb-research" && \
        sha256sum kirkwood-wd-mycloud-ex4.dtb)
    actual_ex4_manifest=$(cat "$directory/ex4-dtb-research/SHA256SUMS")
    if [ "$actual_ex4_manifest" != "$expected_ex4_manifest" ]; then
        echo "EX4 DTB checksum manifest is invalid or outside the fixed allowlist: $directory/ex4-dtb-research/SHA256SUMS" >&2
        return 1
    fi
}

validate_build_directory "$left"
validate_build_directory "$right"

for artifact in $expected_files; do
    if ! cmp -s "$left/$artifact" "$right/$artifact"; then
        left_hash=$(sha256sum "$left/$artifact" | cut -d ' ' -f 1)
        right_hash=$(sha256sum "$right/$artifact" | cut -d ' ' -f 1)
        echo "artifact differs: $artifact (build-a=$left_hash build-b=$right_hash)" >&2
        exit 1
    fi
done

artifact_count=$(printf '%s\n' "$expected_files" | wc -l | tr -d '[:space:]')
echo "Independent build artifacts match byte-for-byte ($artifact_count allowlisted paths)."
