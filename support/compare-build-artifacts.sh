#!/bin/sh
set -eu

profile=research
if [ "${1:-}" = --rc0 ]; then
    profile=rc0
    shift
fi
if [ "$#" -ne 2 ]; then
    echo "usage: $0 [--rc0] BUILD-A-DIRECTORY BUILD-B-DIRECTORY" >&2
    exit 2
fi

left=$1
right=$2

if [ "$profile" = rc0 ]; then
    expected_directories='d rc0-armv5'
    expected_files=$(printf '%s\n' \
        source-commit.txt \
        rc0-armv5/SHA256SUMS \
        rc0-armv5/buildroot-show-info.json \
        rc0-armv5/buildroot.config \
        rc0-armv5/host-license-manifest.csv \
        rc0-armv5/license-manifest.csv \
        rc0-armv5/linux.config \
        rc0-armv5/rootfs.ext2 \
        rc0-armv5/sbom.cdx.json \
        rc0-armv5/versatile-pb.dtb \
        rc0-armv5/zImage | LC_ALL=C sort)
else
    expected_directories=$(printf '%s\n' 'd ex4-dtb-research' 'd qemu-armv5')
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
fi
expected_entries=$(
    {
        printf '%s\n' "$expected_directories"
        printf '%s\n' "$expected_files" | sed 's/^/f /'
    } | LC_ALL=C sort
)

validate_manifest() {
    manifest_directory=$1
    shift
    expected_manifest=$(cd "$manifest_directory" && sha256sum "$@")
    actual_manifest=$(cat "$manifest_directory/SHA256SUMS")
    if [ "$actual_manifest" != "$expected_manifest" ]; then
        echo "checksum manifest is invalid or outside the fixed allowlist: $manifest_directory/SHA256SUMS" >&2
        return 1
    fi
}

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

    if [ "$profile" = rc0 ]; then
        validate_manifest "$directory/rc0-armv5" zImage versatile-pb.dtb rootfs.ext2 \
            buildroot.config linux.config buildroot-show-info.json sbom.cdx.json \
            license-manifest.csv host-license-manifest.csv
        return
    fi

    validate_manifest "$directory/qemu-armv5" zImage versatile-pb.dtb rootfs.ext2 \
        phantowd-api buildroot-show-info.json sbom.cdx.json license-manifest.csv
    validate_manifest "$directory/ex4-dtb-research" kirkwood-wd-mycloud-ex4.dtb
}

validate_build_directory "$left"
validate_build_directory "$right"

different=0
for artifact in $expected_files; do
    if ! cmp -s "$left/$artifact" "$right/$artifact"; then
        left_hash=$(sha256sum "$left/$artifact" | cut -d ' ' -f 1)
        right_hash=$(sha256sum "$right/$artifact" | cut -d ' ' -f 1)
        echo "artifact differs: $artifact (build-a=$left_hash build-b=$right_hash)" >&2
        different=1
    fi
done
[ "$different" -eq 0 ] || exit 1

artifact_count=$(printf '%s\n' "$expected_files" | wc -l | tr -d '[:space:]')
echo "Independent build artifacts match byte-for-byte ($artifact_count allowlisted paths)."
