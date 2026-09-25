#!/bin/sh
set -eu

comparator=${1:-"$(dirname "$0")/compare-build-artifacts.sh"}
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

make_fixture() {
    directory=$1
    mkdir -p "$directory/qemu-armv5" "$directory/ex4-dtb-research"
    printf 'synthetic-source-commit\n' > "$directory/source-commit.txt"
    for artifact in \
        buildroot-show-info.json license-manifest.csv phantowd-api rootfs.ext2 \
        sbom.cdx.json versatile-pb.dtb zImage; do
        printf 'synthetic-%s\n' "$artifact" > "$directory/qemu-armv5/$artifact"
    done
    printf 'synthetic-ex4-dtb\n' > \
        "$directory/ex4-dtb-research/kirkwood-wd-mycloud-ex4.dtb"
    (
        cd "$directory/qemu-armv5"
        sha256sum zImage versatile-pb.dtb rootfs.ext2 phantowd-api \
            buildroot-show-info.json sbom.cdx.json license-manifest.csv > SHA256SUMS
    )
    (
        cd "$directory/ex4-dtb-research"
        sha256sum kirkwood-wd-mycloud-ex4.dtb > SHA256SUMS
    )
}

expect_rejection() {
    label=$1
    left=$2
    right=$3
    if "$comparator" "$left" "$right" > "$temporary/rejection.log" 2>&1; then
        echo "comparator unexpectedly accepted $label" >&2
        exit 1
    fi
}

make_fixture "$temporary/build-a"
make_fixture "$temporary/build-b"
"$comparator" "$temporary/build-a" "$temporary/build-b" >/dev/null

cp -a "$temporary/build-b" "$temporary/mismatch"
printf 'tampered\n' >> "$temporary/mismatch/qemu-armv5/rootfs.ext2"
expect_rejection "a modified payload" "$temporary/build-a" "$temporary/mismatch"

cp -a "$temporary/build-b" "$temporary/missing"
rm "$temporary/missing/qemu-armv5/zImage"
expect_rejection "a missing payload" "$temporary/build-a" "$temporary/missing"

cp -a "$temporary/build-b" "$temporary/extra"
printf 'unexpected\n' > "$temporary/extra/unlisted-file"
expect_rejection "an unlisted file" "$temporary/build-a" "$temporary/extra"

cp -a "$temporary/build-b" "$temporary/extra-directory"
mkdir "$temporary/extra-directory/unlisted-directory"
expect_rejection "an unlisted directory" "$temporary/build-a" "$temporary/extra-directory"

cp -a "$temporary/build-b" "$temporary/symlink"
ln -s source-commit.txt "$temporary/symlink/unlisted-symlink"
expect_rejection "a symbolic link" "$temporary/build-a" "$temporary/symlink"

cp -a "$temporary/build-b" "$temporary/bad-manifest"
printf 'invalid manifest entry\n' >> "$temporary/bad-manifest/ex4-dtb-research/SHA256SUMS"
expect_rejection "a malformed checksum manifest" "$temporary/build-a" "$temporary/bad-manifest"

echo "Reproducible artifact comparator tests passed."
