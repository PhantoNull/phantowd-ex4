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
    shift
    if sh "$comparator" "$@" > "$temporary/rejection.log" 2>&1; then
        echo "comparator unexpectedly accepted $label" >&2
        exit 1
    fi
}

make_fixture "$temporary/build-a"
make_fixture "$temporary/build-b"
sh "$comparator" "$temporary/build-a" "$temporary/build-b" >/dev/null

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

rc0_a="$temporary/rc0-a"
rc0_b="$temporary/rc0-b"
rc0_manifest() {
    (cd "$1/rc0-armv5" && sha256sum zImage versatile-pb.dtb rootfs.ext2 buildroot.config linux.config \
        buildroot-show-info.json sbom.cdx.json license-manifest.csv host-license-manifest.csv > SHA256SUMS)
}

mkdir -p "$rc0_a/rc0-armv5"
cp "$temporary/build-a/source-commit.txt" "$rc0_a/"
for artifact in zImage rootfs.ext2 versatile-pb.dtb buildroot-show-info.json sbom.cdx.json license-manifest.csv; do
    cp "$temporary/build-a/qemu-armv5/$artifact" "$rc0_a/rc0-armv5/"
done
printf 'synthetic Buildroot configuration\n' > "$rc0_a/rc0-armv5/buildroot.config"
printf 'synthetic Linux configuration\n' > "$rc0_a/rc0-armv5/linux.config"
printf 'synthetic host licenses\n' > "$rc0_a/rc0-armv5/host-license-manifest.csv"
rc0_manifest "$rc0_a"
cp -a "$rc0_a" "$rc0_b"
sh "$comparator" --rc0 "$rc0_a" "$rc0_b" >/dev/null
expect_rejection "the RC0 comparison set in the legacy profile" "$rc0_a" "$rc0_b"

printf 'malformed\n' >> "$rc0_b/rc0-armv5/SHA256SUMS"
expect_rejection "a damaged RC0 manifest" --rc0 "$rc0_a" "$rc0_b"
printf 'changed SBOM\n' >> "$rc0_b/rc0-armv5/sbom.cdx.json"
rc0_manifest "$rc0_b"
expect_rejection "RC0 metadata that matches its manifest but differs" --rc0 "$rc0_a" "$rc0_b"

cp "$rc0_a/rc0-armv5/sbom.cdx.json" "$rc0_a/rc0-armv5/SHA256SUMS" "$rc0_b/rc0-armv5/"
rm "$rc0_b/rc0-armv5/linux.config"
expect_rejection "a missing RC0 configuration" --rc0 "$rc0_a" "$rc0_b"
cp "$rc0_a/rc0-armv5/linux.config" "$rc0_b/rc0-armv5/"
printf 'out-of-scope\n' > "$rc0_b/rc0-armv5/unlisted"
expect_rejection "extra files beside RC0 images" --rc0 "$rc0_a" "$rc0_b"

echo "Reproducible artifact comparator tests passed."
