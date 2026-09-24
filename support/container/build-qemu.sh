#!/bin/sh
set -eu

external_dir="${PHANTOWD_EXTERNAL_DIR:-/external}"
workspace_dir="${PHANTOWD_WORKSPACE_DIR:-/workspace}"

# This file is maintained by the project and contains no executable secrets.
# shellcheck disable=SC1091
. "$external_dir/versions.env"

buildroot_archive="buildroot-$BUILDROOT_VERSION.tar.xz"
buildroot_url="https://buildroot.org/downloads/$buildroot_archive"
buildroot_signature="$buildroot_archive.sign"
buildroot_source="$workspace_dir/buildroot-$BUILDROOT_VERSION"
download_dir="$workspace_dir/dl"
key_file="$workspace_dir/buildroot-release-key.asc"
gnupg_dir="$workspace_dir/gnupg"

mkdir -p "$workspace_dir" "$download_dir/linux" "$download_dir/cyclonedx"

download_verified() {
    url="$1"
    destination="$2"
    expected_sha256="$3"

    if [ ! -f "$destination" ]; then
        temporary="$destination.part"
        curl --fail --location --proto '=https' --tlsv1.2 \
            --output "$temporary" "$url"
        mv "$temporary" "$destination"
    fi

    printf '%s  %s\n' "$expected_sha256" "$destination" | sha256sum --check --status
}

download_verified \
    "$BUILDROOT_SIGNING_KEY_URL" \
    "$key_file" \
    "$BUILDROOT_SIGNING_KEY_SHA256"

if [ ! -f "$workspace_dir/$buildroot_signature" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 \
        --output "$workspace_dir/$buildroot_signature.part" \
        "$buildroot_url.sign"
    mv "$workspace_dir/$buildroot_signature.part" \
        "$workspace_dir/$buildroot_signature"
fi

rm -rf "$gnupg_dir"
install -d -m 0700 "$gnupg_dir"
GNUPGHOME="$gnupg_dir" gpg --batch --quiet --import "$key_file"
signature_status="$(GNUPGHOME="$gnupg_dir" gpg --batch --status-fd=1 \
    --verify "$workspace_dir/$buildroot_signature" 2>/dev/null)"
printf '%s\n' "$signature_status" | grep -F \
    "[GNUPG:] VALIDSIG $BUILDROOT_SIGNING_KEY_FINGERPRINT " >/dev/null
grep -F \
    "SHA256: $BUILDROOT_ARCHIVE_SHA256  $buildroot_archive" \
    "$workspace_dir/$buildroot_signature" >/dev/null

download_verified \
    "$buildroot_url" \
    "$workspace_dir/$buildroot_archive" \
    "$BUILDROOT_ARCHIVE_SHA256"

linux_archive="linux-$LINUX_VERSION.tar.xz"
download_verified \
    "https://cdn.kernel.org/pub/linux/kernel/v6.x/$linux_archive" \
    "$download_dir/linux/$linux_archive" \
    "$LINUX_ARCHIVE_SHA256"

linux_signature="$download_dir/linux/linux-$LINUX_VERSION.tar.sign"
if [ ! -f "$linux_signature" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 \
        --output "$linux_signature.part" \
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$LINUX_VERSION.tar.sign"
    mv "$linux_signature.part" "$linux_signature"
fi

# Kernel.org signs the uncompressed tar stream. Pin and verify the stable
# release signing key in addition to the compressed archive's SHA-256.
GNUPGHOME="$gnupg_dir" gpg --batch --keyserver-options timeout=30 \
    --locate-keys "$LINUX_SIGNING_KEY_EMAIL" >/dev/null
GNUPGHOME="$gnupg_dir" gpg --batch --with-colons --fingerprint --list-keys |
    grep -F "$LINUX_SIGNING_KEY_FINGERPRINT" >/dev/null
linux_signature_status="$(xz --decompress --stdout "$download_dir/linux/$linux_archive" |
    GNUPGHOME="$gnupg_dir" gpg --batch --status-fd=1 \
        --verify "$linux_signature" - 2>/dev/null)"
printf '%s\n' "$linux_signature_status" |
    grep -F "[GNUPG:] VALIDSIG $LINUX_SIGNING_KEY_FINGERPRINT " >/dev/null

cyclonedx_generator="$buildroot_source/utils/generate-cyclonedx"
grep -F "CYCLONEDX_VERSION = \"$CYCLONEDX_SPEC_VERSION\"" \
    "$cyclonedx_generator" >/dev/null
cyclonedx_schema="$download_dir/cyclonedx/spdx-$CYCLONEDX_SPEC_VERSION.schema.json"
download_verified \
    "https://raw.githubusercontent.com/CycloneDX/specification/$CYCLONEDX_SPEC_VERSION/schema/spdx.schema.json" \
    "$cyclonedx_schema" \
    "$CYCLONEDX_SPDX_SCHEMA_SHA256"

if [ ! -f "$buildroot_source/.phantowd-source-ready" ]; then
    source_stage="$workspace_dir/.buildroot-$BUILDROOT_VERSION.extracting"
    if [ -e "$source_stage" ]; then
        echo "Incomplete Buildroot extraction exists at $source_stage" >&2
        exit 1
    fi
    mkdir "$source_stage"
    tar --extract --xz --file "$workspace_dir/$buildroot_archive" \
        --directory "$source_stage" --strip-components=1
    touch "$source_stage/.phantowd-source-ready"
    mv "$source_stage" "$buildroot_source"
fi

config_file="$external_dir/configs/phantowd_qemu_armv5_defconfig"
release_file="$external_dir/board/qemu/armv5/rootfs-overlay/etc/phantowd-release"
grep -F "BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE=\"$LINUX_VERSION\"" \
    "$config_file" >/dev/null
grep -F "PHANTOWD_KERNEL_VERSION=$LINUX_VERSION" "$release_file" >/dev/null
config_hash="$(sha256sum "$config_file" | cut -c1-16)"
output_dir="$workspace_dir/output/$BUILDROOT_VERSION-$config_hash"

make -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
    O="$output_dir" \
    phantowd_qemu_armv5_defconfig

make -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
    O="$output_dir" \
    phantowd-api-dirclean

# Clean only the generated local-package directory: rsync alone can retain
# deleted source files. Dependencies stay cached; all regenerates the rootfs.
make -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
    O="$output_dir" \
    -j"$(getconf _NPROCESSORS_ONLN)"

GOCACHE="$workspace_dir/api-host-cache" \
    sh "$external_dir/support/container/test-api.sh" \
    "$output_dir/host/bin/go" "$external_dir/src/phantowd-api" \
    "$output_dir/api-host-tests"

GOCACHE="$workspace_dir/lab-tools-host-cache" \
    sh "$external_dir/support/container/test-lab-tools.sh" \
    "$output_dir/host/bin/go" "$external_dir/tools/phantowd-lab" \
    "$output_dir/lab-tools-host-tests"

"$external_dir/support/qemu-smoke.sh" \
    "$output_dir/images" "$output_dir/qemu-smoke.log" "$LINUX_VERSION"

artifact_dir="$external_dir/artifacts/qemu-armv5"
install -d -m 0755 "$artifact_dir"
make --no-print-directory -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
    O="$output_dir" \
    show-info > "$artifact_dir/buildroot-show-info.json"
(
    cd "$buildroot_source"
    O="$output_dir" BR2_EXTERNAL="$external_dir" BR2_DL_DIR="$download_dir" \
        "$cyclonedx_generator" \
        --project-name "PhantoWD EX4 QEMU ARMv5" \
        --project-version "dev-buildroot-$BUILDROOT_VERSION-linux-$LINUX_VERSION" \
        < "$artifact_dir/buildroot-show-info.json" \
        > "$artifact_dir/sbom.cdx.json"
)
python3 -m json.tool "$artifact_dir/sbom.cdx.json" >/dev/null
grep -F '"bomFormat": "CycloneDX"' "$artifact_dir/sbom.cdx.json" >/dev/null
grep -F "\"specVersion\": \"$CYCLONEDX_SPEC_VERSION\"" \
    "$artifact_dir/sbom.cdx.json" >/dev/null
install -m 0644 "$output_dir/images/zImage" "$artifact_dir/zImage"
install -m 0644 "$output_dir/images/versatile-pb.dtb" "$artifact_dir/versatile-pb.dtb"
install -m 0644 "$output_dir/images/rootfs.ext2" "$artifact_dir/rootfs.ext2"
install -m 0644 "$output_dir/qemu-smoke.log" "$artifact_dir/qemu-smoke.log"
install -m 0644 "$output_dir/api-host-tests/coverage.out" "$artifact_dir/api-host-coverage.out"
install -m 0644 "$output_dir/lab-tools-host-tests/coverage.out" "$artifact_dir/lab-tools-host-coverage.out"
install -m 0644 "$output_dir/target/usr/bin/phantowd-api" "$artifact_dir/phantowd-api"
(
    cd "$artifact_dir"
    sha256sum zImage versatile-pb.dtb rootfs.ext2 phantowd-api \
        buildroot-show-info.json sbom.cdx.json > SHA256SUMS
)

printf 'Build and smoke test passed. Artifacts: %s\n' "$artifact_dir"
