#!/bin/sh
set -eu

external_dir="${PHANTOWD_EXTERNAL_DIR:-/external}"
workspace_dir="${PHANTOWD_WORKSPACE_DIR:-/workspace}"
ccache_dir="${PHANTOWD_CCACHE_DIR:-$workspace_dir/ccache}"
compile_checkpoint="$external_dir/artifacts/qemu-build-checkpoints/compile-complete"
# A checkpoint describes this invocation, never a previous cached build.
if [ "${PHANTOWD_PREPARE_ONLY:-0}" != 1 ]; then
    rm -f "$compile_checkpoint"
fi

# This file is maintained by the project and contains no executable secrets.
# shellcheck disable=SC1091
. "$external_dir/versions.env"

buildroot_archive="buildroot-$BUILDROOT_VERSION.tar.xz"
buildroot_url="https://buildroot.org/downloads/$buildroot_archive"
buildroot_signature="$buildroot_archive.sign"
buildroot_source="$workspace_dir/buildroot-$BUILDROOT_VERSION"
download_dir="$workspace_dir/dl"
key_file="$workspace_dir/buildroot-release-key.asc"

mkdir -p "$workspace_dir" "$download_dir/linux" "$download_dir/cyclonedx"

shellcheck -s sh \
	"$external_dir/support/compare-build-artifacts.sh" \
	"$external_dir/support/test-compare-build-artifacts.sh" \
	"$external_dir/support/container/apply-buildroot-samba-json-patch.sh" \
	"$external_dir/support/tests/test-buildroot-samba-json-patch.sh" \
	"$external_dir/package/phantowd-api/S02phantowd-mdev" \
	"$external_dir/package/phantowd-api/S40phantowd-storage-broker" \
	"$external_dir/board/qemu/armv5/rootfs-overlay/etc/init.d/S49phantowd-identity-owner" \
	"$external_dir/board/qemu/armv5/rootfs-overlay/usr/lib/phantowd/qemu-md-v10-init.sh" \
	"$external_dir/support/qemu-md-v10-fixture.sh"
shellcheck -s sh "$external_dir/support/container/save-qemu-failure-log.sh"
python3 -B "$external_dir/support/tests/test-qemu-build-feedback.py"
python3 -B "$external_dir/support/tests/test-service-launcher.py"
python3 -B "$external_dir/support/tests/test-runtime-loader-fixture.py"
python3 -B "$external_dir/support/tests/test-samba-root-fixture.py"
python3 -B "$external_dir/support/tests/test-qemu-kernel-inputs.py"
python3 -B -m flake8 "$external_dir/support/tests/runtime_loader_fixture.py" \
    "$external_dir/support/tests/test-runtime-loader-fixture.py" \
    "$external_dir/support/tests/samba_root_fixture.py" \
    "$external_dir/support/tests/test-samba-root-fixture.py"
python3 -B -m flake8 "$external_dir/support/container/qemu_kernel_inputs.py" \
    "$external_dir/support/tests/test-qemu-kernel-inputs.py"
shellcheck "$external_dir/support/tests/test-qemu-runtime-loader.sh"
shellcheck "$external_dir/support/tests/test-qemu-samba-root.sh" \
    "$external_dir/support/tests/samba-root-init.sh"
shellcheck "$external_dir/support/tests/test-qemu-service-launcher.sh" \
    "$external_dir/support/tests/service-launcher-init.sh"
shellcheck "$external_dir/support/tests/test-qemu-smart-report.sh" \
    "$external_dir/support/tests/smart-report-init.sh"
sh "$external_dir/support/test-compare-build-artifacts.sh"
python3 "$external_dir/support/test-volume-probe-build.py"

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

gnupg_dir="$(mktemp -d /tmp/phantowd-build-gnupg.XXXXXX)"
trap 'rm -rf -- "$gnupg_dir"' EXIT
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

# Buildroot 2025.02.18's linux package license-file hash predates the GPL-2.0
# text shipped in Linux 6.18.54. The archive itself is separately SHA-256 and
# PGP verified above; update only that expected license-text hash, fail closed
# if the pinned Buildroot source no longer matches either known state.
if [ "$BUILDROOT_VERSION" != "2025.02.18" ] || [ "$LINUX_VERSION" != "6.18.54" ]; then
    echo "The Buildroot GPL-2.0 hash refresh is qualified only for Buildroot 2025.02.18 and Linux 6.18.54" >&2
    exit 1
fi
linux_hash_file="$buildroot_source/linux/linux.hash"
old_gpl_text_hash="f6b78c087c3ebdf0f3c13415070dd480a3f35d8fc76f3d02180a407c1c812f79"
linux_gpl_text_hash="$LINUX_GPL_TEXT_SHA256"
old_gpl_hash_count="$(grep -F -c \
    "$old_gpl_text_hash  LICENSES/preferred/GPL-2.0" "$linux_hash_file" || true)"
linux_gpl_hash_count="$(grep -F -c \
    "$linux_gpl_text_hash  LICENSES/preferred/GPL-2.0" "$linux_hash_file" || true)"
if [ "$old_gpl_hash_count" -eq 1 ] && [ "$linux_gpl_hash_count" -eq 0 ]; then
    patch --directory "$buildroot_source" --strip=1 --fuzz=0 --forward \
        < "$external_dir/support/buildroot-patches/$BUILDROOT_VERSION/0001-linux-gpl-text-hash-for-linux-6.18.54.patch"
elif [ "$old_gpl_hash_count" -ne 0 ] || [ "$linux_gpl_hash_count" -ne 1 ]; then
    echo "Unexpected GPL-2.0 license hash in $linux_hash_file" >&2
    exit 1
fi

# Board-only research builds need the same verified sources, not the much
# larger QEMU root filesystem, Go packages and smoke-test output.
if [ "${PHANTOWD_PREPARE_ONLY:-0}" = 1 ]; then
    printf 'Pinned Buildroot and Linux sources verified; QEMU build skipped.\n'
    exit 0
fi

# Add structured Samba server IDs without enabling the much larger AD-DC role.
# This patch is pinned to the Buildroot release and is idempotent in the cache.
sh "$external_dir/support/tests/test-buildroot-samba-json-patch.sh" "$buildroot_source"
samba_patch_state=$(sh "$external_dir/support/container/apply-buildroot-samba-json-patch.sh" \
	"$buildroot_source" \
	"$external_dir/support/buildroot-patches/$BUILDROOT_VERSION/0002-samba4-json-without-ad-dc.patch")
case "$samba_patch_state" in
	applied) samba_json_patch_new=1 ;;
	already-applied) samba_json_patch_new=0 ;;
	*) echo "Unexpected Samba JSON patch state: $samba_patch_state" >&2; exit 1 ;;
esac

# The compile-only EX4 workflow shares source verification above but does not
# need a compiler cache. Initialize it only for the QEMU image build.
mkdir -p "$ccache_dir"
if [ ! -d "$ccache_dir" ] || [ ! -w "$ccache_dir" ]; then
    echo "Buildroot compiler cache directory is missing or not writable: $ccache_dir" >&2
    exit 1
fi
BR2_CCACHE_DIR="$ccache_dir"
CCACHE_UMASK=0022
export BR2_CCACHE_DIR CCACHE_UMASK

cyclonedx_generator="$buildroot_source/utils/generate-cyclonedx"
grep -F "CYCLONEDX_VERSION = \"$CYCLONEDX_SPEC_VERSION\"" \
    "$cyclonedx_generator" >/dev/null
cyclonedx_schema="$download_dir/cyclonedx/spdx-$CYCLONEDX_SPEC_VERSION.schema.json"
download_verified \
    "https://raw.githubusercontent.com/CycloneDX/specification/$CYCLONEDX_SPEC_VERSION/schema/spdx.schema.json" \
    "$cyclonedx_schema" \
    "$CYCLONEDX_SPDX_SCHEMA_SHA256"

config_file="$external_dir/configs/phantowd_qemu_armv5_defconfig"
release_file="$external_dir/board/qemu/armv5/rootfs-overlay/etc/phantowd-release"
grep -F "BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE=\"$LINUX_VERSION\"" \
    "$config_file" >/dev/null
grep -F "PHANTOWD_KERNEL_VERSION=$LINUX_VERSION" "$release_file" >/dev/null
config_hash="$(sha256sum "$config_file" | cut -c1-16)"
output_dir="$workspace_dir/output/$BUILDROOT_VERSION-$config_hash"
previous_jansson_enabled=0
if [ -f "$output_dir/.config" ] &&
	grep -Fx 'BR2_PACKAGE_JANSSON=y' "$output_dir/.config" >/dev/null; then
	previous_jansson_enabled=1
fi
samba_package_rebuild=$samba_json_patch_new
if [ -f "$output_dir/build/samba4-4.22.11/bin/.lock-wscript" ] &&
	grep -F -- '--without-json' "$output_dir/build/samba4-4.22.11/bin/.lock-wscript" >/dev/null; then
	# Recover cleanly if an earlier run applied the source patch but stopped
	# before Samba completed its reconfigure/rebuild.
	samba_package_rebuild=1
fi
cached_samba_source="$output_dir/build/samba4-4.22.11"
if [ -d "$cached_samba_source" ] && {
	! grep -F 'Ignoring message with stale destination generation' \
		"$cached_samba_source/source3/lib/messages.c" >/dev/null ||
	! grep -F 'smbXsrv_session_logoff_user' \
		"$cached_samba_source/source3/smbd/smbXsrv_session.c" >/dev/null ||
	! grep -F 'unix_info->unix_name' \
		"$cached_samba_source/source3/smbd/smbXsrv_session.c" >/dev/null ||
	! grep -F 'MSG_SMB_LOGOFF_USER' \
		"$cached_samba_source/source3/smbd/server.c" >/dev/null ||
	! grep -F 'msg_logoff_user' \
		"$cached_samba_source/source3/smbd/smb2_process.c" >/dev/null ||
	! grep -F 'logoff-user' \
		"$cached_samba_source/source3/utils/smbcontrol.c" >/dev/null;
}; then
	# The package source is cached independently of the repository's global
	# patches. Re-extract and apply the exact pinned patch series once when a
	# patch is new; do not clean unrelated Buildroot dependencies or volumes.
	samba_package_rebuild=1
fi

make -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
	O="$output_dir" \
	phantowd_qemu_armv5_defconfig

grep -Fx 'BR2_PACKAGE_SAMBA4=y' "$output_dir/.config" >/dev/null
grep -Fx 'BR2_PACKAGE_JANSSON=y' "$output_dir/.config" >/dev/null
if grep -Fx 'BR2_PACKAGE_SAMBA4_AD_DC=y' "$output_dir/.config" >/dev/null; then
	echo 'Samba JSON support must not enable the Active Directory Domain Controller' >&2
	exit 1
fi
if [ "$previous_jansson_enabled" = 0 ]; then
	samba_package_rebuild=1
fi

# Obtain the pinned native Go toolchain first. Linux lifecycle/race failures
# must fail before the expensive kernel/Samba/target build, not an hour later.
make -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
    O="$output_dir" \
    host-go-bin

GOCACHE="$workspace_dir/api-host-cache" \
    sh "$external_dir/support/container/test-api.sh" \
    "$output_dir/host/bin/go" "$external_dir/src/phantowd-api" \
    "$output_dir/api-host-tests"

GOCACHE="$workspace_dir/lab-tools-host-cache" \
    sh "$external_dir/support/container/test-lab-tools.sh" \
    "$output_dir/host/bin/go" "$external_dir/tools/phantowd-lab" \
    "$output_dir/lab-tools-host-tests"

make -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
	O="$output_dir" \
	phantowd-api-dirclean phantowd-volume-probe-dirclean

if [ "$samba_package_rebuild" = 1 ]; then
	make -C "$buildroot_source" \
		BR2_EXTERNAL="$external_dir" \
		BR2_DL_DIR="$download_dir" \
		O="$output_dir" \
		samba4-dirclean
fi

# Clean only the generated local-package directory: rsync alone can retain
# deleted source files. Dependencies stay cached; all regenerates the rootfs.
# Buildroot does not invalidate a configured kernel when only a fragment
# changes. Refresh just Linux, reusing the same output/cache namespace. A
# missing legacy stamp also refreshes once; stamp only audited successful work.
kernel_inputs_helper="$external_dir/support/container/qemu_kernel_inputs.py"
linux_inputs_digest=$(python3 -B "$kernel_inputs_helper" fingerprint \
    "$external_dir" "$buildroot_source")
linux_inputs_stamp="$output_dir/.phantowd-linux-inputs.sha256"
linux_inputs_previous=
if [ -f "$linux_inputs_stamp" ]; then
    linux_inputs_previous=$(cat "$linux_inputs_stamp")
fi
if [ -f "$output_dir/build/linux-$LINUX_VERSION/.stamp_configured" ] && \
    [ "$linux_inputs_previous" != "$linux_inputs_digest" ]; then
    make -C "$buildroot_source" BR2_EXTERNAL="$external_dir" \
        BR2_DL_DIR="$download_dir" O="$output_dir" \
        -j"$(getconf _NPROCESSORS_ONLN)" linux-reconfigure
fi
make -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
    O="$output_dir" \
    -j"$(getconf _NPROCESSORS_ONLN)"

python3 -B "$kernel_inputs_helper" audit \
    "$output_dir/build/linux-$LINUX_VERSION/.config"
[ "$(python3 -B "$kernel_inputs_helper" fingerprint \
    "$external_dir" "$buildroot_source")" = "$linux_inputs_digest" ] || {
    echo 'QEMU kernel inputs changed during the build; no checkpoint recorded' >&2
    exit 1
}
printf '%s\n' "$linux_inputs_digest" > "$linux_inputs_stamp.part"
mv "$linux_inputs_stamp.part" "$linux_inputs_stamp"

# Compiler-cache readiness is not test or release qualification. Trusted CI
# can retain completed compiler work even when a later guest fixture fails.
install -d -m 0755 "$(dirname "$compile_checkpoint")"
printf 'complete\n' > "$compile_checkpoint"

# The cached Buildroot TARGET_DIR may contain an mdev rule from an earlier
# PhantoWD package revision. Require the package hook to replace it atomically,
# not merely add a new range alongside the stale one.
installed_mdev_conf="$output_dir/target/etc/mdev.conf"
if ! awk '
    $0 ~ /^\^sd.*\$ root:phantowd-storage-read 0440$/ {
        rule_count++
        if ($0 != "^sd[a-g]$ root:phantowd-storage-read 0440") invalid = 1
    }
    END { if (rule_count != 1 || invalid) exit 1 }
' "$installed_mdev_conf"; then
    echo "Buildroot TARGET_DIR has stale or duplicate PhantoWD mdev rules: $installed_mdev_conf" >&2
    exit 1
fi

make -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
    O="$output_dir" \
    legal-info

# Native generated-image tests use the same hash-checked libblkid source as
# the target package. No host devices, mounts or privileged mode are needed.
sh "$external_dir/support/container/test-volume-probe.sh" \
    "$external_dir" "$download_dir/util-linux/util-linux-2.40.4.tar.xz" \
    "$buildroot_source/package/util-linux" "$output_dir/host/bin"

artifact_dir="$external_dir/artifacts/qemu-armv5"
save_qemu_failure_log() {
    sh "$external_dir/support/container/save-qemu-failure-log.sh" \
        "$artifact_dir/$1" "$2"
}

if ! "$external_dir/support/qemu-smoke.sh" \
    "$output_dir/images" "$output_dir/qemu-smoke.log" "$LINUX_VERSION"; then
    save_qemu_failure_log qemu-smoke-failure.log "$output_dir/qemu-smoke.log"
    echo "Preserved failed QEMU smoke diagnostics at $artifact_dir/qemu-smoke-failure.log" >&2
    exit 1
fi
if ! TMPDIR=/phantowd-qemu-fixture-tmp \
    GOCACHE="$workspace_dir/lab-tools-host-cache" \
    sh "$external_dir/support/qemu-md-v10-fixture.sh" \
    "$output_dir/images" "$output_dir/host/bin/go" "$external_dir" \
    "$output_dir/qemu-md-v10.log"; then
    save_qemu_failure_log qemu-md-v10-failure.log "$output_dir/qemu-md-v10.log"
    echo "Preserved failed MD v1.0 diagnostics at $artifact_dir/qemu-md-v10-failure.log" >&2
    exit 1
fi
if ! sh "$external_dir/support/qemu-state-reboot.sh" \
    "$output_dir/images" "$output_dir/qemu-state-reboot.log"; then
    save_qemu_failure_log qemu-state-reboot-failure.log "$output_dir/qemu-state-reboot.log"
    echo "Preserved failed state-reboot diagnostics at $artifact_dir/qemu-state-reboot-failure.log" >&2
    exit 1
fi

install -d -m 0755 "$artifact_dir"
make --no-print-directory -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
    O="$output_dir" \
    show-info > "$artifact_dir/buildroot-show-info.json"
raw_sbom="$artifact_dir/buildroot-sbom.cdx.json"
(
    cd "$buildroot_source"
    O="$output_dir" BR2_EXTERNAL="$external_dir" BR2_DL_DIR="$download_dir" \
        "$cyclonedx_generator" \
        --project-name "PhantoWD EX4 QEMU ARMv5" \
        --project-version "dev-buildroot-$BUILDROOT_VERSION-linux-$LINUX_VERSION" \
        < "$artifact_dir/buildroot-show-info.json" \
        > "$raw_sbom"
)
python3 "$external_dir/support/container/augment-cyclonedx.py" \
    < "$raw_sbom" > "$artifact_dir/sbom.cdx.json"
rm -f "$raw_sbom"
python3 -m json.tool "$artifact_dir/sbom.cdx.json" >/dev/null
python3 -B -m flake8 \
    "$external_dir/support/container/augment-cyclonedx.py" \
    "$external_dir/support/container/test_augment_cyclonedx.py"
python3 -B "$external_dir/support/container/test_augment_cyclonedx.py"
grep -F '"bomFormat": "CycloneDX"' "$artifact_dir/sbom.cdx.json" >/dev/null
grep -F "\"specVersion\": \"$CYCLONEDX_SPEC_VERSION\"" \
    "$artifact_dir/sbom.cdx.json" >/dev/null
grep -F 'golang.org/x/crypto' "$artifact_dir/sbom.cdx.json" >/dev/null
grep -F 'golang.org/x/sys' "$artifact_dir/sbom.cdx.json" >/dev/null
install -m 0644 "$output_dir/images/zImage" "$artifact_dir/zImage"
install -m 0644 "$output_dir/images/versatile-pb.dtb" "$artifact_dir/versatile-pb.dtb"
install -m 0644 "$output_dir/images/rootfs.ext2" "$artifact_dir/rootfs.ext2"
install -m 0644 "$output_dir/legal-info/manifest.csv" "$artifact_dir/license-manifest.csv"
install -m 0644 "$output_dir/qemu-smoke.log" "$artifact_dir/qemu-smoke.log"
install -m 0644 "$output_dir/qemu-md-v10.log" "$artifact_dir/qemu-md-v10.log"
install -m 0644 "$output_dir/qemu-state-reboot.log" "$artifact_dir/qemu-state-reboot.log"
install -m 0644 "$output_dir/api-host-tests/coverage.out" "$artifact_dir/api-host-coverage.out"
install -m 0644 "$output_dir/lab-tools-host-tests/coverage.out" "$artifact_dir/lab-tools-host-coverage.out"
install -m 0644 "$output_dir/target/usr/bin/phantowd-api" "$artifact_dir/phantowd-api"
(
    cd "$artifact_dir"
    sha256sum zImage versatile-pb.dtb rootfs.ext2 phantowd-api \
        buildroot-show-info.json sbom.cdx.json license-manifest.csv > SHA256SUMS
)

# Isolated native launcher test reuses this exact qualified QEMU baseline.
# Its static probe/helper live only in a temporary copy, not the firmware image.
TMPDIR=/phantowd-qemu-fixture-tmp sh "$external_dir/support/tests/test-qemu-service-launcher.sh" \
    "$artifact_dir" "$output_dir/host/bin/arm-buildroot-linux-gnueabi-gcc" \
    "$output_dir/host/sbin/debugfs" "$external_dir" \
    "$artifact_dir/qemu-service-launcher-failure.log" "$output_dir/host/bin/go"

# Compare only the just-built public Samba dependencies with the real loader.
# This does not start smbd or approve a daemon-root/privilege profile.
if ! TMPDIR=/phantowd-qemu-fixture-tmp sh "$external_dir/support/tests/test-qemu-runtime-loader.sh" \
    "$artifact_dir" "$output_dir/target" "$output_dir/host/bin/go" \
    "$output_dir/host/sbin/debugfs" "$external_dir" \
    "$artifact_dir/qemu-runtime-loader-failure.log"; then
    echo "Preserved failed loader differential diagnostics in $artifact_dir" >&2
    exit 1
fi

# Fixed multi-user Samba experiment, not a product helper/profile installation.
if ! TMPDIR=/phantowd-qemu-fixture-tmp sh "$external_dir/support/tests/test-qemu-samba-root.sh" \
    "$artifact_dir" "$output_dir/target" "$output_dir/host/bin/go" \
    "$output_dir/host/sbin/debugfs" "$output_dir/host/bin/arm-buildroot-linux-gnueabi-gcc" \
    "$external_dir" "$artifact_dir/qemu-samba-root-failure.log"; then
    echo "Preserved failed Samba-root diagnostics in $artifact_dir" >&2
    exit 1
fi

# Pure report interpretation only: no SMART executable or device commands.
TMPDIR=/phantowd-qemu-fixture-tmp sh "$external_dir/support/tests/test-qemu-smart-report.sh" \
    "$artifact_dir" "$output_dir/host/bin/go" "$output_dir/host/sbin/debugfs" \
    "$external_dir" "$artifact_dir/qemu-smart-report-failure.log"

printf 'Build and smoke test passed. Artifacts: %s\n' "$artifact_dir"
