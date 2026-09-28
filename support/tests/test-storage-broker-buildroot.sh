#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
package_dir="$repo_root/package/phantowd-api"
package_makefile="$package_dir/phantowd-api.mk"
mdev_file="$package_dir/mdev.conf"

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

# Buildroot makeusers tables are line-oriented. Keep the application API and
# storage broker as distinct records so the broker's account/group are created.
users=$(awk '
    $0 == "define PHANTOWD_API_USERS" { in_users = 1; found = 1; next }
    in_users && $0 == "endef" { in_users = 0; ended = 1; next }
    in_users && NF { print }
    END { if (!found || !ended || in_users) exit 1 }
' "$package_makefile") || fail 'PHANTOWD_API_USERS must be a multiline Buildroot users table'

printf '%s\n' "$users" | awk '
    NF {
        rows++
        if (NF < 9) bad = 1
        if ($1 == "phantowd") {
            api++
            if ($2 != "-1" || $3 != "phantowd" || $4 != "-1" ||
                $7 != "/bin/false" || $8 != "-") bad = 1
        } else if ($1 == "phantowd-storage") {
            broker++
            if ($2 != "-1" || $3 != "phantowd-storage-read" || $4 != "-1" ||
                $7 != "/bin/false" || $8 != "-") bad = 1
        } else {
            bad = 1
        }
    }
    END { if (rows != 2 || api != 1 || broker != 1 || bad) exit 1 }
' || fail 'API and broker accounts must be separate, locked, non-root users'

# mdev must grant only read access to whole-disk fixture nodes; /dev/null is
# normalized before any unprivileged service is launched.
grep -Fx '^sd[a-f]$ root:phantowd-storage-read 0440' "$mdev_file" >/dev/null ||
    fail 'mdev must grant the broker read-only access to whole-disk fixture nodes'
grep -F 'PHANTOWD_API_DEPENDENCIES += busybox' "$package_makefile" >/dev/null ||
    fail 'storage init integration must depend on BusyBox'
grep -F '$(TOPDIR)/package/busybox/mdev.conf' "$package_makefile" >/dev/null ||
    fail 'storage rules must preserve the pinned BusyBox mdev defaults'
grep -F 'cat "$(PHANTOWD_API_PKGDIR)/mdev.conf" &&' "$package_makefile" >/dev/null ||
    fail 'storage rules must precede defaults so the whole-disk whitelist wins'
grep -F 'mv "$$mdev_tmp" "$$mdev_conf"' "$package_makefile" >/dev/null ||
    fail 'mdev integration must atomically install its merged, idempotent rules'
grep -Fq 'chmod 0666 /dev/null' "$package_dir/S02phantowd-mdev" ||
    fail 'mdev init must restore standard /dev/null access before launching services'

grep -F -- '--chuid phantowd-storage:phantowd-storage-read' \
    "$package_dir/S40phantowd-storage-broker" >/dev/null ||
    fail 'broker init must use its dedicated non-root identity'
grep -F -- '--chuid phantowd:phantowd' "$package_dir/S50phantowd-api" >/dev/null ||
    fail 'API init must keep its separate non-root identity'

qemu_ready_script="$repo_root/board/qemu/armv5/rootfs-overlay/etc/init.d/S99phantowd-ready"
grep -F 'PHANTOWD_QEMU_API_SELFTEST_FAILURE detail=' "$qemu_ready_script" >/dev/null ||
    fail 'QEMU diagnostics failures must print a bounded self-test error summary'
grep -F 'index($0, "PHANTOWD_API_ERROR ") == 1' "$qemu_ready_script" >/dev/null ||
    fail 'QEMU diagnostics must only summarize the API self-test error marker'

error_summary=$(printf '%s\n' \
    'PHANTOWD_API_ERROR authentication status request failed; address=127.0.0.1:8080' \
    'unrelated secret-looking text must be ignored' |
    awk 'index($0, "PHANTOWD_API_ERROR ") == 1 { gsub(/[^A-Za-z0-9 _-]/, "?"); print substr($0, 1, 160); exit }')
[ "$error_summary" = 'PHANTOWD_API_ERROR authentication status request failed? address?127?0?0?1?8080' ] ||
    fail 'QEMU API self-test error summary must be bounded and sanitized'

mounted_identity_marker='PHANTOWD_MOUNTED_STORAGE_CORRELATION_READY anchors=3 uuid_conflict_entries=3 bind_alias_same_device=true complete_sysfs=true scope=qemu-fixture-only'
grep -F "$mounted_identity_marker" "$repo_root/src/phantowd-api/mount_guard_qemu_linux.go" >/dev/null ||
    fail 'QEMU mounted-identity integration must define its complete fixture marker'
grep -F "$mounted_identity_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke must require mounted filesystem identity correlation'

md_filesystem_identity_marker='PHANTOWD_MD_FILESYSTEM_IDENTITY_READY filesystem_to_md=true md_uuid_internal=true members=2 readonly_mount=true conflict_free=true scope=disposable-qemu-only'
grep -F "$md_filesystem_identity_marker" "$repo_root/src/phantowd-api/md_stack_qemu_linux.go" >/dev/null ||
    fail 'QEMU MD fixture must correlate a mounted filesystem to its transient MD/member identity'
grep -F "$md_filesystem_identity_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke must require mounted MD/filesystem identity correlation'

# Keep the QEMU smoke driver's expected marker synchronized with the guest
# self-test. A typo here otherwise costs a full ARMv5 build before the guest
# can even boot.
source_set_marker=$(sed -n 's/.*fmt\.Println("\(PHANTOWD_VOLUME_SET_READY[^"]*\)").*/\1/p' \
    "$repo_root/src/phantowd-api/volume_probe_qemu_linux.go")
[ -n "$source_set_marker" ] ||
    fail 'guest self-test must define one source-set readiness marker'
grep -F "$source_set_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke assertion must match the guest source-set readiness marker'

printf 'Read-only storage broker Buildroot contracts passed\n'
