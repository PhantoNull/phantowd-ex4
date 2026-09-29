#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
package_dir="$repo_root/package/phantowd-api"
package_makefile="$package_dir/phantowd-api.mk"
mdev_file="$package_dir/mdev.conf"
build_qemu_script="$repo_root/support/container/build-qemu.sh"

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
grep -Fx '^sd[a-g]$ root:phantowd-storage-read 0440' "$mdev_file" >/dev/null ||
    fail 'mdev must grant the broker read-only access to whole-disk fixture nodes'
grep -F 'PHANTOWD_API_DEPENDENCIES += busybox' "$package_makefile" >/dev/null ||
    fail 'storage init integration must depend on BusyBox'
grep -F '$(TOPDIR)/package/busybox/mdev.conf' "$package_makefile" >/dev/null ||
    fail 'storage rules must preserve the pinned BusyBox mdev defaults'
grep -F 'cat "$(PHANTOWD_API_PKGDIR)/mdev.conf" &&' "$package_makefile" >/dev/null ||
    fail 'storage rules must precede defaults so the whole-disk whitelist wins'
grep -F 'mv "$$mdev_tmp" "$$mdev_conf"' "$package_makefile" >/dev/null ||
    fail 'mdev integration must atomically install its merged, idempotent rules'
# The dollar signs here are literal Makefile syntax, not shell expansion.
# shellcheck disable=SC2016
stale_mdev_filter='$$0 != "# PhantoWD storage broker: QEMU whole-disk fixtures only." && $$0 !~ /^\^sd.*\$$ root:phantowd-storage-read 0440$$/ { print }'
grep -F "$stale_mdev_filter" "$package_makefile" >/dev/null ||
    fail 'mdev install must remove an older PhantoWD whole-disk rule before adding the current one'
grep -F 'rule_count != 1 || invalid' "$build_qemu_script" >/dev/null ||
    fail 'the full Buildroot runner must reject stale or duplicate PhantoWD mdev rules in TARGET_DIR'

# Model reinstall over a target rootfs left by the previous package revision.
# Keep the current and legacy patterns distinct so stale rules cannot silently
# survive only in Buildroot's cached TARGET_DIR.
fixture_dir=$(mktemp -d)
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM
printf '%s\n' \
    '# PhantoWD storage broker: QEMU whole-disk fixtures only.' \
    '^sd[a-f]$ root:phantowd-storage-read 0440' \
    'UNRELATED_BUSYBOX_RULE_KEEP_ME' > "$fixture_dir/defaults"
merge_mdev_fixture() {
    defaults="$1"
    output="$2"
    awk '$0 != "# PhantoWD storage broker: QEMU whole-disk fixtures only." &&
        $0 !~ /^\^sd.*\$ root:phantowd-storage-read 0440$/ { print }' \
        "$defaults" > "$fixture_dir/filtered"
    {
        cat "$mdev_file"
        cat "$fixture_dir/filtered"
    } > "$output"
}
merge_mdev_fixture "$fixture_dir/defaults" "$fixture_dir/merged-once"
merge_mdev_fixture "$fixture_dir/merged-once" "$fixture_dir/merged-twice"
for merged in "$fixture_dir/merged-once" "$fixture_dir/merged-twice"; do
    [ "$(grep -Fxc '^sd[a-g]$ root:phantowd-storage-read 0440' "$merged")" -eq 1 ] ||
        fail 'mdev reinstall must leave exactly one current PhantoWD whole-disk rule'
    if grep -Fqx '^sd[a-f]$ root:phantowd-storage-read 0440' "$merged"; then
        fail 'mdev reinstall must remove the stale PhantoWD whole-disk rule'
    fi
    grep -Fx 'UNRELATED_BUSYBOX_RULE_KEEP_ME' "$merged" >/dev/null ||
        fail 'mdev reinstall must preserve unrelated BusyBox rules'
done

grep -Fq 'chmod 0666 /dev/null' "$package_dir/S02phantowd-mdev" ||
    fail 'mdev init must restore standard /dev/null access before launching services'

grep -F -- '--chuid phantowd-storage:phantowd-storage-read' \
    "$package_dir/S40phantowd-storage-broker" >/dev/null ||
    fail 'broker init must use its dedicated non-root identity'
grep -F 'ensureStorageBrokerNoNewPrivileges()' \
    "$repo_root/src/phantowd-api/storage_broker_linux.go" >/dev/null ||
    fail 'broker startup must normalize no_new_privs across the Go runtime threads before opening its socket'
grep -F 'runtime.LockOSThread()' "$repo_root/src/phantowd-api/storage_broker_linux.go" >/dev/null ||
    fail 'broker startup must keep its no_new_privs thread fixed during self-exec'
grep -F 'unix.Exec(executable, os.Args, os.Environ())' \
    "$repo_root/src/phantowd-api/storage_broker_linux.go" >/dev/null ||
    fail 'broker startup must restart the process before exposing the storage socket'
grep -F -- '--chuid phantowd:phantowd' "$package_dir/S50phantowd-api" >/dev/null ||
    fail 'API init must keep its separate non-root identity'

qemu_ready_script="$repo_root/board/qemu/armv5/rootfs-overlay/etc/init.d/S99phantowd-ready"
qemu_selftest_helper="$repo_root/board/qemu/armv5/rootfs-overlay/usr/lib/phantowd/qemu-selftest-once.sh"
qemu_owner_init="$repo_root/board/qemu/armv5/rootfs-overlay/etc/init.d/S49phantowd-identity-owner"
qemu_owner_service="$repo_root/src/phantowd-api/identity_owner_service_qemu_linux.go"
grep -F 'PHANTOWD_QEMU_API_SELFTEST_FAILURE detail=' "$qemu_selftest_helper" >/dev/null ||
    fail 'QEMU diagnostics failures must print a bounded first self-test error summary'
grep -F 'index($0, "PHANTOWD_API_ERROR ") == 1' "$qemu_selftest_helper" >/dev/null ||
    fail 'QEMU diagnostics must only summarize the API self-test error marker'
[ "$(grep -Fc '/usr/lib/phantowd/qemu-selftest-once.sh /usr/bin/phantowd-api "$api_error_log"' "$qemu_ready_script")" -eq 2 ] ||
    fail 'QEMU readiness init must run one-shot self-tests before and after the daemon restart'
if grep -F 'while ! /usr/bin/phantowd-api --self-test' "$qemu_ready_script" >/dev/null; then
    fail 'QEMU readiness init must not retry state-mutating API self-tests'
fi
[ -f "$qemu_owner_init" ] || fail 'QEMU identity-owner init service is missing'
qemu_owner_mode=$(git -C "$repo_root" ls-files --stage -- \
    board/qemu/armv5/rootfs-overlay/etc/init.d/S49phantowd-identity-owner | awk '{print $1}')
[ "$qemu_owner_mode" = 100755 ] ||
    fail 'QEMU identity-owner init service must be executable in the tracked rootfs overlay'
grep -F -- '--qemu-identity-owner-service' "$qemu_owner_init" >/dev/null ||
    fail 'QEMU init must start the fixed owner-service mode'
if grep -F -- '--chuid' "$qemu_owner_init" >/dev/null; then
    fail 'QEMU identity-owner service must remain root'
fi
grep -F 'BR2_PACKAGE_PHANTOWD_API_QEMU_SELFTEST' "$package_makefile" >/dev/null ||
    fail 'owner init script must be gated to the QEMU self-test image'
grep -F 'qemuOwnerSocketDir' "$qemu_owner_service" >/dev/null ||
    fail 'QEMU owner service must use its fixed protected socket path'
grep -F 'qemuOwnerRoot       = "/run/phantowd-identity-owner-fixture"' "$qemu_owner_service" >/dev/null ||
    fail 'QEMU owner state must remain under volatile /run'
config_prepare_line=$(grep -n 'prepareQEMUIdentityOwnerConfig(); err != nil' "$qemu_owner_service" | head -n 1 | cut -d: -f1)
backend_validate_line=$(grep -n 'smbBackend, err := smbexec.New(qemuOwnerSMBConfig)' "$qemu_owner_service" | head -n 1 | cut -d: -f1)
runtime_prepare_line=$(grep -n 'prepareQEMUIdentityOwnerRuntime(apiGID); err != nil' "$qemu_owner_service" | head -n 1 | cut -d: -f1)
registry_init_line=$(grep -n 'initializeQEMUIdentityOwnerRegistry(); err != nil' "$qemu_owner_service" | head -n 1 | cut -d: -f1)
[ -n "$config_prepare_line" ] && [ -n "$backend_validate_line" ] &&
    [ -n "$runtime_prepare_line" ] && [ -n "$registry_init_line" ] &&
    [ "$config_prepare_line" -lt "$backend_validate_line" ] &&
    [ "$backend_validate_line" -lt "$runtime_prepare_line" ] &&
    [ "$runtime_prepare_line" -lt "$registry_init_line" ] ||
    fail 'QEMU must validate its Samba backend before creating Owner runtime/authority state'
grep -F 'PHANTOWD_IDENTITY_OWNER_BOOT_READY service_uid=0 socket_mode=0620 api_uid=nonroot config_validated_before_owner_state=true config_missing_rejected=true config_invalid_rejected=true no_side_effects=true process_restart=true drained=true runtime=run http=false scope=qemu-only' "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke must require the boot owner service lifecycle marker'
smb_revoke_marker='PHANTOWD_SMB_CONNECTION_REVOCATION_READY pre_disable_active_write=true disable_revokes_active_sessions=true target_connections=2 target_sessions_absent=true same_ip_peer_preserved=true peer_session_verified=true fresh_login_denied=true process_generation_available=true generation_targeting=qemu-only stale_generation_nonmatch_safe=true pid_targeting=false open_handles=false durable_reconnect=false scope=isolated-qemu-only'
grep -F "$smb_revoke_marker" "$repo_root/src/phantowd-api/smb_session_qemu_linux.go" >/dev/null ||
    fail 'QEMU SMB fixture must define the account-scoped disable-and-revoke marker'
grep -F "$smb_revoke_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke must require account-scoped session revocation and same-IP peer preservation'
sh "$repo_root/support/tests/test-qemu-selftest-helper.sh"

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
