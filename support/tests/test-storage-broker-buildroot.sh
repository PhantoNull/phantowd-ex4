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
qemu_owner_mode=$(git -c safe.directory="$repo_root" -C "$repo_root" ls-files --stage -- \
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
grep -F 'PHANTOWD_IDENTITY_OWNER_DESIRED_STATE_READY enabled=true disabled=true registry_revisioned=true native_journal_immutable=true smb_journal=false auth_mutation=false service_activation=false http=false scope=qemu-only' "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke must require the non-activating Owner desired-state roundtrip'
grep -F 'PHANTOWD_IDENTITY_OWNER_BOOT_READY service_uid=0 socket_mode=0620 api_uid=nonroot config_validated_before_owner_state=true config_missing_rejected=true config_invalid_rejected=true no_side_effects=true process_restart=true drained=true desired_state_roundtrip=true native_journal_immutable=true smb_journal=false service_activation=false runtime=run http=false scope=qemu-only' "$repo_root/support/qemu-smoke.sh" >/dev/null ||
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
mounted_census_marker='PHANTOWD_MOUNTED_EXT_CENSUS_READY namespace_scoped=true roots_from_mountinfo=true rootfs_excluded=true md_members=2 repeated_metadata=true private=true block_opened=false file_data_read=false qualification=false activation=false scope=disposable-qemu-only'
grep -F "$mounted_census_marker" "$repo_root/src/phantowd-api/md_stack_qemu_linux.go" >/dev/null || fail 'QEMU must exercise the fixed private mounted-ext census'
grep -F "$mounted_census_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null || fail 'QEMU smoke must require the complete-scope census assertion'
mounted_review_marker='PHANTOWD_SCOPED_VOLUME_REVIEW_READY desired_ids_only=true complete_census=true actual_md=true unclaimed_explicit=true private=true qualification=false activation=false scope=disposable-qemu-only'
grep -F "$mounted_review_marker" "$repo_root/src/phantowd-api/md_stack_qemu_linux.go" >/dev/null || fail 'QEMU must exercise private scoped desired-volume review'
grep -F "$mounted_review_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null || fail 'QEMU smoke must require scoped desired-volume review'
grep -F "$mounted_identity_marker" "$repo_root/src/phantowd-api/mount_guard_qemu_linux.go" >/dev/null ||
    fail 'QEMU mounted-identity integration must define its complete fixture marker'
grep -F "$mounted_identity_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke must require mounted filesystem identity correlation'

md_filesystem_identity_marker='PHANTOWD_MD_FILESYSTEM_IDENTITY_READY filesystem_to_md=true md_uuid_internal=true members=2 readonly_mount=true conflict_free=true scope=disposable-qemu-only'
grep -F "$md_filesystem_identity_marker" "$repo_root/src/phantowd-api/md_stack_qemu_linux.go" >/dev/null ||
    fail 'QEMU MD fixture must correlate a mounted filesystem to its transient MD/member identity'
grep -F "$md_filesystem_identity_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke must require mounted MD/filesystem identity correlation'

md_v10_api="$repo_root/src/phantowd-api/md_v10_qemu_linux.go"
md_v10_discovery="$repo_root/src/phantowd-api/storage_md_v10.go"
md_v10_provider="$repo_root/src/phantowd-api/storage_broker_md_v10_qemu_linux.go"
md_v10_stub="$repo_root/src/phantowd-api/smb_io_stub.go"
md_v10_init="$repo_root/board/qemu/armv5/rootfs-overlay/usr/lib/phantowd/qemu-md-v10-init.sh"
md_v10_fixture="$repo_root/support/qemu-md-v10-fixture.sh"
md_v10_broker_marker='PHANTOWD_MD_V10_BROKER_READY candidates=2 gpt=2 raid_partitions=2 metadata_candidates=2 arrays=1 status=metadata-consistent active_roles=complete peer_nonroot=true broker_readonly=true generation_rechecked=true assembly=false mount=false filesystem_data=false scope=disposable-qemu-only'
md_v10_marker='PHANTOWD_MD_V10_READY metadata=1.0 raid1=true members=2 gpt=true partition=1 filesystem=ext2 array_stopped=true root_snapshot=true scope=disposable-qemu-only'
md_v10_m34_marker='PHANTOWD_MD_V10_M34_OWNER_READY metadata=1.0 raid1=true candidates=2 active_roles=complete filesystem_uuid=true member_topology=true assembly_readonly=true mount_readonly=true owner_live_revalidated=true planner_snapshot=true activation=false http=false scope=disposable-qemu-only'
md_v10_component_set_host_marker='PHANTOWD_MD_V10_COMPONENT_SET_HOST_READY components=2 metadata=1.0 checksums=valid status=metadata-consistent active_roles=complete descriptor_readonly=true input_unchanged=true wd_compatibility=unqualified assembly=false mount=false scope=tmpfs-qemu-only'
md_v10_host_marker='PHANTOWD_MD_V10_HOST_READY disks=2 gpt=valid partition=1 type=linux-raid metadata=1.0 checksums=valid same_array=true distinct_members=true active_roles=complete set_comparison=expected-filesystem-uuid-review md_metadata_consistent=true input_unchanged=true scope=tmpfs-qemu-only'
[ -f "$md_v10_api" ] && [ -f "$md_v10_init" ] && [ -f "$md_v10_fixture" ] ||
    fail 'MD v1.0 QEMU/host fixture source files are incomplete'
grep -F "$md_v10_marker" "$md_v10_api" >/dev/null ||
    fail 'guest MD v1.0 fixture must report only its bounded synthetic RAID1 result'
grep -F "$md_v10_broker_marker" "$md_v10_api" >/dev/null ||
    fail 'guest MD v1.0 fixture must require a redacted broker observation from its non-root client'
grep -F 'mkfs.ext2' "$md_v10_api" >/dev/null ||
    fail 'guest MD v1.0 fixture must format only the fixed disposable array before read-only reassembly'
grep -F "$md_v10_m34_marker" "$repo_root/src/phantowd-api/md_v10_m34_qemu_linux.go" >/dev/null ||
    fail 'guest MD v1.0 fixture must require read-only assembly/mount and M3.4 Owner evidence'
grep -F 'runQEMUMDV10BrokerClientAsAPIUser' "$repo_root/src/phantowd-api/md_v10_m34_qemu_linux.go" >/dev/null ||
    fail 'M3.4 fixture must gate on a fresh broker observation through the API-UID client'
if grep -F 'observeTrustedMDV10ForBroker' "$repo_root/src/phantowd-api/md_v10_m34_qemu_linux.go" >/dev/null; then
    fail 'root M3.4 fixture must not bypass the non-root broker to read block devices'
fi
grep -F "$md_v10_m34_marker" "$md_v10_fixture" >/dev/null ||
    fail 'host wrapper must require the MD v1.0-to-M3.4 QEMU marker'
grep -F "mkdir /srv/phantowd/volumes" "$repo_root/support/container/test-qemu-api-overlay.sh" >/dev/null ||
    fail 'current-source MD overlay must create the dedicated mount-root directory in its temporary rootfs copy'
grep -F "stat /srv/phantowd/volumes" "$repo_root/support/container/test-qemu-api-overlay.sh" >/dev/null ||
    fail 'current-source MD overlay must verify the temporary mount-root directory before installing the fixture'
grep -F 'mount -t tmpfs -o mode=0755,nosuid,nodev,size=1m tmpfs /srv/phantowd/volumes' "$md_v10_init" >/dev/null ||
    fail 'MD v1.0 M3.4 fixture must keep its mount-owner target on disposable tmpfs'
grep -F 'runQEMUMDV10BrokerClientAsAPIUser' "$md_v10_api" >/dev/null ||
    fail 'guest MD v1.0 fixture must exercise the API-credential broker client'
grep -F 'observeTrustedMDV10With' "$md_v10_provider" >/dev/null ||
    fail 'trusted MD v1.0 provider must run behind the QEMU storage broker'
grep -Fx '//go:build qemu && linux' "$md_v10_provider" >/dev/null ||
    fail 'real-device MD v1.0 broker reads must be compiled only into the QEMU fixture'
grep -F 'return storageMDV10ObservationSummary{}, errStorageBrokerUnavailable' "$md_v10_stub" >/dev/null ||
    fail 'non-QEMU firmware builds must refuse the MD v1.0 broker operation without reading devices'
grep -F 'inspectTrustedMDV10Candidates' "$md_v10_discovery" >/dev/null ||
    fail 'trusted MD v1.0 observation must correlate only GPT-declared RAID partitions'
grep -F 'revalidateTrustedStorageDiscovery' "$repo_root/src/phantowd-api/storage_md_v10_linux.go" >/dev/null ||
    fail 'trusted MD v1.0 observation must recheck storage, mounts and swap before returning'
grep -F 'mdmetadata.InspectBlock' "$md_v10_provider" >/dev/null ||
    fail 'broker MD v1.0 operation must call the parser on its fixed read-only block sources'
grep -F '/sbin/mdev -s' "$md_v10_init" >/dev/null ||
    fail 'MD v1.0 QEMU init must apply read-only device permissions before broker startup'
grep -F 'S40phantowd-storage-broker start' "$md_v10_init" >/dev/null ||
    fail 'MD v1.0 QEMU fixture must start the non-root storage broker'
grep -F "$md_v10_host_marker" "$md_v10_fixture" >/dev/null ||
    fail 'host MD v1.0 fixture must verify both parser reports and unchanged inputs'
grep -F -- '--metadata=1.0' "$repo_root/src/phantowd-api/qemu_md_arguments.go" >/dev/null ||
    fail 'guest fixture must explicitly create metadata version 1.0'
grep -F -- '"/dev/sdb1", "/dev/sdc1"' "$repo_root/src/phantowd-api/qemu_md_arguments.go" >/dev/null ||
    fail 'guest mdadm command must target only partition 1 on its two fixed disposable GPT disks'
grep -F 'truncate -s 32M "$workspace/member-a.raw" "$workspace/member-b.raw"' "$md_v10_fixture" >/dev/null ||
    fail 'host fixture must create exactly two 32 MiB member files'
grep -F 'refuses non-tmpfs temporary storage' "$md_v10_fixture" >/dev/null ||
    fail 'host fixture must fail closed unless its member files live in tmpfs'
grep -F 'snapshot=on' "$md_v10_fixture" >/dev/null ||
    fail 'guest root disk must use a temporary QEMU snapshot'
grep -F -- '-nic none' "$md_v10_fixture" >/dev/null ||
    fail 'MD v1.0 fixture must not attach a network interface'
grep -F 'inspect-md-v1.0-partition' "$md_v10_fixture" >/dev/null ||
    fail 'host-side partition parser must read each generated GPT member'
grep -F 'inspect-storage-image-set' "$md_v10_fixture" >/dev/null ||
    fail 'host-side whole-disk parser must compare the GPT partition members'
grep -F 'duplicate_filesystem_uuid_groups") != 1' "$md_v10_fixture" >/dev/null ||
    fail 'whole-disk fixture must account for the expected mirrored ext filesystem UUID review result'
grep -F 'image_set_status" -ne 2' "$md_v10_fixture" >/dev/null ||
    fail 'whole-disk fixture must accept only the specific redacted review exit status'
grep -F 'inspect-md-v1.0-component-set' "$md_v10_fixture" >/dev/null ||
    fail 'host-side component-set parser must compare the extracted mdadm-authored partition images'
grep -F 'bs=512 skip=2048 count=63455' "$md_v10_fixture" >/dev/null ||
    fail 'host fixture must extract the exact synthetic GPT partition ranges for the standalone component test'
grep -F "$md_v10_component_set_host_marker" "$md_v10_fixture" >/dev/null ||
    fail 'host fixture must require the extracted MD v1.0 component-set result and unchanged inputs'
grep -F 'a19d880f-05fc-4d3b-a006-743f0f84911e' "$md_v10_fixture" >/dev/null ||
    fail 'host fixture must declare the standard Linux RAID partition type GUID'
sed -n '/^cleanup()/,/^}/p' "$md_v10_fixture" | grep -F '"$workspace/member-set.json"' >/dev/null ||
    fail 'MD v1.0 fixture cleanup must remove the generated component-set report'
sed -n '/^cleanup()/,/^}/p' "$md_v10_fixture" | grep -F '"$workspace/member-a-component.raw"' >/dev/null ||
    fail 'MD v1.0 fixture cleanup must remove extracted standalone component images'
sed -n '/^cleanup()/,/^}/p' "$md_v10_fixture" | grep -F '"$workspace/component-set.json"' >/dev/null ||
    fail 'MD v1.0 fixture cleanup must remove the extracted component-set report'
grep -F 'sha256sum "$images/rootfs.ext2"' "$md_v10_fixture" >/dev/null ||
    fail 'MD v1.0 QEMU run must assert the root image remained unchanged'
grep -F 'TMPDIR=/phantowd-qemu-fixture-tmp' "$build_qemu_script" >/dev/null ||
    fail 'full QEMU runner must place generated component files on its dedicated tmpfs'
grep -F 'qemu-md-v10-fixture.sh' "$repo_root/support/container/test-qemu-api-overlay.sh" >/dev/null ||
    fail 'current-source local overlay runner must be able to exercise the MD v1.0 fixture'
grep -F 'PHANTOWD_QEMU_OVERLAY_MD_V10_ONLY=1' "$repo_root/support/test-qemu-md-v10.ps1" >/dev/null ||
    fail 'local MD v1.0 preflight must omit unrelated long QEMU fixtures'
grep -F 'PHANTOWD_QEMU_OVERLAY_SMOKE_ONLY=1' "$repo_root/support/test-qemu-md-v10.ps1" >/dev/null ||
    fail 'local standard-smoke mode must skip only the separate two-boot fixture'

# Keep the QEMU smoke driver's expected marker synchronized with the guest
# self-test. A typo here otherwise costs a full ARMv5 build before the guest
# can even boot.
source_set_marker=$(sed -n 's/.*fmt\.Println("\(PHANTOWD_VOLUME_SET_READY[^"]*\)").*/\1/p' \
    "$repo_root/src/phantowd-api/volume_probe_qemu_linux.go")
[ -n "$source_set_marker" ] ||
    fail 'guest self-test must define one source-set readiness marker'
grep -F "$source_set_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke assertion must match the guest source-set readiness marker'

process_owner_review_marker=$(sed -n 's/.*fmt\.Println("\(PHANTOWD_PROCESS_OWNER_REVIEW_READY[^\"]*\)").*/\1/p' \
    "$repo_root/src/phantowd-api/smb_io_qemu_linux.go")
[ -n "$process_owner_review_marker" ] ||
    fail 'guest self-test must define the unexpected-exit process-owner marker'
grep -F "$process_owner_review_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke assertion must match the process-owner quarantine marker'

process_owner_force_stop_marker=$(sed -n 's/.*fmt\.Println("\(PHANTOWD_PROCESS_OWNER_FORCE_STOP_READY[^\"]*\)").*/\1/p' \
    "$repo_root/src/phantowd-api/smb_io_qemu_linux.go")
[ -n "$process_owner_force_stop_marker" ] ||
    fail 'guest self-test must define the process-owner forced-stop marker'
grep -F "$process_owner_force_stop_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke assertion must match the process-owner forced-stop marker'

process_owner_failed_start_marker=$(sed -n 's/.*fmt\.Println("\(PHANTOWD_PROCESS_OWNER_FAILED_START_REVIEW_READY[^\"]*\)").*/\1/p' \
    "$repo_root/src/phantowd-api/smb_io_qemu_linux.go")
[ -n "$process_owner_failed_start_marker" ] ||
    fail 'guest self-test must define the process-owner failed-start review marker'
grep -F "$process_owner_failed_start_marker" "$repo_root/support/qemu-smoke.sh" >/dev/null ||
    fail 'QEMU smoke assertion must match the failed-start review marker'

printf 'Read-only storage broker Buildroot contracts passed\n'
