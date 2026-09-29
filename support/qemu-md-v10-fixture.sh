#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Host-owned end-to-end MD 1.0 test: two 32 MiB tmpfs files only.
set -eu

images=${1:?usage: qemu-md-v10-fixture.sh IMAGES_DIR GO_BINARY SOURCE_DIR OUTPUT_LOG}
go_binary=${2:?Go compiler required}
source_dir=${3:?source directory required}
log=${4:?output log required}
qemu=${QEMU_SYSTEM_ARM:-qemu-system-arm}
tmpdir=${TMPDIR:-/tmp}
case "$images:$go_binary:$source_dir:$log:$tmpdir" in *[!a-zA-Z0-9_./:-]*) echo 'Unsupported fixture path' >&2; exit 1 ;; esac
for file in rootfs.ext2 zImage versatile-pb.dtb; do
    [ -f "$images/$file" ] && [ ! -L "$images/$file" ] || exit 1
done
[ -x "$go_binary" ] || exit 1
[ -f "$source_dir/tools/phantowd-lab/go.mod" ] || exit 1
case "$tmpdir" in /*) ;;
    *) echo 'MD v1.0 fixture temporary storage must be an absolute path' >&2; exit 1 ;;
esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || {
    echo 'MD v1.0 fixture refuses non-tmpfs temporary storage' >&2
    exit 1
}

workspace=$(mktemp -d "$tmpdir/phantowd-md-v10.XXXXXX")
qemu_pid=
cleanup() {
    if [ -n "$qemu_pid" ]; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -f "$workspace/member-a.raw" "$workspace/member-b.raw" \
        "$workspace/member-a.json" "$workspace/member-b.json" "$workspace/member-set.json" \
        "$workspace/phantowd-lab" "$workspace/qemu.log"
    rmdir "$workspace"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

truncate -s 32M "$workspace/member-a.raw" "$workspace/member-b.raw"
[ -f "$workspace/member-a.raw" ] && [ ! -L "$workspace/member-a.raw" ]
[ -f "$workspace/member-b.raw" ] && [ ! -L "$workspace/member-b.raw" ]
[ "$(stat -c '%s' "$workspace/member-a.raw")" = 33554432 ]
[ "$(stat -c '%s' "$workspace/member-b.raw")" = 33554432 ]
root_hash=$(sha256sum "$images/rootfs.ext2" | awk '{print $1}')

export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
"$go_binary" version
(cd "$source_dir/tools/phantowd-lab" && \
    "$go_binary" build -trimpath -o "$workspace/phantowd-lab" ./cmd/phantowd-lab)

: > "$log"
"$qemu" \
    -M versatilepb \
    -cpu arm926 \
    -m 256M \
    -kernel "$images/zImage" \
    -dtb "$images/versatile-pb.dtb" \
    -drive "file=$images/rootfs.ext2,if=none,id=rootdisk,format=raw,snapshot=on" \
    -device lsi53c895a,id=scsi0 \
    -device "scsi-hd,bus=scsi0.0,drive=rootdisk,serial=PHANTOWD-QEMU-MDV10-ROOT,wwn=0x500f000000000101" \
    -drive "file=$workspace/member-a.raw,if=none,id=mdmembera,format=raw,cache=writeback" \
    -device "scsi-hd,bus=scsi0.0,drive=mdmembera,serial=PHANTOWD-QEMU-MDV10-A,wwn=0x500f000000000102" \
    -drive "file=$workspace/member-b.raw,if=none,id=mdmemberb,format=raw,cache=writeback" \
    -device "scsi-hd,bus=scsi0.0,drive=mdmemberb,serial=PHANTOWD-QEMU-MDV10-B,wwn=0x500f000000000103" \
    -append 'rootwait root=/dev/sda ro console=ttyAMA0,115200 init=/usr/lib/phantowd/qemu-md-v10-init.sh' \
    -display none -serial stdio -monitor none -no-reboot -nic none \
    > "$workspace/qemu.log" 2>&1 &
qemu_pid=$!

attempt=0
while kill -0 "$qemu_pid" 2>/dev/null && [ "$attempt" -lt 120 ]; do
    if grep -E 'PHANTOWD_MD_V10_ERROR|PHANTOWD_API_ERROR|Kernel panic' "$workspace/qemu.log" >/dev/null; then
        cat "$workspace/qemu.log" >> "$log"
        echo 'MD v1.0 QEMU guest reported a fixture failure' >&2
        exit 1
    fi
    sleep 1
    attempt=$((attempt + 1))
done
if kill -0 "$qemu_pid" 2>/dev/null; then
    cat "$workspace/qemu.log" >> "$log"
    echo 'MD v1.0 QEMU guest timed out' >&2
    exit 1
fi
status=0
wait "$qemu_pid" || status=$?
qemu_pid=
cat "$workspace/qemu.log" >> "$log"
[ "$status" -eq 0 ] || exit 1
grep -F 'PHANTOWD_MD_V10_READY metadata=1.0 raid1=true members=2 fixed_devices=true array_stopped=true root_snapshot=true scope=disposable-qemu-only' "$workspace/qemu.log" >/dev/null
if grep -E 'PHANTOWD_MD_V10_ERROR|PHANTOWD_API_ERROR|Kernel panic' "$workspace/qemu.log" >/dev/null; then
    exit 1
fi
[ "$(sha256sum "$images/rootfs.ext2" | awk '{print $1}')" = "$root_hash" ] || {
    echo 'MD v1.0 fixture changed its snapshot-protected root image' >&2
    exit 1
}
member_a_hash=$(sha256sum "$workspace/member-a.raw" | awk '{print $1}')
member_b_hash=$(sha256sum "$workspace/member-b.raw" | awk '{print $1}')
"$workspace/phantowd-lab" inspect-md-v1.0-component "$workspace/member-a.raw" > "$workspace/member-a.json"
"$workspace/phantowd-lab" inspect-md-v1.0-component "$workspace/member-b.raw" > "$workspace/member-b.json"
"$workspace/phantowd-lab" inspect-md-v1.0-component-set \
    "$workspace/member-a.raw" "$workspace/member-b.raw" > "$workspace/member-set.json"
[ "$(sha256sum "$workspace/member-a.raw" | awk '{print $1}')" = "$member_a_hash" ] || {
    echo 'Host parser modified MD v1.0 component A' >&2
    exit 1
}
[ "$(sha256sum "$workspace/member-b.raw" | awk '{print $1}')" = "$member_b_hash" ] || {
    echo 'Host parser modified MD v1.0 component B' >&2
    exit 1
}
python3 - "$workspace/member-a.json" "$workspace/member-b.json" "$workspace/member-set.json" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        first = json.load(stream)
    with open(sys.argv[2], encoding="utf-8") as stream:
        second = json.load(stream)
    with open(sys.argv[3], encoding="utf-8") as stream:
        component_set = json.load(stream)
    reports = [first, second]
except (OSError, json.JSONDecodeError):
    raise SystemExit("host MD v1.0 parser returned invalid JSON")

if len(reports) != 2:
    raise SystemExit("host MD v1.0 parser did not return both components")
summary_fields = (
    "status", "metadata_version", "superblock_checksum_status", "array_level",
    "raid_disks", "max_devices", "member_number", "member_role",
    "member_role_description", "array_identity_fingerprint",
    "member_identity_fingerprint", "wd_compatibility", "raw_identity_redacted",
    "block_device_opened", "mutations_performed", "assembly_performed", "mount_performed",
)
summary = [{key: report.get(key) for key in summary_fields} for report in reports]
for report in reports:
    if (report.get("status") != "md-v1.0-superblock-candidate"
            or report.get("metadata_version") != "1.0"
            or report.get("superblock_checksum_status") != "valid"
            or report.get("array_level") != 1
            or report.get("raid_disks") != 2
            or not 2 <= report.get("max_devices", 0) <= 128
            or report.get("member_role_description") != "active-slot"
            or not report.get("array_identity_fingerprint")
            or not report.get("member_identity_fingerprint")
            or report.get("wd_compatibility") != "unqualified"
            or report.get("raw_identity_redacted") is not True
            or report.get("block_device_opened") is not False
            or report.get("mutations_performed") is not False
            or report.get("assembly_performed") is not False
            or report.get("mount_performed") is not False):
        raise SystemExit("host MD v1.0 parser report did not meet the generic read-only contract: "
                         + json.dumps(summary, sort_keys=True))
if reports[0]["array_identity_fingerprint"] != reports[1]["array_identity_fingerprint"]:
    raise SystemExit("mdadm MD v1.0 members did not share an array identity: "
                     + json.dumps(summary, sort_keys=True))
if reports[0]["member_identity_fingerprint"] == reports[1]["member_identity_fingerprint"]:
    raise SystemExit("mdadm MD v1.0 components did not have distinct member identities: "
                     + json.dumps(summary, sort_keys=True))
if sorted(report["member_number"] for report in reports) != [0, 1] or \
        sorted(report["member_role"] for report in reports) != [0, 1]:
    raise SystemExit("mdadm MD v1.0 components did not contain both active RAID roles: "
                     + json.dumps(summary, sort_keys=True))
comparison = component_set.get("comparison", {})
arrays = comparison.get("arrays", [])
members = arrays[0].get("members", []) if len(arrays) == 1 else []
if (component_set.get("format") != "phantowd-md-v1.0-component-set-inspection"
        or component_set.get("schema_version") != 1
        or component_set.get("status") != "metadata-consistent"
        or component_set.get("wd_compatibility") != "unqualified"
        or len(component_set.get("components", [])) != 2
        or comparison.get("candidate_components") != 2
        or comparison.get("unqualified_components") != 0
        or comparison.get("unidentified_candidate_components") != 0
        or len(arrays) != 1
        or arrays[0].get("status") != "metadata-consistent"
        or arrays[0].get("observed_active_roles") != 2
        or [member.get("input_index") for member in members] != [1, 2]
        or any("partition_number" in member for member in members)
        or component_set.get("block_device_opened") is not False
        or component_set.get("mutations_performed") is not False
        or component_set.get("assembly_performed") is not False
        or component_set.get("mount_performed") is not False):
    raise SystemExit("host component-set comparison did not confirm a generic complete read-only array: "
                     + json.dumps(component_set, sort_keys=True))
serialized = json.dumps(reports, sort_keys=True)
for private_value in ("PHANTOWD-QEMU-MDV10-A", "PHANTOWD-QEMU-MDV10-B", "PHANTOWD-QEMU-MDV10-ROOT"):
    if private_value in serialized:
        raise SystemExit("host parser report leaked a QEMU-only VPD identity")
PY
echo 'PHANTOWD_MD_V10_HOST_READY components=2 metadata=1.0 checksums=valid same_array=true distinct_members=true active_roles=complete set_comparison=metadata-consistent input_unchanged=true scope=tmpfs-qemu-only' | tee -a "$log"
