#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Host-owned GPT-partitioned MD 1.0 test; mdadm writes only two 32 MiB tmpfs files.
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
        "$workspace/member-a-component.raw" "$workspace/member-b-component.raw" \
        "$workspace/member-a.json" "$workspace/member-b.json" "$workspace/member-set.json" \
        "$workspace/component-set.json" \
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
python3 "$source_dir/support/make-qemu-gpt-fixture.py" \
    "$workspace/member-a.raw" \
    "500f0000-0000-0000-0000-000000000102" \
    "8fd20a43-e550-4632-9a8e-5241c40c0861" \
    "a19d880f-05fc-4d3b-a006-743f0f84911e"
python3 "$source_dir/support/make-qemu-gpt-fixture.py" \
    "$workspace/member-b.raw" \
    "500f0000-0000-0000-0000-000000000103" \
    "8fd20a43-e550-4632-9a8e-5241c40c0862" \
    "a19d880f-05fc-4d3b-a006-743f0f84911e"
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
grep -F 'PHANTOWD_MD_V10_READY metadata=1.0 raid1=true members=2 gpt=true partition=1 fixed_devices=true array_stopped=true root_snapshot=true scope=disposable-qemu-only' "$workspace/qemu.log" >/dev/null
grep -F 'PHANTOWD_MD_V10_PRODUCT_PROBE_READY disks=2 metadata=1.0 checksums=valid comparison=metadata-consistent same_array=true distinct_members=true active_roles=complete descriptor_readonly=true diskseq_bound=true assembly=false mount=false scope=disposable-qemu-only' "$workspace/qemu.log" >/dev/null
grep -F 'PHANTOWD_MD_V10_TRUSTED_DISCOVERY_READY candidates=2 gpt=2 raid_partitions=2 metadata_candidates=2 arrays=1 status=metadata-consistent sources_readonly=true generation_rechecked=true assembly=false mount=false scope=disposable-qemu-only' "$workspace/qemu.log" >/dev/null
if grep -E 'PHANTOWD_MD_V10_ERROR|PHANTOWD_API_ERROR|Kernel panic' "$workspace/qemu.log" >/dev/null; then
    exit 1
fi
[ "$(sha256sum "$images/rootfs.ext2" | awk '{print $1}')" = "$root_hash" ] || {
    echo 'MD v1.0 fixture changed its snapshot-protected root image' >&2
    exit 1
}
member_a_hash=$(sha256sum "$workspace/member-a.raw" | awk '{print $1}')
member_b_hash=$(sha256sum "$workspace/member-b.raw" | awk '{print $1}')
dd if="$workspace/member-a.raw" of="$workspace/member-a-component.raw" bs=512 skip=2048 count=63455 2>/dev/null
dd if="$workspace/member-b.raw" of="$workspace/member-b-component.raw" bs=512 skip=2048 count=63455 2>/dev/null
[ -f "$workspace/member-a-component.raw" ] && [ ! -L "$workspace/member-a-component.raw" ]
[ -f "$workspace/member-b-component.raw" ] && [ ! -L "$workspace/member-b-component.raw" ]
[ "$(stat -c '%s' "$workspace/member-a-component.raw")" = 32488960 ] || exit 1
[ "$(stat -c '%s' "$workspace/member-b-component.raw")" = 32488960 ] || exit 1
component_a_hash=$(sha256sum "$workspace/member-a-component.raw" | awk '{print $1}')
component_b_hash=$(sha256sum "$workspace/member-b-component.raw" | awk '{print $1}')
"$workspace/phantowd-lab" inspect-md-v1.0-partition "$workspace/member-a.raw" 1 > "$workspace/member-a.json"
"$workspace/phantowd-lab" inspect-md-v1.0-partition "$workspace/member-b.raw" 1 > "$workspace/member-b.json"
"$workspace/phantowd-lab" inspect-storage-image-set \
    "$workspace/member-a.raw" "$workspace/member-b.raw" > "$workspace/member-set.json"
if ! "$workspace/phantowd-lab" inspect-md-v1.0-component-set \
    "$workspace/member-a-component.raw" "$workspace/member-b-component.raw" > "$workspace/component-set.json"; then
    cat "$workspace/component-set.json" >&2
    exit 1
fi
[ "$(sha256sum "$workspace/member-a.raw" | awk '{print $1}')" = "$member_a_hash" ] || {
    echo 'Host parser modified MD v1.0 component A' >&2
    exit 1
}
[ "$(sha256sum "$workspace/member-b.raw" | awk '{print $1}')" = "$member_b_hash" ] || {
    echo 'Host parser modified MD v1.0 component B' >&2
    exit 1
}
[ "$(sha256sum "$workspace/member-a-component.raw" | awk '{print $1}')" = "$component_a_hash" ] || {
    echo 'Host parser modified extracted MD v1.0 component A' >&2
    exit 1
}
[ "$(sha256sum "$workspace/member-b-component.raw" | awk '{print $1}')" = "$component_b_hash" ] || {
    echo 'Host parser modified extracted MD v1.0 component B' >&2
    exit 1
}
python3 - "$workspace/member-a.json" "$workspace/member-b.json" "$workspace/member-set.json" \
    "$workspace/component-set.json" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        first = json.load(stream)
    with open(sys.argv[2], encoding="utf-8") as stream:
        second = json.load(stream)
    with open(sys.argv[3], encoding="utf-8") as stream:
        component_set = json.load(stream)
    with open(sys.argv[4], encoding="utf-8") as stream:
        extracted_set = json.load(stream)
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
summaries = []
for disk_report in reports:
    md = disk_report.get("md_superblock", {})
    summaries.append({
        "gpt_status": disk_report.get("gpt", {}).get("status"),
        "partition_number": disk_report.get("partition_number"),
        **{key: md.get(key) for key in summary_fields},
    })
for report in reports:
    md = report.get("md_superblock", {})
    if (report.get("format") != "phantowd-md-v1.0-gpt-partition-inspection"
            or report.get("partition_number") != 1
            or report.get("gpt", {}).get("status") != "valid-gpt"
            or md.get("status") != "md-v1.0-superblock-candidate"
            or md.get("metadata_version") != "1.0"
            or md.get("superblock_checksum_status") != "valid"
            or md.get("array_level") != 1
            or md.get("raid_disks") != 2
            or not 2 <= md.get("max_devices", 0) <= 128
            or md.get("member_role_description") != "active-slot"
            or not md.get("array_identity_fingerprint")
            or not md.get("member_identity_fingerprint")
            or md.get("wd_compatibility") != "unqualified"
            or md.get("raw_identity_redacted") is not True
            or md.get("block_device_opened") is not False
            or md.get("mutations_performed") is not False
            or md.get("assembly_performed") is not False
            or md.get("mount_performed") is not False):
        raise SystemExit("host MD v1.0 partition parser report did not meet the generic read-only contract: "
                         + json.dumps(summaries, sort_keys=True))
if reports[0]["md_superblock"]["array_identity_fingerprint"] != \
        reports[1]["md_superblock"]["array_identity_fingerprint"]:
    raise SystemExit("mdadm MD v1.0 partitions did not share an array identity: "
                     + json.dumps(summaries, sort_keys=True))
if reports[0]["md_superblock"]["member_identity_fingerprint"] == \
        reports[1]["md_superblock"]["member_identity_fingerprint"]:
    raise SystemExit("mdadm MD v1.0 partitions did not have distinct member identities: "
                     + json.dumps(summaries, sort_keys=True))
if sorted(report["md_superblock"]["member_number"] for report in reports) != [0, 1] or \
        sorted(report["md_superblock"]["member_role"] for report in reports) != [0, 1]:
    raise SystemExit("mdadm MD v1.0 partitions did not contain both active RAID roles: "
                     + json.dumps(summaries, sort_keys=True))
comparison = component_set.get("md_v1_0_comparison", {})
arrays = comparison.get("arrays", [])
members = arrays[0].get("members", []) if len(arrays) == 1 else []
inputs = component_set.get("inputs", [])
identity_scan = component_set.get("identity_scan", {})
if (component_set.get("format") != "phantowd-read-only-storage-image-set-observation"
        or component_set.get("schema_version") != 2
        or component_set.get("status") != "metadata-observed"
        or component_set.get("wd_compatibility") != "unqualified"
        or len(inputs) != 2
        or any(item.get("gpt_status") != "valid-gpt"
               or item.get("partition_count") != 1
               or item.get("md_v1_0_candidate_count") != 1
               or len(item.get("partition_observations", [])) != 1
               or item["partition_observations"][0].get("partition_number") != 1
               or item["partition_observations"][0].get("declared_type_guid") != "a19d880f-05fc-4d3b-a006-743f0f84911e"
               or item["partition_observations"][0].get("md_v1_0_status") != "md-v1.0-superblock-candidate"
               for item in inputs)
        or identity_scan.get("complete") is not True
        or identity_scan.get("duplicate_disk_guid_groups") != 0
        or identity_scan.get("duplicate_partuuid_groups") != 0
        or comparison.get("candidate_components") != 2
        or comparison.get("unqualified_components") != 0
        or comparison.get("unidentified_candidate_components") != 0
        or len(arrays) != 1
        or arrays[0].get("status") != "metadata-consistent"
        or arrays[0].get("observed_active_roles") != 2
        or [member.get("input_index") for member in members] != [1, 2]
        or [member.get("partition_number") for member in members] != [1, 1]
        or component_set.get("block_device_opened") is not False
        or component_set.get("mutations_performed") is not False
        or component_set.get("assembly_performed") is not False
        or component_set.get("mount_performed") is not False):
    raise SystemExit("host whole-disk parser did not confirm a generic GPT-partitioned read-only array: "
                     + json.dumps(component_set, sort_keys=True))
extracted_components = extracted_set.get("components", [])
extracted_comparison = extracted_set.get("comparison", {})
extracted_arrays = extracted_comparison.get("arrays", [])
if (extracted_set.get("format") != "phantowd-md-v1.0-component-set-inspection"
        or extracted_set.get("schema_version") != 1
        or extracted_set.get("status") != "metadata-consistent"
        or extracted_set.get("wd_compatibility") != "unqualified"
        or len(extracted_components) != 2
        or any(item.get("status") != "md-v1.0-superblock-candidate"
               or item.get("report", {}).get("superblock_checksum_status") != "valid"
               for item in extracted_components)
        or extracted_comparison.get("candidate_components") != 2
        or extracted_comparison.get("unqualified_components") != 0
        or extracted_comparison.get("unidentified_candidate_components") != 0
        or len(extracted_arrays) != 1
        or extracted_arrays[0].get("status") != "metadata-consistent"
        or extracted_arrays[0].get("observed_active_roles") != 2
        or extracted_arrays[0].get("missing_active_roles") != []
        or sorted(item.get("report", {}).get("member_number") for item in extracted_components) != [0, 1]
        or sorted(item.get("report", {}).get("member_role") for item in extracted_components) != [0, 1]
        or extracted_set.get("block_device_opened") is not False
        or extracted_set.get("mutations_performed") is not False
        or extracted_set.get("assembly_performed") is not False
        or extracted_set.get("mount_performed") is not False):
    raise SystemExit("host extracted-component parser did not confirm a generic read-only array: "
                     + json.dumps(extracted_set, sort_keys=True))
serialized = json.dumps([reports, component_set, extracted_set], sort_keys=True)
for private_value in ("PHANTOWD-QEMU-MDV10-A", "PHANTOWD-QEMU-MDV10-B", "PHANTOWD-QEMU-MDV10-ROOT"):
    if private_value in serialized:
        raise SystemExit("host parser report leaked a QEMU-only VPD identity")
PY
echo 'PHANTOWD_MD_V10_COMPONENT_SET_HOST_READY components=2 metadata=1.0 checksums=valid status=metadata-consistent active_roles=complete descriptor_readonly=true input_unchanged=true wd_compatibility=unqualified assembly=false mount=false scope=tmpfs-qemu-only' | tee -a "$log"
echo 'PHANTOWD_MD_V10_HOST_READY disks=2 gpt=valid partition=1 type=linux-raid metadata=1.0 checksums=valid same_array=true distinct_members=true active_roles=complete set_comparison=metadata-observed input_unchanged=true scope=tmpfs-qemu-only' | tee -a "$log"
grep -F 'PHANTOWD_MD_V10_COMPONENT_SET_HOST_READY components=2 metadata=1.0 checksums=valid status=metadata-consistent active_roles=complete descriptor_readonly=true input_unchanged=true wd_compatibility=unqualified assembly=false mount=false scope=tmpfs-qemu-only' "$log" >/dev/null
