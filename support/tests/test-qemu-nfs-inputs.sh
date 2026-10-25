#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# One disposable ARM code-data fixture; no NFS program is executed.
set -eu
base=${1:?BASE TARGET GO DEBUGFS SOURCE [FAILURE_LOG]}
target=${2:?extracted public Buildroot target required}
go_binary=${3:?pinned Go required}
debugfs=${4:?pinned debugfs required}
source_dir=${5:?source required}
failure_log=${6:-}
tmpdir=${TMPDIR:-/tmp}
export TMPDIR="$tmpdir"
case "$base:$target:$go_binary:$debugfs:$source_dir:$failure_log:$tmpdir" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$tmpdir" in /*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
[ -d "$target" ] && [ ! -L "$target" ] || exit 1
(cd "$base" && sha256sum -c SHA256SUMS)
sh "$source_dir/support/tests/test-samba-root-staging-environment.sh" "$debugfs" "$source_dir"
base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
scratch=$(mktemp -d "$tmpdir/phantowd-nfs-inputs.XXXXXX")
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    rm -f "$scratch/rootfs.ext2" "$scratch/lab" "$scratch/probe" "$scratch/metadata" "$scratch/inventory.json" "$scratch/candidate.json" "$scratch/expected" "$scratch/marker" "$scratch/check" "$scratch/guest.log"
    rm -rf "$scratch/go-cache" "$scratch/go-path"
    rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
(cd "$source_dir/tools/phantowd-lab" && "$go_binary" build -trimpath -o "$scratch/lab" ./cmd/phantowd-lab)
"$scratch/lab" inventory-rootfs "$target" >"$scratch/inventory.json"
"$scratch/lab" inspect-nfs-runtime "$target" >"$scratch/candidate.json"
python3 - "$scratch" <<'PY'
import json
from pathlib import Path
import re
import sys
root = Path(sys.argv[1])
assert (root / 'inventory.json').stat().st_size <= 16 << 20
assert (root / 'candidate.json').stat().st_size <= 128 << 10
inventory = json.loads((root / 'inventory.json').read_text())
candidate = json.loads((root / 'candidate.json').read_text())
observed = inventory['root_digest_sha256']
assert inventory['format'] == 'phantowd-extracted-rootfs-inventory' and re.fullmatch('[0-9a-f]{64}', observed)
assert candidate['root_digest_sha256'] == observed
(root / 'expected').write_text(observed + '\n')
files = len(candidate['objects'])
aliases = sum(len(item['bindings']) for item in candidate['objects']) - files
(root / 'marker').write_text(f"PHANTOWD_NFS_CODE_INPUTS_READY files={files} aliases={aliases} bytes={candidate['total_bytes']} separate_root=true readonly=true duplicate_caller_closed=true released=true fd_equal=true execution=false kernel_backend=false scope=qemu-only\n")
PY
(cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 "$go_binary" build -tags=qemu -trimpath -ldflags='-s -w' -o "$scratch/probe" ./cmd/qemu-runtime-bundle)
(cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 "$go_binary" test -c -tags=qemu -trimpath -ldflags='-s -w' -o "$scratch/metadata" ./internal/runtimebundle)
rm -rf "$scratch/go-cache" "$scratch/go-path"
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
[ "$(wc -c <"$scratch/rootfs.ext2")" -le 134217728 ] || exit 1
"$(dirname "$debugfs")/resize2fs" "$scratch/rootfs.ext2" 128M >/dev/null
for pair in "$scratch/probe /usr/sbin/phantowd-runtime-bundle-probe 0100755" "$scratch/metadata /usr/sbin/phantowd-runtime-metadata-tests 0100755" "$source_dir/support/tests/nfs-inputs-init.sh /usr/sbin/phantowd-nfs-inputs-init 0100755" "$scratch/candidate.json /usr/lib/phantowd/qemu-nfs-inputs.json 0100644" "$scratch/expected /usr/lib/phantowd/qemu-nfs-expected-root 0100644"; do
    input=${pair%% *} remainder=${pair#* }
    destination=${remainder% *} mode=${remainder##* }
    sh "$source_dir/support/tests/stage-samba-root-file.sh" "$debugfs" "$scratch/rootfs.ext2" "$input" "$destination" "$scratch/check" "$mode"
done
TMPDIR="$scratch" timeout --signal=TERM --kill-after=5 90 qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 phantowd_nfs_inputs_fixture=1 init=/usr/sbin/phantowd-nfs-inputs-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" >"$scratch/guest.log" 2>&1 &
child_pid=$!
status=0
wait "$child_pid" || status=$?
child_pid=
if [ "$status" -ne 0 ] || [ "$(grep '^PHANTOWD_NFS_CODE_INPUTS_' "$scratch/guest.log" | tr -d '\r')" != "$(cat "$scratch/marker"; echo PHANTOWD_NFS_CODE_INPUTS_DONE)" ] ||
    [ "$(grep -Ec '^--- PASS: Test(NFSExpectedQEMU|NFSCodeProbe)' "$scratch/guest.log")" -ne 7 ] || grep -Eq '^--- FAIL:|^FAIL|--- SKIP:' "$scratch/guest.log"; then
    if [ -n "$failure_log" ]; then mkdir -p "$(dirname "$failure_log")"; cp "$scratch/guest.log" "$failure_log"; fi
    tail -n 100 "$scratch/guest.log" >&2
    exit 1
fi
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
grep -E '^--- PASS: Test(NFSExpectedQEMU|NFSCodeProbe)' "$scratch/guest.log"
grep '^PHANTOWD_NFS_CODE_INPUTS_' "$scratch/guest.log"
echo PHANTOWD_NFS_CODE_INPUTS_BASE_UNCHANGED
