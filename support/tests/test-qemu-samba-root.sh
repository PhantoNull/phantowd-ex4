#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Exact fixed public-runtime profile, disposable root snapshot and guest tmpfs.
set -eu
base=${1:?BASE TARGET GO DEBUGFS CC SOURCE [FAILURE_LOG] [CAMPAIGN] [DIAGNOSTICS]}
target=${2:?pinned target required}
go_binary=${3:?pinned Go required}
debugfs=${4:?pinned debugfs required}
compiler=${5:?pinned ARM compiler required}
source_dir=${6:?source required}
failure_log=${7:-}
selection=${8:-all}
[ "$#" -le 9 ] || exit 1
diagnostics=${9:-none}
case "$diagnostics" in none|diagnostic) ;; *) exit 1 ;; esac
case "$selection" in
    all|service|native|candidate|lifecycle|fault|data|exit|held|file|file-source|persistent|pending|pending-peer-exit|pending-handle) ;;
    *) exit 1 ;;
esac
tmpdir=${TMPDIR:-/tmp}
export TMPDIR="$tmpdir"
case "$base:$target:$go_binary:$debugfs:$compiler:$source_dir:$failure_log:$tmpdir" in
    *[!a-zA-Z0-9_./:-]*) exit 1 ;;
esac
case "$tmpdir" in /*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
pending_profile=0
case "$selection" in pending|pending-peer-exit|pending-handle) pending_profile=1 ;; esac
if [ "$pending_profile" -eq 1 ]; then
    campaigns=$selection # Separate prerequisites, NOT the default union.
else
    campaigns=$(python3 -B "$source_dir/support/tests/samba_root_fixture.py" select-campaigns "$selection")
fi
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
[ -d "$target" ] && [ ! -L "$target" ] || exit 1
sh "$source_dir/support/tests/test-samba-root-staging.sh" "$debugfs" "$source_dir"
scratch=$(mktemp -d "$tmpdir/phantowd-samba-root.XXXXXX")
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    # Only this exact newly-created tmpfs directory owns these files.
    rm -f "$scratch/rootfs.ext2" "$scratch/acl.ext4" "$scratch/lab" "$scratch/smbd.json" \
        "$scratch/smbpasswd.json" "$scratch/testparm.json" "$scratch/pdbedit.json" \
        "$scratch/smbstatus.json" "$scratch/smbcontrol.json" \
        "$scratch/streams_xattr.json" "$scratch/ibm850.json" "$scratch/manifest" \
        "$scratch/launcher" "$scratch/charset" "$scratch/bundle" "$scratch/owner" \
        "$scratch/service.log" "$scratch/native.log" "$scratch/candidate.log" \
        "$scratch/lifecycle.log" "$scratch/fault.log" "$scratch/data.log" "$scratch/exit.log" "$scratch/held.log" "$scratch/file.log" "$scratch/file-source.log"
    rm -f "$scratch/persistent.log" "$scratch/pending.log" "$scratch/pending-peer-exit.log" "$scratch/pending-handle.log"
    if [ "$pending_profile" -eq 1 ]; then rm -rf "$scratch/pending"; fi
    rm -rf "$scratch/go-cache" "$scratch/go-path"
    rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
(cd "$source_dir/tools/phantowd-lab" && \
    "$go_binary" build -trimpath -o "$scratch/lab" ./cmd/phantowd-lab)
"$scratch/lab" inspect-runtime-closure "$target" usr/sbin/smbd >"$scratch/smbd.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/bin/smbpasswd >"$scratch/smbpasswd.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/bin/testparm >"$scratch/testparm.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/lib/samba/vfs/streams_xattr.so >"$scratch/streams_xattr.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/lib/gconv/IBM850.so >"$scratch/ibm850.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/bin/pdbedit >"$scratch/pdbedit.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/bin/smbstatus >"$scratch/smbstatus.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/bin/smbcontrol >"$scratch/smbcontrol.json"
python3 -B "$source_dir/support/tests/samba_root_fixture.py" prepare \
    "$scratch/smbd.json" "$scratch/smbpasswd.json" "$scratch/testparm.json" \
    "$scratch/streams_xattr.json" "$scratch/ibm850.json" "$scratch/pdbedit.json" \
    "$scratch/smbstatus.json" "$scratch/smbcontrol.json" \
    "$target/usr/lib/gconv/gconv-modules" "$scratch/manifest"
"$compiler" -std=c11 -O2 -static -Wall -Wextra -Werror \
    -o "$scratch/launcher" "$source_dir/support/tests/samba-root-launcher-fixture.c"
"$compiler" -std=c11 -O2 -Wall -Wextra -Werror \
    -o "$scratch/charset" "$source_dir/support/tests/samba-charset-fixture.c"
(cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    "$go_binary" build -tags=qemu -trimpath -o "$scratch/bundle" ./cmd/qemu-runtime-bundle)
(cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    "$go_binary" build -tags=qemu -trimpath -o "$scratch/owner" ./cmd/qemu-samba-owner)
if [ "$pending_profile" -eq 1 ]; then
    mkdir "$scratch/pending"
    (cd "$source_dir/src/phantowd-api" && "$go_binary" build -tags=qemu -trimpath \
        -o "$scratch/pending/host-inputs" ./cmd/qemu-pending-client-inputs)
    "$scratch/pending/host-inputs" documents >"$scratch/pending/documents.json"
    (cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
        "$go_binary" build -tags=qemu -trimpath -o "$scratch/pending/arm-inputs" ./cmd/qemu-pending-client-inputs)
    "$scratch/lab" inspect-runtime-closure "$target" usr/lib/libsmbclient.so.0 >"$scratch/pending/closure.json"
    if [ "$selection" = pending-handle ]; then
        pinned_output=$(dirname "$target")
        bash "$source_dir/support/tests/build-samba-pending-handle-observer.sh" "$pinned_output" "$source_dir" "$scratch/pending"
        bash "$source_dir/support/tests/test-samba-pending-handle-client.sh" "$pinned_output" "$source_dir" "$scratch/pending"
        cp "$scratch/pending/handle-client" "$scratch/pending/client"
        python3 -B "$source_dir/support/tests/pending_client_inputs_fixture.py" observer-tree \
            "$scratch/pending/closure.json" "$scratch/ibm850.json" "$target" \
            "$scratch/pending/observer.so" "$scratch/pending/observer-tree"
        if ! "$scratch/lab" inspect-runtime-closure "$scratch/pending/observer-tree" \
            usr/lib/libphantowd-pending-handle-qemu.so >"$scratch/pending/observer.json"; then
            head -c 32768 "$scratch/pending/observer.json" >&2
            exit 1
        fi
    else
        "$compiler" -std=c11 -O2 -Wall -Wextra -Werror \
            -I"$target/../staging/usr/include/samba-4.0" -Wl,-rpath-link,"$target/../staging/usr/lib/samba" \
            -o "$scratch/pending/client" "$source_dir/support/tests/samba-pending-write-fixture.c" -lsmbclient
    fi
    "$compiler" -std=c11 -O2 -static -Wall -Wextra -Werror \
        -o "$scratch/pending/helper" "$source_dir/support/tests/samba-pending-write-launcher-fixture.c"
    if [ "$selection" = pending-handle ]; then
        python3 -B "$source_dir/support/tests/pending_client_inputs_fixture.py" \
            "$scratch/pending/closure.json" "$scratch/ibm850.json" "$scratch/pending/documents.json" \
            "$scratch/pending/client" "$scratch/pending/helper" "$target" "$scratch/pending" \
            "$scratch/pending/observer.json" "$scratch/pending/observer.so"
    else
        python3 -B "$source_dir/support/tests/pending_client_inputs_fixture.py" \
            "$scratch/pending/closure.json" "$scratch/ibm850.json" "$scratch/pending/documents.json" \
            "$scratch/pending/client" "$scratch/pending/helper" "$target" "$scratch/pending"
    fi
fi
rm -rf "$scratch/go-cache" "$scratch/go-path"
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
# Enlarge ONLY this new regular tmpfs image copy. The default Go programs
# can also exhaust the borrowed base's free blocks; original base stays RO.
[ -f "$scratch/rootfs.ext2" ] && [ ! -L "$scratch/rootfs.ext2" ] || exit 1
[ "$(wc -c < "$scratch/rootfs.ext2")" -le 134217728 ] || {
    echo 'Samba root copy exceeds the fixed 128 MiB staging bound' >&2
    exit 1
}
truncate -s 128M "$scratch/rootfs.ext2"
"$(dirname "$debugfs")/resize2fs" -f "$scratch/rootfs.ext2" >/dev/null 2>&1
if [ "$pending_profile" -eq 1 ]; then
    "$debugfs" -w -f "$scratch/pending/stage.commands" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "write $scratch/pending/inputs.json /usr/lib/phantowd/qemu-pending-client-inputs.json" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "write $scratch/pending/arm-inputs /usr/sbin/phantowd-pending-client-inputs" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R 'set_inode_field /usr/sbin/phantowd-pending-client-inputs mode 0100555' "$scratch/rootfs.ext2" >/dev/null 2>&1
fi
# Format only this newly-created regular tmpfs file, never a block-device path.
truncate -s 16M "$scratch/acl.ext4"
[ -f "$scratch/acl.ext4" ] && [ ! -L "$scratch/acl.ext4" ] || exit 1
"$(dirname "$debugfs")/mke2fs" -q -F -t ext4 \
    -U c395f03e-60ea-4ea1-9f47-08fb0aabfa72 \
    -E lazy_itable_init=0,lazy_journal_init=0 "$scratch/acl.ext4"
for pair in "launcher phantowd-samba-root-launcher" \
    "charset phantowd-samba-charset-probe" \
    "bundle phantowd-runtime-bundle-probe" \
    "owner phantowd-samba-owner-probe" \
    "$source_dir/support/tests/samba-root-init.sh phantowd-samba-root-init"; do
    input=${pair%% *}
    output=${pair#* }
    case "$input" in /*) ;; *) input="$scratch/$input" ;; esac
    sh "$source_dir/support/tests/stage-samba-root-file.sh" "$debugfs" \
        "$scratch/rootfs.ext2" "$input" "/usr/sbin/$output" \
        "$scratch/stage-roundtrip" 0100755
done
sh "$source_dir/support/tests/stage-samba-root-file.sh" "$debugfs" \
    "$scratch/rootfs.ext2" "$scratch/manifest" \
    /usr/lib/phantowd/qemu-samba-root.manifest "$scratch/stage-roundtrip" 0100644
# Default remains the complete qualification. Explicit local selection narrows
# only which fresh guest is run. Native uses360s; all other guests keep180s.
# Selection never changes assertions, authority or retries.
for campaign in $campaigns; do
    guest_timeout=$(python3 -B "$source_dir/support/tests/samba_root_fixture.py" guest-timeout "$campaign")
    timeout --signal=TERM --kill-after=5 "$guest_timeout" qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -object rng-random,id=samba-rng,filename=/dev/urandom \
    -device virtio-rng-pci,rng=samba-rng \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append "console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 phantowd_samba_ext4_fixture=1 phantowd_samba_campaign=$campaign init=/usr/sbin/phantowd-samba-root-init" \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    -drive "file=$scratch/acl.ext4,format=raw,if=scsi,snapshot=on" \
    >"$scratch/$campaign.log" 2>&1 &
child_pid=$!
status=0
wait "$child_pid" || status=$?
child_pid=
if [ "$diagnostics" = diagnostic ]; then
    # Escaped, bounded telemetry only. Emitted before verification even for a
    # timeout; never a success marker or substitute for original acceptance.
    if [ "$pending_profile" -eq 1 ]; then
        cat "$scratch/$campaign.log" # Fixed fixture contains no operator secrets.
    else
        python3 -B "$source_dir/support/tests/samba_root_fixture.py" diagnostic-log \
            "$scratch/$campaign.log" "$campaign" "$status"
    fi
fi
verified=0
if [ "$status" -eq 0 ]; then
    if [ "$selection" = pending-handle ]; then
        python3 -B "$source_dir/support/tests/pending_client_healthy_log.py" "$scratch/$campaign.log" handle && verified=1
    elif [ "$selection" = pending-peer-exit ]; then
        python3 -B "$source_dir/support/tests/pending_client_healthy_log.py" "$scratch/$campaign.log" peer-exit && verified=1
    elif [ "$selection" = pending ]; then
        python3 -B "$source_dir/support/tests/pending_client_healthy_log.py" "$scratch/$campaign.log" && verified=1
    else
        python3 -B "$source_dir/support/tests/samba_root_fixture.py" verify-campaign "$scratch/$campaign.log" "$campaign" && verified=1
    fi
fi
if [ "$verified" -ne 1 ]; then
    # Diagnostics cannot set verified or replace the original failure status.
    # Summed reported worker stages are neither wall time nor scope coverage.
    if ! python3 -B "$source_dir/support/tests/samba_root_fixture.py" timing-summary \
        "$scratch/$campaign.log" "$campaign" >&2; then
        echo 'PHANTOWD_SAMBA_TIMING_SUMMARY_UNAVAILABLE qualifying=false scope=qemu-only' >&2
    fi
    if [ -n "$failure_log" ]; then
        mkdir -p "$(dirname "$failure_log")"
        cp "$scratch/$campaign.log" "$failure_log"
    fi
    printf 'Samba campaign failed: %s\n' "$campaign" >&2
    tail -n 120 "$scratch/$campaign.log" >&2
    exit 1
fi
done
if [ "$selection" = persistent ] && [ -n "$failure_log" ]; then
    cp "$scratch/persistent.log" "$failure_log"
fi
if [ "$selection" = all ] && ! python3 -B "$source_dir/support/tests/samba_root_fixture.py" verify \
    "$scratch/service.log" --native-log "$scratch/native.log" \
    --candidate-log "$scratch/candidate.log" \
    --lifecycle-log "$scratch/lifecycle.log" --fault-log "$scratch/fault.log" \
    --data-log "$scratch/data.log" --exit-log "$scratch/exit.log" \
    --held-log "$scratch/held.log" --file-log "$scratch/file.log" \
    --file-source-log "$scratch/file-source.log"; then
    if [ -n "$failure_log" ]; then
        mkdir -p "$(dirname "$failure_log")"
        cat "$scratch/service.log" "$scratch/native.log" \
            "$scratch/candidate.log" "$scratch/lifecycle.log" \
            "$scratch/fault.log" "$scratch/data.log" "$scratch/exit.log" \
            "$scratch/held.log" "$scratch/file.log" "$scratch/file-source.log" >"$failure_log"
    fi
    tail -n 60 "$scratch/service.log" >&2
    tail -n 60 "$scratch/native.log" >&2
    tail -n 60 "$scratch/candidate.log" >&2
    tail -n 60 "$scratch/lifecycle.log" >&2
    tail -n 60 "$scratch/fault.log" >&2
    tail -n 60 "$scratch/data.log" >&2
    tail -n 60 "$scratch/exit.log" >&2
    tail -n 60 "$scratch/held.log" >&2
    tail -n 60 "$scratch/file.log" >&2
    tail -n 60 "$scratch/file-source.log" >&2
    exit 1
fi
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
if [ "$selection" = all ]; then
    echo PHANTOWD_SAMBA_ROOT_BASE_UNCHANGED
else
    printf 'PHANTOWD_SAMBA_FOCUSED_COMPLETE campaign=%s base_unchanged=true complete_image=false scope=qemu-only\n' "$selection"
fi
