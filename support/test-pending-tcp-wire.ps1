# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param([string]$BaseArtifactDir = '')
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $BaseArtifactDir) { $BaseArtifactDir = Join-Path $repoRoot 'artifacts/qemu-armv5' }
$baseRoot = (Resolve-Path -LiteralPath $BaseArtifactDir).Path
foreach ($name in @('rootfs.ext2', 'zImage', 'versatile-pb.dtb', 'SHA256SUMS')) {
    $file = Get-Item -LiteralPath (Join-Path $baseRoot $name)
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Input must be a regular file: $name"
    }
}
$pins = @(Get-Content (Join-Path $repoRoot 'versions.env') | Where-Object { $_ -match '^BUILDROOT_VERSION=' })
if ($pins.Count -ne 1) { throw 'One Buildroot pin is required.' }
$version = ($pins[0] -split '=', 2)[1].Trim().Trim('"')
if ($version -notmatch '^\d{4}\.\d{2}(?:\.\d{1,2})?$') { throw 'Invalid Buildroot pin.' }
$imageName = "phantowd/buildroot:$version"
$workspaceVolume = "phantowd-ex4-buildroot-$($version.Replace('.', '-'))"
docker image inspect $imageName *> $null
if ($LASTEXITCODE -ne 0) { throw 'Pinned image missing; this check never pulls or builds an image.' }
docker volume inspect $workspaceVolume *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing workspace missing; this check never creates a volume.' }
$linuxScript = @'
set -eu
. /src/versions.env
config_hash=$(sha256sum /src/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)
output=/workspace/output/$BUILDROOT_VERSION-$config_hash
go_binary=$output/host/bin/go
debugfs=$output/host/sbin/debugfs
scratch=$(mktemp -d /tmp/phantowd-pending-tcp.XXXXXX)
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    rm -rf "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
export TMPDIR=$scratch GOCACHE=$scratch/go-cache GOPATH=$scratch/go-path
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false -p=2' GOMAXPROCS=2
shellcheck /src/support/tests/pending-tcp-arm-init.sh
(cd /base && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum /base/rootfs.ext2 | awk '{print $1}')
"$go_binary" version | grep -F "go$GO_VERSION "
(cd /src/src/phantowd-api && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    timeout --signal=TERM --kill-after=5 180 "$go_binary" test -tags=qemu -c -trimpath \
    -ldflags '-s -w' -o "$scratch/tcp-test" ./internal/processowner)
rm -rf "$scratch/go-cache" "$scratch/go-path"
cp /base/rootfs.ext2 "$scratch/rootfs.ext2"
for pair in "$scratch/tcp-test phantowd-pending-tcp-test" \
    '/src/support/tests/pending-tcp-arm-init.sh phantowd-pending-tcp-init'; do
    input=${pair%% *}
    name=${pair#* }
    "$debugfs" -w -R "write $input /usr/sbin/$name" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -R "dump /usr/sbin/$name $scratch/readback" "$scratch/rootfs.ext2" >/dev/null 2>&1
    cmp "$input" "$scratch/readback"
    rm -f "$scratch/readback"
    "$debugfs" -w -R "set_inode_field /usr/sbin/$name mode 0100755" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
sha256sum "$scratch/tcp-test" /src/support/tests/pending-tcp-arm-init.sh
timeout --signal=TERM --kill-after=5 90 qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -kernel /base/zImage -dtb /base/versatile-pb.dtb \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 phantowd_pending_tcp_wire=1 init=/usr/sbin/phantowd-pending-tcp-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" >"$scratch/guest.log" 2>&1 &
child_pid=$!
status=0
wait "$child_pid" || status=$?
child_pid=
tr -d '\r' <"$scratch/guest.log" >"$scratch/normalized.log"
if [ "$status" -ne 0 ] || \
    [ "$(grep -Fxc 'PHANTOWD_PENDING_TCP_ARM_DONE cases=9 repetitions=3 binding=false scope=qemu-only' "$scratch/normalized.log")" -ne 1 ] || \
    grep -Eq '^--- FAIL:|^FAIL|PHANTOWD_PENDING_TCP_ARM_FAILED' "$scratch/normalized.log"; then
    tail -n 100 "$scratch/normalized.log" >&2
    exit 1
fi
for name in ActualKernelLoopbackIdentityAndClosure RefusesIncompleteIdentity DecodesKernelIPv4Identity \
    DumpPublishesOnlyCompleteCopiedRows DumpRefusesForeignInterruptedAndPartialData \
    DumpCompletionAndEarlierRowsFailClosed DumpBoundsRowsAndBytes ExtensionBoundsAndNonAuthority ExactRecordLimit; do
    [ "$(grep -c "^--- PASS: TestPendingTCPWire$name " "$scratch/normalized.log")" -eq 3 ]
done
grep -E '^--- PASS:|^PASS$|^PHANTOWD_PENDING_TCP_ARM_DONE' "$scratch/normalized.log"
[ "$(sha256sum /base/rootfs.ext2 | awk '{print $1}')" = "$base_hash" ]
printf 'PHANTOWD_PENDING_TCP_ARM_BASE_UNCHANGED sha256=%s\n' "$base_hash"
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($linuxScript.Replace("`r`n", "`n")))
docker run --rm --pull never --network none --read-only --user 1000:1000 `
    --cap-drop ALL --security-opt no-new-privileges --cpus 2 --memory 2g --pids-limit 256 `
    --tmpfs /tmp:rw,exec,nosuid,nodev,size=1536m --entrypoint /bin/sh `
    --mount "type=bind,source=$repoRoot,target=/src,readonly" `
    --mount "type=bind,source=$baseRoot,target=/base,readonly" `
    --mount "type=volume,source=$workspaceVolume,target=/workspace,readonly,volume-nocopy" `
    $imageName -ec "printf '%s' '$encoded' | base64 -d | sh"
if ($LASTEXITCODE -ne 0) { throw 'Focused TCP wire ARMv5 qualification failed; no physical devices were exposed.' }
