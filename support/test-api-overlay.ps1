# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param(
    [string]$BaseArtifactDirectory = (Join-Path $PSScriptRoot '../artifacts/qemu-armv5'),
    [string]$DockerDataVhdxPath = (Join-Path $env:LOCALAPPDATA 'Docker/wsl/disk/docker_data.vhdx'),
    [switch]$ReuseBaseVolumeProbe
)
$ErrorActionPreference = 'Stop'
if (-not $ReuseBaseVolumeProbe) {
    throw 'This API-only launcher requires -ReuseBaseVolumeProbe after reviewing that the trusted base helper sources are unchanged. Use the shell overlay builder to rebuild a changed helper.'
}
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not (Test-Path -LiteralPath $DockerDataVhdxPath -PathType Leaf)) {
    throw 'Cannot verify Docker data-drive headroom: provide its actual VHDX path.'
}
$dataDrive = (Get-Item -LiteralPath $DockerDataVhdxPath).PSDrive.Name
# This is not a full Buildroot build: all persistent inputs stay read-only,
# scratch is capped tmpfs, and the container cannot use cgroup swap. Reserve
# extra host headroom nevertheless; this does not bound unrelated/WSL writes.
if ((Get-PSDrive -Name $dataDrive).Free -lt 8GB) {
    throw 'API overlay requires at least 8 GiB free on the Docker data drive.'
}
$baseRoot = (Resolve-Path -LiteralPath $BaseArtifactDirectory).Path
foreach ($name in @('rootfs.ext2','zImage','versatile-pb.dtb','SHA256SUMS')) {
    $file = Join-Path $baseRoot $name
    if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or
        ((Get-Item -LiteralPath $file).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The trusted base requires regular non-reparse image/manifest files.'
    }
}
$pins = @(Get-Content (Join-Path $repoRoot 'versions.env') | Where-Object { $_ -match '^BUILDROOT_VERSION=' })
if ($pins.Count -ne 1) { throw 'Exactly one Buildroot pin required.' }
$version = ($pins[0] -split '=',2)[1].Trim().Trim('"')
if ($version -notmatch '^\d{4}\.\d{2}(?:\.\d{1,2})?$') { throw 'Invalid Buildroot pin.' }
$imageName = "phantowd/buildroot:$version"
$workspace = 'phantowd-ex4-buildroot-' + $version.Replace('.','-')
docker info *> $null
if ($LASTEXITCODE -ne 0) { throw 'Docker is unavailable.' }
docker image inspect $imageName *> $null
if ($LASTEXITCODE -ne 0) { throw 'Pinned image missing; no image is built or pulled.' }
docker volume inspect $workspace *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing workspace missing; no volume is created.' }
$linuxScript = @'
set -eu
. /src/versions.env
config_hash="$(sha256sum /src/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)"
output="/workspace/output/${BUILDROOT_VERSION}-${config_hash}"
buildroot="/workspace/buildroot-${BUILDROOT_VERSION}"
test -x "$output/host/bin/go"
test -x "$output/host/bin/arm-buildroot-linux-gnueabi-gcc"
test -r /workspace/dl/util-linux/util-linux-2.40.4.tar.xz
test -d "$buildroot/package/util-linux"
export PATH="$output/host/bin:$output/host/sbin:$PATH"
export PHANTOWD_QEMU_OVERLAY_REUSE_BASE_VOLUME_PROBE=1
export PHANTOWD_QEMU_OVERLAY_SMOKE_ONLY=1
sh /src/support/container/test-qemu-api-overlay.sh /base "$output/host/bin/go" /src \
    /workspace/dl/util-linux/util-linux-2.40.4.tar.xz \
    "$output/host/bin/arm-buildroot-linux-gnueabi-gcc" "$buildroot/package/util-linux"
'@
$linuxScript = $linuxScript.Replace("`r`n","`n")
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($linuxScript))
$command = "printf '%s' '$encoded' | base64 -d > /tmp/phantowd-api-overlay.sh; exec timeout --signal=TERM --kill-after=10s 360s /bin/sh /tmp/phantowd-api-overlay.sh"
# Windows PowerShell 5 can promote a native stderr diagnostic into a terminating
# ErrorRecord when this script is captured by a caller's 2>&1 pipeline. Do not
# abandon a still-running guest on debugfs's informational stderr. Stream both
# outputs, then decide from the actual exit code; restore the preference even
# if command invocation itself fails. No timeout, guest assertion or retry changes.
$previousNativePreference = $ErrorActionPreference
$overlayExitCode = $null
try {
    $ErrorActionPreference = 'Continue'
    # A missing native command must not inherit a successful preflight exit.
    $global:LASTEXITCODE = $null
    docker run --rm --pull never --cpus 2 --memory 2g --memory-swap 2g --pids-limit 256 `
    --network none --read-only --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges:true `
    --tmpfs '/tmp:rw,exec,nosuid,nodev,size=1024m,uid=1000,gid=1000' `
    --mount "type=bind,source=$repoRoot,target=/src,readonly" `
    --mount "type=bind,source=$baseRoot,target=/base,readonly" `
    --mount "type=volume,source=$workspace,target=/workspace,readonly,volume-nocopy" `
    --entrypoint /bin/sh $imageName -ec $command
    $overlayExitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previousNativePreference
}
if ($null -eq $overlayExitCode -or $overlayExitCode -ne 0) { throw 'API-only ARM overlay failed, timed out or was killed; no retry made.' }
