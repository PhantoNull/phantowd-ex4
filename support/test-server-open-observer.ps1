# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param([string]$BaseArtifactDir, [switch]$Wire)
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
if ($pins.Count -ne 1) { throw 'One Buildroot version pin is required.' }
$buildrootVersion = ($pins[0] -split '=', 2)[1].Trim().Trim('"')
if ($buildrootVersion -notmatch '^\d{4}\.\d{2}(?:\.\d{1,2})?$') { throw 'Invalid Buildroot pin.' }
$imageName = "phantowd/buildroot:$buildrootVersion"
$workspaceVolume = "phantowd-ex4-buildroot-$($buildrootVersion.Replace('.', '-'))"
docker image inspect $imageName *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing pinned image required; no image is pulled or built.' }
docker volume inspect $workspaceVolume *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing workspace required; no volume is created.' }
$linuxScript = @'
set -eu
. /src/versions.env
config_hash="$(sha256sum /src/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)"
output="/workspace/output/$BUILDROOT_VERSION-$config_hash"
shellcheck /src/support/tests/build-samba-server-open-observer.sh /src/support/tests/test-server-open-observer-qemu.sh /src/support/tests/server-open-observer-init.sh /src/support/tests/server-open-wire-init.sh /src/support/tests/test-server-open-observer-log.sh
bash /src/support/tests/test-server-open-observer-log.sh /src
bash /src/support/tests/test-server-open-observer-qemu.sh /base "$output" /src __WIRE_MODE__
'@
$linuxScript = $linuxScript.Replace('__WIRE_MODE__', $(if ($Wire) { 'wire' } else { 'source' }))
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($linuxScript.Replace("`r`n", "`n")))
$memoryLimit = if ($Wire) { '2g' } else { '512m' }
$tmpLimit = if ($Wire) { '1536m' } else { '256m' }
docker run --rm --pull never --network none --read-only `
    --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges `
    --cpus 2 --memory $memoryLimit --pids-limit 128 `
    --tmpfs "/tmp:rw,exec,nosuid,nodev,size=$tmpLimit" `
    --tmpfs /var/tmp:rw,noexec,nosuid,nodev,size=128m `
    --entrypoint /bin/sh `
    --mount "type=bind,source=$repoRoot,target=/src,readonly" `
    --mount "type=bind,source=$baseRoot,target=/base,readonly" `
    --mount "type=volume,source=$workspaceVolume,target=/workspace,readonly,volume-nocopy" `
    $imageName -ec "printf '%s' '$encoded' | base64 -d | sh"
if ($LASTEXITCODE -ne 0) { throw 'Server observer prerequisite failed; no NAS or physical storage was used.' }
