# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param(
    [string]$SourceArchive = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/smart-replay/smartmontools-7.4.tar.gz')
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$archive = Get-Item -LiteralPath $SourceArchive
if ($archive.PSIsContainer -or ($archive.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Source archive must be a regular file.'
}
$expected = 'e9a61f641ff96ca95319edfb17948cd297d0cd3342736b2c49c99d4716fb993d'
if ((Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Source archive does not match the pinned smartmontools 7.4 hash.'
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
config_hash="$(sha256sum /src/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)"
output="/workspace/output/$BUILDROOT_VERSION-$config_hash"
shellcheck /src/support/tests/test-smart-replay.sh
exec sh /src/support/tests/test-smart-replay.sh /input/smartmontools-7.4.tar.gz "$output/host/bin/go" /src
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($linuxScript.Replace("`r`n", "`n")))
docker run --rm --pull never --network none --read-only --user 1000:1000 `
    --cap-drop ALL --security-opt no-new-privileges --cpus 2 --memory 1g --pids-limit 128 `
    --tmpfs /tmp:rw,exec,nosuid,nodev,size=768m `
    --entrypoint /bin/sh `
    --mount "type=bind,source=$repoRoot,target=/src,readonly" `
    --mount "type=bind,source=$($archive.FullName),target=/input/smartmontools-7.4.tar.gz,readonly" `
    --mount "type=volume,source=$workspaceVolume,target=/workspace,readonly,volume-nocopy" `
    $imageName -ec "printf '%s' '$encoded' | base64 -d | sh"
if ($LASTEXITCODE -ne 0) { throw 'Synthetic native SMART producer check failed; no physical device was exposed.' }
