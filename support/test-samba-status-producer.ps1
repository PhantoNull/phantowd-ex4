# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param([string]$BaseArtifactDir = '', [switch]$SourcePatchExperiment)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ((Get-PSDrive -Name ([IO.Path]::GetPathRoot($repoRoot).Substring(0, 1))).Free -lt 8GB) {
    throw 'At least 8 GiB headroom is required for this scoped test.'
}
if (-not $BaseArtifactDir) { $BaseArtifactDir = Join-Path $repoRoot 'artifacts/qemu-armv5' }
$baseRoot = (Resolve-Path -LiteralPath $BaseArtifactDir).Path
$pins = @(Get-Content (Join-Path $repoRoot 'versions.env') | Where-Object { $_ -match '^BUILDROOT_VERSION=' })
if ($pins.Count -ne 1) { throw 'One Buildroot pin required.' }
$version = ($pins[0] -split '=', 2)[1].Trim().Trim('"')
if ($version -notmatch '^\d{4}\.\d{2}(?:\.\d{1,2})?$') { throw 'Invalid Buildroot pin.' }
foreach ($name in @('rootfs.ext2', 'zImage', 'versatile-pb.dtb', 'SHA256SUMS')) {
    $inputFile = Get-Item -LiteralPath (Join-Path $baseRoot $name)
    if ($inputFile.PSIsContainer -or ($inputFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Regular base inputs required.'
    }
}
$imageName = "phantowd/buildroot:$version"
$workspaceVolume = "phantowd-ex4-buildroot-$($version.Replace('.', '-'))"
$experimentMounts = @()
$outerBudget = 180
if ($SourcePatchExperiment) {
    $configPath = Join-Path $repoRoot 'configs/phantowd_qemu_armv5_defconfig'
    $configHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $configPath).Hash.ToLowerInvariant().Substring(0, 16)
    $shadow = "/workspace/output/$version-$configHash/build/samba4-4.22.11"
    $experimentMounts = @('--mount', "type=volume,source=$workspaceVolume,target=/cache,readonly,volume-nocopy",
        '--tmpfs', "${shadow}:rw,exec,nosuid,nodev,size=768m,uid=1000,gid=1000")
    $outerBudget = 480
}
docker image inspect $imageName *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing image required; no build or pull.' }
docker volume inspect $workspaceVolume *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing workspace required; no new volume.' }
$linuxScript = @'
set -eu
. /src/versions.env
config_hash=$(sha256sum /src/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)
output=/workspace/output/$BUILDROOT_VERSION-$config_hash
python3 -B /src/support/tests/test-samba-status-producer-fixture.py
python3 -B -m flake8 /src/support/tests/samba_status_producer_fixture.py /src/support/tests/test-samba-status-producer-fixture.py
shellcheck /src/support/tests/samba-status-producer-init.sh /src/support/tests/test-qemu-samba-status-producer.sh
if [ "$PHANTOWD_STATUS_PATCH_EXPERIMENT" = 1 ]; then
    shadow=$output/build/samba4-4.22.11
    sh /src/support/tests/build-samba-status-producer-experiment.sh \
        "/cache/output/$BUILDROOT_VERSION-$config_hash/build/samba4-4.22.11" "$shadow" \
        /src/support/tests/fixtures/samba-status-source-errors.patch
    exec sh /src/support/tests/test-qemu-samba-status-producer.sh /base "$output/target" "$output/host/sbin/debugfs" /src "$shadow"
fi
exec sh /src/support/tests/test-qemu-samba-status-producer.sh /base "$output/target" "$output/host/sbin/debugfs" /src
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($linuxScript.Replace("`r`n", "`n")))
docker run --rm --pull never --network none --read-only `
    --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges `
    --cpus 2 --memory 2g --memory-swap 2g --pids-limit 128 `
    --tmpfs '/tmp:rw,exec,nosuid,nodev,size=512m,uid=1000,gid=1000' `
    --entrypoint /usr/bin/timeout `
    --env "PHANTOWD_STATUS_PATCH_EXPERIMENT=$([int][bool]$SourcePatchExperiment)" `
    --mount "type=bind,source=$repoRoot,target=/src,readonly" `
    --mount "type=bind,source=$baseRoot,target=/base,readonly" `
    --mount "type=volume,source=$workspaceVolume,target=/workspace,readonly,volume-nocopy" `
    @experimentMounts `
    $imageName --signal=TERM --kill-after=10 $outerBudget /bin/sh -ec "printf '%s' '$encoded' | base64 -d | sh"
if ($LASTEXITCODE -ne 0) { throw 'Stock Samba producer test failed; no NAS or physical disk used.' }
