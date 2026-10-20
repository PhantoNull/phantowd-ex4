# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param(
    [string]$BaseArtifactDirectory = (Join-Path $PSScriptRoot '../artifacts/qemu-armv5'),
    [string]$DockerDataVhdxPath = (Join-Path $env:LOCALAPPDATA 'Docker/wsl/disk/docker_data.vhdx'),
    [ValidateSet('code','source')][string]$FixtureMode = 'code'
)
$ErrorActionPreference = 'Stop'
$FixtureMode = $FixtureMode.ToLowerInvariant()
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$baseRoot = (Resolve-Path -LiteralPath $BaseArtifactDirectory).Path
if (-not (Test-Path -LiteralPath $DockerDataVhdxPath -PathType Leaf)) { throw 'Provide the existing Docker data VHDX path.' }
$drive = (Get-Item -LiteralPath $DockerDataVhdxPath).PSDrive.Name
if ((Get-PSDrive -Name $drive).Free -lt 8GB) { throw 'NFS code fixture requires 8 GiB free; full build still requires 40 GiB.' }
$pins = @(Get-Content (Join-Path $repoRoot 'versions.env') | Where-Object { $_ -match '^BUILDROOT_VERSION=' })
if ($pins.Count -ne 1) { throw 'Exactly one Buildroot pin is required.' }
$version = ($pins[0] -split '=',2)[1].Trim().Trim('"')
if ($version -notmatch '^\d{4}\.\d{2}(?:\.\d{1,2})?$') { throw 'Invalid Buildroot pin.' }
$image = "phantowd/buildroot:$version"
$volume = 'phantowd-ex4-buildroot-' + $version.Replace('.','-')
docker image inspect $image *> $null
if ($LASTEXITCODE -ne 0) { throw 'Pinned image unavailable; no image is built/pulled.' }
docker volume inspect $volume *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing workspace unavailable; no volume is created.' }
$linux = @'
set -eu
. /src/versions.env
config_hash="$(sha256sum /src/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)"
output="/workspace/output/${BUILDROOT_VERSION}-${config_hash}"
exec timeout --signal=TERM --kill-after=10s 360s sh /src/support/tests/test-qemu-nfs-code.sh /base "$output/target" "$output/host/bin/go" "$(command -v debugfs)" /src '' __MODE__
'@
$linux = $linux.Replace('__MODE__', $FixtureMode)
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($linux.Replace("`r`n","`n")))
$command = "printf '%s' '$encoded' | base64 -d > /tmp/nfs-code-fixture.sh; exec /bin/sh /tmp/nfs-code-fixture.sh"
$preferenceBefore = $ErrorActionPreference
$fixtureExit = $null
try {
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = $null
    docker run --rm --pull never --cpus 2 --memory 2g --memory-swap 2g --pids-limit 256 `
        --network none --read-only --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges:true `
        --tmpfs '/tmp:rw,exec,nosuid,nodev,size=1024m,uid=1000,gid=1000' `
        --mount "type=bind,source=$repoRoot,target=/src,readonly" `
        --mount "type=bind,source=$baseRoot,target=/base,readonly" `
        --mount "type=volume,source=$volume,target=/workspace,readonly,volume-nocopy" `
        --entrypoint /bin/sh $image -ec $command
    $fixtureExit = $LASTEXITCODE
} finally { $ErrorActionPreference = $preferenceBefore }
if ($null -eq $fixtureExit -or $fixtureExit -ne 0) { throw 'NFS code fixture failed/timed out; no retry made.' }
