# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param([string]$BaseArtifactDir, [switch]$WorkerExit, [switch]$UncertainRead, [switch]$CancelRead,
    [ValidateSet('module', 'configuration', 'channel', 'source', 'source-root')][string]$InputDrift)
$ErrorActionPreference = 'Stop'
if ($WorkerExit -and $InputDrift) { throw 'Choose exactly one fixed fault fixture.' }
if ($UncertainRead -and ($WorkerExit -or $InputDrift)) { throw 'Choose exactly one fixed fault fixture.' }
if ($CancelRead -and ($UncertainRead -or $WorkerExit -or $InputDrift)) { throw 'Choose exactly one fixed fault fixture.' }
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $BaseArtifactDir) { $BaseArtifactDir = Join-Path $repoRoot 'artifacts/qemu-armv5' }
$baseRoot = (Resolve-Path -LiteralPath $BaseArtifactDir).Path
foreach ($name in @('rootfs.ext2', 'zImage', 'versatile-pb.dtb', 'SHA256SUMS')) {
    $file = Get-Item -LiteralPath (Join-Path $baseRoot $name)
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Regular input required: $name" }
}
$image = 'phantowd/buildroot:2025.02.18'
$workspace = 'phantowd-ex4-buildroot-2025-02-18'
$pins = @(Get-Content (Join-Path $repoRoot 'versions.env') | Where-Object { $_ -match '^BUILDROOT_VERSION=' })
if ($pins.Count -ne 1 -or $pins[0] -cne 'BUILDROOT_VERSION=2025.02.18') { throw 'Exact pinned SDK required.' }
docker image inspect $image *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing image required; no pull/build.' }
docker volume inspect $workspace *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing workspace required; no new volume.' }
$linux = @'
set -eu
. /src/versions.env
config_hash="$(sha256sum /src/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)"
output="/workspace/output/$BUILDROOT_VERSION-$config_hash"
shellcheck /src/support/tests/test-server-capture-runtime-qemu.sh /src/support/tests/server-capture-runtime-init.sh /src/support/tests/test-server-capture-open-log.sh
bash /src/support/tests/test-server-capture-open-log.sh /src
shellcheck /src/support/tests/test-server-capture-worker-exit-log.sh
bash /src/support/tests/test-server-capture-worker-exit-log.sh /src
shellcheck /src/support/tests/test-server-capture-input-fault-log.sh
bash /src/support/tests/test-server-capture-input-fault-log.sh /src
shellcheck /src/support/tests/test-server-capture-uncertain-read-log.sh /src/support/tests/test-samba-server-capture-client.sh
bash /src/support/tests/test-server-capture-uncertain-read-log.sh /src
shellcheck /src/support/tests/test-server-capture-cancel-read-log.sh
bash /src/support/tests/test-server-capture-cancel-read-log.sh /src
bash /src/support/tests/test-server-capture-runtime-qemu.sh /base "$output" /src --client-open
'@
if ($WorkerExit) { $linux = $linux.Replace('--client-open', '--client-worker-exit') }
if ($InputDrift) { $linux = $linux.Replace('--client-open', "--client-$InputDrift-fault") }
if ($UncertainRead) { $linux = $linux.Replace('--client-open', '--client-withheld-read') }
if ($CancelRead) { $linux = $linux.Replace('--client-open', '--client-cancel-read') }
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($linux.Replace("`r`n", "`n")))
docker run --rm --pull never --network none --read-only `
    --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges `
    --cpus 4 --memory 2g --pids-limit 256 `
    --tmpfs '/tmp:rw,exec,nosuid,nodev,size=1024m,uid=1000,gid=1000' `
    --entrypoint /usr/bin/timeout `
    --mount "type=bind,source=$repoRoot,target=/src,readonly" `
    --mount "type=bind,source=$baseRoot,target=/base,readonly" `
    --mount "type=volume,source=$workspace,target=/workspace,readonly,volume-nocopy" `
    $image --signal=TERM --kill-after=5 180 /bin/sh -ec "printf '%s' '$encoded' | base64 -d | sh"
if ($LASTEXITCODE -ne 0) { throw 'Capture OPEN tracer failed; no NAS or physical disk was used.' }
