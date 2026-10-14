# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$image = 'phantowd/buildroot:2025.02.18'
$workspace = 'phantowd-ex4-buildroot-2025-02-18'
$pins = @(Get-Content (Join-Path $repoRoot 'versions.env') | Where-Object { $_ -match '^BUILDROOT_VERSION=' })
if ($pins.Count -ne 1 -or $pins[0] -cne 'BUILDROOT_VERSION=2025.02.18') { throw 'Exact pinned Buildroot SDK required.' }
docker image inspect $image *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing pinned image required; no pull/build.' }
docker volume inspect $workspace *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing workspace required; no new volume.' }
$linux = @'
set -eu
. /src/versions.env
config_hash="$(sha256sum /src/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)"
output="/workspace/output/$BUILDROOT_VERSION-$config_hash"
shellcheck /src/support/tests/test-samba-server-capture-client.sh
scratch=$(mktemp -d /tmp/phantowd-capture-client.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
bash /src/support/tests/build-samba-pending-handle-observer.sh "$output" /src "$scratch"
bash /src/support/tests/test-samba-server-capture-client.sh "$output" /src "$scratch"
# Existing close-only variant stays independently qualified and cannot read.
bash /src/support/tests/test-samba-pending-handle-client.sh "$output" /src "$scratch"
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($linux.Replace("`r`n", "`n")))
docker run --rm --pull never --network none --read-only `
    --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges `
    --cpus 2 --memory 256m --pids-limit 64 `
    --tmpfs '/tmp:rw,exec,nosuid,nodev,size=64m,uid=1000,gid=1000' `
    --entrypoint /usr/bin/timeout `
    --mount "type=bind,source=$repoRoot,target=/src,readonly" `
    --mount "type=volume,source=$workspace,target=/workspace,readonly,volume-nocopy" `
    $image --signal=TERM --kill-after=5 120 /bin/sh -ec "printf '%s' '$encoded' | base64 -d | sh"
if ($LASTEXITCODE -ne 0) { throw 'Capture client prerequisite failed; no guest, actual SMB or NAS was used.' }
