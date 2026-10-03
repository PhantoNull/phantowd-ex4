# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param(
    [string]$BaseArtifactDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/qemu-armv5')
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$baseRoot = (Resolve-Path -LiteralPath $BaseArtifactDir).Path
$pins = @(Get-Content (Join-Path $repoRoot 'versions.env') | Where-Object { $_ -match '^BUILDROOT_VERSION=' })
if ($pins.Count -ne 1) { throw 'One Buildroot version pin is required.' }
$buildrootVersion = ($pins[0] -split '=', 2)[1].Trim().Trim('"')
if ($buildrootVersion -notmatch '^\d{4}\.\d{2}(?:\.\d{1,2})?$') { throw 'Invalid Buildroot pin.' }
$imageName = "phantowd/buildroot:$buildrootVersion"
$workspaceVolume = "phantowd-ex4-buildroot-$($buildrootVersion.Replace('.', '-'))"
foreach ($name in @('rootfs.ext2', 'zImage', 'versatile-pb.dtb', 'SHA256SUMS')) {
    $file = Get-Item -LiteralPath (Join-Path $baseRoot $name)
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Input must be a regular file: $name"
    }
}
docker image inspect $imageName *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing pinned image required; no image is pulled or built.' }
docker volume inspect $workspaceVolume *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing workspace required; no volume is created.' }
$linuxScript = @'
set -eu
. /src/versions.env
config_hash="$(sha256sum /src/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)"
output="/workspace/output/$BUILDROOT_VERSION-$config_hash"
python3 -B /src/support/tests/test-samba-root-fixture.py
python3 -B /src/support/tests/test-runtime-loader-fixture.py
python3 -B -m flake8 /src/support/tests/samba_root_fixture.py /src/support/tests/test-samba-root-fixture.py /src/support/tests/runtime_loader_fixture.py
shellcheck /src/support/tests/samba-root-init.sh /src/support/tests/test-qemu-samba-root.sh
exec sh /src/support/tests/test-qemu-samba-root.sh /base "$output/target" \
    "$output/host/bin/go" "$output/host/sbin/debugfs" \
    "$output/host/bin/arm-buildroot-linux-gnueabi-gcc" /src
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($linuxScript.Replace("`r`n", "`n")))
docker run --rm --pull never --network none --read-only `
    --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges `
    --cpus 2 --memory 2g --pids-limit 256 `
    --tmpfs /tmp:rw,exec,nosuid,nodev,size=512m `
    --tmpfs /var/tmp:rw,noexec,nosuid,nodev,size=128m `
    --entrypoint /bin/sh `
    --mount "type=bind,source=$repoRoot,target=/src,readonly" `
    --mount "type=bind,source=$baseRoot,target=/base,readonly" `
    --mount "type=volume,source=$workspaceVolume,target=/workspace,readonly,volume-nocopy" `
    $imageName -ec "printf '%s' '$encoded' | base64 -d | sh"
if ($LASTEXITCODE -ne 0) { throw 'Disposable Samba-root fixture failed; no NAS or physical disk was used.' }
