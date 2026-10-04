# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param([switch]$CompileKernel, [switch]$RequireMutual)

$ErrorActionPreference = 'Stop'
if ($RequireMutual -and !$CompileKernel) {
    throw 'Strict mutual research requires a fresh kernel compile; a default cached kernel cannot qualify it.'
}
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$versions = @(Get-Content (Join-Path $repoRoot 'versions.env') | Where-Object { $_ -match '^BUILDROOT_VERSION=' })
if ($versions.Count -ne 1) { throw 'Exactly one Buildroot pin required.' }
$version = ($versions[0] -split '=', 2)[1].Trim().Trim('"')
if ($version -notmatch '^\d{4}\.\d{2}\.\d{1,2}$') { throw 'Invalid Buildroot pin.' }
$image = "phantowd/buildroot:$version"
$volume = "phantowd-ex4-buildroot-$($version.Replace('.', '-'))"
docker image inspect $image *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing pinned builder image required; no pull/build is performed.' }
docker volume inspect $volume *> $null
if ($LASTEXITCODE -ne 0) { throw 'Existing Buildroot workspace required; no volume is created.' }
$archive = Join-Path $repoRoot 'artifacts/fixture-sources/libiscsi-1.20.0.tar.gz'
if (!(Test-Path -LiteralPath $archive -PathType Leaf) -or
    (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne
    '6321d802103f2a363d3afd9a5ae772de0b4052c84fe6a301ecb576b34e853caa') {
    throw 'Verified libiscsi 1.20.0 source archive required; this wrapper does not download.'
}
$scratch = '512m'
$memory = '2g'
$compile = '0'
$requiredMutual = if ($RequireMutual) { '1' } else { '0' }
if ($CompileKernel) { $scratch = '4g'; $memory = '8g'; $compile = '1' }
if (!$CompileKernel) {
    foreach ($name in @('zImage', 'versatile-pb.dtb', 'kernel.config', 'SHA256SUMS', 'INPUTS.sha256')) {
        $file = Get-Item -LiteralPath (Join-Path $repoRoot "artifacts/lio-research/$name")
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Regular local research kernel candidate required.'
        }
    }
}
$linuxScript = @'
set -eu
. /src/versions.env
config_hash=$(sha256sum /src/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)
workspace=/workspace/output/${BUILDROOT_VERSION}-${config_hash}
host=$workspace/host
[ -x "$host/bin/arm-buildroot-linux-gnueabi-gcc" ]
python3 -B /src/support/tests/test-qemu-lio-inputs.py
python3 -B /src/support/tests/test-qemu-lio-result.py
sh /src/support/tests/test-lio-lun-set.sh /src
shellcheck /src/support/container/build-qemu-lio-kernel.sh /src/support/container/build-qemu-iscsi-client.sh /src/support/qemu-lio-fixture.sh /src/support/fixtures/qemu-lio-init.sh /src/support/tests/test-qemu-lio-snapshot-temp.sh /src/support/tests/test-lio-lun-set.sh
sh /src/support/tests/test-qemu-lio-snapshot-temp.sh /src
if [ "$PHANTOWD_LIO_COMPILE" = 1 ]; then
    mkdir /tmp/kernel
    sh /src/support/container/build-qemu-lio-kernel.sh /src \
        /workspace/dl/linux/linux-${LINUX_VERSION}.tar.xz \
        "$workspace/build/linux-${LINUX_VERSION}/.config" "$host" /tmp/kernel
    kernel=/tmp/kernel/build/arch/arm/boot/zImage
    dtb=/tmp/kernel/build/arch/arm/boot/dts/arm/versatile-pb.dtb
else
    (cd /src/artifacts/lio-research && sha256sum -c SHA256SUMS && sha256sum -c INPUTS.sha256)
    python3 -B /src/support/container/qemu_lio_inputs.py /src/artifacts/lio-research/kernel.config
    kernel=/src/artifacts/lio-research/zImage
    dtb=/src/artifacts/lio-research/versatile-pb.dtb
fi
mkdir /tmp/client
sh /src/support/container/build-qemu-iscsi-client.sh /src \
    /src/artifacts/fixture-sources/libiscsi-1.20.0.tar.gz "$host" /tmp/client \
    > /tmp/client-build.log 2>&1 || { tail -30 /tmp/client-build.log; exit 1; }
tail -3 /tmp/client-build.log
status=0
sh /src/support/qemu-lio-fixture.sh /src/artifacts/qemu-armv5 "$kernel" "$dtb" \
    /tmp/client/phantowd-iscsi-fixture-client /src /tmp/lio-guest.log || status=$?
# Only fixed synthetic markers, never arbitrary kernel/auth diagnostics.
if [ -f /tmp/lio-guest.log ]; then grep '^PHANTOWD_LIO_' /tmp/lio-guest.log || true; fi
if [ "$PHANTOWD_LIO_COMPILE" = 0 ]; then
    (cd /src/artifacts/lio-research && sha256sum -c SHA256SUMS && sha256sum -c INPUTS.sha256)
fi
exit "$status"
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($linuxScript.Replace("`r`n", "`n")))
docker run --rm --pull never --entrypoint /bin/sh --network none --read-only --cap-drop ALL `
    --security-opt no-new-privileges --user 1000:1000 --cpus 4 --memory $memory --pids-limit 512 `
    --tmpfs "/tmp:rw,exec,nosuid,nodev,size=$scratch,mode=1777" `
    --mount "type=bind,source=$repoRoot,target=/src,readonly" `
    --mount "type=volume,source=$volume,target=/workspace,readonly,volume-nocopy" `
    --env "PHANTOWD_LIO_COMPILE=$compile" `
    --env "PHANTOWD_LIO_REQUIRE_MUTUAL=$requiredMutual" $image `
    -c "printf '%s' '$encoded' | base64 -d | timeout --signal=TERM --kill-after=10 900 sh"
if ($LASTEXITCODE -ne 0) { throw 'Disposable LIO qualification failed; no product/device authority.' }
