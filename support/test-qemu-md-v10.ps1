[CmdletBinding()]
param(
    [string]$BaseArtifactDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/qemu-armv5')
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$versionLines = @(Get-Content (Join-Path $repoRoot 'versions.env') | Where-Object { $_ -match '^BUILDROOT_VERSION=' })
if ($versionLines.Count -ne 1) {
    throw 'versions.env must define exactly one BUILDROOT_VERSION.'
}
$buildrootVersion = ($versionLines[0] -split '=', 2)[1].Trim().Trim('"')
if ($buildrootVersion -notmatch '^\d{4}\.\d{2}(?:\.\d{1,2})?$') {
    throw "Unexpected Buildroot version format: $buildrootVersion"
}

$imageName = "phantowd/buildroot:$buildrootVersion"
$workspaceVolume = "phantowd-ex4-buildroot-$($buildrootVersion.Replace('.', '-'))"
$baseRoot = (Resolve-Path -LiteralPath $BaseArtifactDir).Path
foreach ($name in @('rootfs.ext2', 'zImage', 'versatile-pb.dtb', 'SHA256SUMS')) {
    $file = Get-Item -LiteralPath (Join-Path $baseRoot $name) -ErrorAction Stop
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "QEMU base input must be a regular file: $name"
    }
}

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop is unavailable.'
}
docker image inspect $imageName *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Required local image is missing: $imageName. This test never pulls or builds images."
}
docker volume inspect $workspaceVolume *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Required existing Buildroot workspace is missing: $workspaceVolume. This test never creates volumes."
}

$repoMount = "type=bind,source=$repoRoot,target=/src,readonly"
$baseMount = "type=bind,source=$baseRoot,target=/base,readonly"
$workspaceMount = "type=volume,source=$workspaceVolume,target=/workspace,readonly,volume-nocopy"
$linuxScript = @'
set -eu
. /src/versions.env
config_hash="$(sha256sum /src/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)"
buildroot_source="/workspace/buildroot-$BUILDROOT_VERSION"
output="/workspace/output/$BUILDROOT_VERSION-$config_hash"
go_binary="$output/host/bin/go"
target_cc="$output/host/bin/arm-buildroot-linux-gnueabi-gcc"
probe_archive="/workspace/dl/util-linux/util-linux-2.40.4.tar.xz"
patch_dir="$buildroot_source/package/util-linux"
for input in "$go_binary" "$target_cc" "$patch_dir"; do
    [ -e "$input" ] || {
        printf 'Required cached Buildroot input is missing: %s\n' "$input" >&2
        exit 2
    }
done

export GOPROXY=off GOTOOLCHAIN=local GOCACHE=/tmp/go-cache GOPATH=/tmp/go-path
export TMPDIR=/tmp
export PHANTOWD_QEMU_OVERLAY_MD_V10_ONLY=1
exec sh /src/support/container/test-qemu-api-overlay.sh \
    /base "$go_binary" /src "$probe_archive" "$target_cc" "$patch_dir"
'@
$linuxScript = $linuxScript.Replace("`r`n", "`n")
$encodedLinuxScript = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($linuxScript))
$linuxCommand = "set -eu; printf '%s' '$encodedLinuxScript' | base64 -d > /tmp/phantowd-test-qemu-md-v10.sh; exec /bin/sh /tmp/phantowd-test-qemu-md-v10.sh"

docker run --rm --pull never `
    --network none `
    --read-only `
    --tmpfs /tmp:rw,exec,nosuid,nodev,size=2048m `
    --entrypoint /bin/sh `
    --mount $repoMount `
    --mount $baseMount `
    --mount $workspaceMount `
    $imageName `
    -ec $linuxCommand

if ($LASTEXITCODE -ne 0) {
    throw 'MD v1.0 QEMU fixture failed. No NAS or physical disk was used; no image was pulled and no volume was created.'
}
