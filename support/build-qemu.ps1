[CmdletBinding()]
param(
    [string]$DockerDataVhdxPath = (Join-Path $env:LOCALAPPDATA 'Docker\wsl\disk\docker_data.vhdx'),
    [ValidateRange(1, 1024)]
    [int]$MinimumFreeGiB = 40,
    [switch]$CachedOnly
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dashboardTest = Join-Path $repoRoot 'support/test-dashboard-ui.mjs'
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
$ccacheVolume = "phantowd-ex4-buildroot-ccache-$($buildrootVersion.Replace('.', '-'))"
$dockerfile = Join-Path $repoRoot 'support/docker/Dockerfile'

node $dashboardTest
if ($LASTEXITCODE -ne 0) {
    throw 'Dashboard interaction tests failed.'
}

if (-not (Test-Path -LiteralPath $DockerDataVhdxPath -PathType Leaf)) {
    throw ('Cannot verify Docker data-disk headroom: VHDX not found at {0}. If Docker Desktop stores it elsewhere, pass -DockerDataVhdxPath with its exact path.' -f $DockerDataVhdxPath)
}

$dockerDrive = (Get-Item -LiteralPath $DockerDataVhdxPath).PSDrive.Name
$freeBytes = (Get-PSDrive -Name $dockerDrive).Free
$minimumFreeBytes = [int64]$MinimumFreeGiB * 1GB
if ($freeBytes -lt $minimumFreeBytes) {
    throw ('Docker data drive {0}: has only {1:N1} GiB free; this full Buildroot/QEMU build requires at least {2} GiB of host headroom before starting.' -f $dockerDrive, ($freeBytes / 1GB), $MinimumFreeGiB)
}

docker info | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop is not available.'
}

$bindMount = "type=bind,source=$repoRoot,target=/external"
$volumeMount = "type=volume,source=$workspaceVolume,target=/workspace,volume-nocopy"
$ccacheMount = "type=volume,source=$ccacheVolume,target=/ccache,volume-nocopy"

if ($CachedOnly) {
    # Fail closed: do not let Docker implicitly create or populate a cache.
    docker image inspect $imageName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Cached-only image is missing: $imageName. Seed it with the ordinary wrapper; this mode never builds or pulls an image."
    }
    foreach ($requiredVolume in @($workspaceVolume, $ccacheVolume)) {
        docker volume inspect $requiredVolume | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Cached-only volume is missing: $requiredVolume. Seed it with the ordinary wrapper; this mode never creates volumes."
        }
    }

    $cachedScript = @'
set -eu
. /external/versions.env
config_hash="$(sha256sum /external/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)"
output_dir="/workspace/output/${BUILDROOT_VERSION}-${config_hash}"
for marker in /workspace/.phantowd-owner-builder-v1 /ccache/.phantowd-owner-builder-v1 /external/artifacts/.phantowd-owner-builder-v1; do
    [ -f "$marker" ] || { printf 'Cached-only workspace is not initialized: %s\n' "$marker" >&2; exit 2; }
done
[ -x "$output_dir/host/bin/go" ] && [ -d "$output_dir/target" ] || {
    printf 'Cached-only output for the current configuration is missing: %s\n' "$output_dir" >&2
    exit 2
}
[ -w /workspace ] && [ -w /ccache ] && [ -w /external/artifacts ] || {
    printf 'Cached-only inputs require existing builder write permissions; no ownership repair is performed.\n' >&2
    exit 2
}
exec /bin/sh /external/support/container/build-qemu.sh
'@
    $cachedScript = $cachedScript.Replace("`r`n", "`n")
    $encodedScript = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($cachedScript))
    $cachedCommand = "set -eu; printf '%s' '$encodedScript' | base64 -d > /tmp/phantowd-cached-build.sh; exec /bin/sh /tmp/phantowd-cached-build.sh"

    # The cold API race suite was reproduced failing at 256 MiB /tmp and
    # passing at 2048 MiB. Caches/scratch are separate bounded RAM filesystems.
    docker run --rm --pull never `
        --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges `
        --cpus 4 --memory 6g --pids-limit 512 `
        --tmpfs '/tmp:rw,exec,nosuid,nodev,size=2048m,uid=1000,gid=1000' `
        --tmpfs '/phantowd-qemu-fixture-tmp:rw,exec,nosuid,nodev,size=512m,uid=1000,gid=1000' `
        --tmpfs '/workspace/api-host-cache:rw,exec,nosuid,nodev,size=768m,uid=1000,gid=1000' `
        --tmpfs '/workspace/lab-tools-host-cache:rw,exec,nosuid,nodev,size=768m,uid=1000,gid=1000' `
        --mount $bindMount --mount $volumeMount --mount $ccacheMount `
        --env PHANTOWD_CCACHE_DIR=/ccache --env GOMAXPROCS=4 `
        --env GIT_CONFIG_COUNT=1 --env GIT_CONFIG_KEY_0=safe.directory --env GIT_CONFIG_VALUE_0=/external `
        --entrypoint /usr/bin/timeout $imageName `
        --signal=TERM --kill-after=30 1800 /bin/sh -ec $cachedCommand

    if ($LASTEXITCODE -ne 0) {
        throw 'The cached-only full Buildroot/QEMU validation failed; no retry or cache repair was attempted.'
    }
    return
}

docker build --file $dockerfile --tag $imageName $repoRoot
if ($LASTEXITCODE -ne 0) {
    throw 'Could not build the pinned Buildroot build environment.'
}

$existingVolume = docker volume ls --quiet --filter "name=^$workspaceVolume$"
if ($LASTEXITCODE -ne 0) {
    throw 'Could not query Docker volumes.'
}

if ($existingVolume -ne $workspaceVolume) {
    docker volume create $workspaceVolume | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not create the persistent Buildroot workspace volume.'
    }
}

$existingCcacheVolume = docker volume ls --quiet --filter "name=^$ccacheVolume$"
if ($LASTEXITCODE -ne 0) {
    throw 'Could not query Docker compiler-cache volumes.'
}

if ($existingCcacheVolume -ne $ccacheVolume) {
    docker volume create $ccacheVolume | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not create the persistent Buildroot compiler-cache volume.'
    }
}

docker run --rm `
    --tmpfs /phantowd-qemu-fixture-tmp:rw,exec,nosuid,nodev,size=512m `
    --mount $bindMount `
    --mount $volumeMount `
    --mount $ccacheMount `
    --env PHANTOWD_CCACHE_DIR=/ccache `
    $imageName `
    /external/support/container/build-qemu.sh

if ($LASTEXITCODE -ne 0) {
    throw 'The Buildroot build or QEMU smoke test failed.'
}
