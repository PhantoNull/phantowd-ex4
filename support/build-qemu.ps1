[CmdletBinding()]
param(
    [string]$DockerDataVhdxPath = (Join-Path $env:LOCALAPPDATA 'Docker\wsl\disk\docker_data.vhdx'),
    [ValidateRange(1, 1024)]
    [int]$MinimumFreeGiB = 40
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dashboardTest = Join-Path $repoRoot 'support/test-dashboard-ui.mjs'
$imageName = 'phantowd/buildroot:2025.02.18'
$workspaceVolume = 'phantowd-ex4-buildroot-2025-02-18'
$ccacheVolume = 'phantowd-ex4-buildroot-ccache-2025-02-18'
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

$bindMount = "type=bind,source=$repoRoot,target=/external"
$volumeMount = "type=volume,source=$workspaceVolume,target=/workspace"
$ccacheMount = "type=volume,source=$ccacheVolume,target=/ccache"

docker run --rm `
    --mount $bindMount `
    --mount $volumeMount `
    --mount $ccacheMount `
    --env PHANTOWD_CCACHE_DIR=/ccache `
    $imageName `
    /external/support/container/build-qemu.sh

if ($LASTEXITCODE -ne 0) {
    throw 'The Buildroot build or QEMU smoke test failed.'
}
