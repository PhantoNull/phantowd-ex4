[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$imageName = 'phantowd/buildroot:2025.02.18'
$workspaceVolume = 'phantowd-ex4-buildroot-2025-02-18'
$dockerfile = Join-Path $repoRoot 'support/docker/Dockerfile'

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

$bindMount = "type=bind,source=$repoRoot,target=/external"
$volumeMount = "type=volume,source=$workspaceVolume,target=/workspace"

docker run --rm `
    --mount $bindMount `
    --mount $volumeMount `
    $imageName `
    /external/support/container/build-qemu.sh

if ($LASTEXITCODE -ne 0) {
    throw 'The Buildroot build or QEMU smoke test failed.'
}
