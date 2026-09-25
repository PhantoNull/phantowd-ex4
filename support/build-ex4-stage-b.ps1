[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$imageName = 'phantowd/buildroot:2025.02.18'
$workspaceVolume = 'phantowd-ex4-buildroot-2025-02-18'
$dockerfile = Join-Path $repoRoot 'support/docker/Dockerfile'

# Docker Desktop's default WSL data disk expands on the Windows host. A fresh
# Buildroot toolchain must not consume the last free bytes of that filesystem.
$dockerDisk = Join-Path $env:LOCALAPPDATA 'Docker\wsl\disk\docker_data.vhdx'
if (Test-Path -LiteralPath $dockerDisk) {
    $dockerDrive = (Get-Item -LiteralPath $dockerDisk).PSDrive.Name
    $freeBytes = (Get-PSDrive -Name $dockerDrive).Free
    if ($freeBytes -lt 40GB) {
        throw ('Docker data drive {0}: has only {1:N1} GiB free; Stage B requires at least 40 GiB before starting.' -f $dockerDrive, ($freeBytes / 1GB))
    }
}

docker info | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop is not available.' }

docker build --file $dockerfile --tag $imageName $repoRoot
if ($LASTEXITCODE -ne 0) { throw 'Could not build the pinned environment.' }

$existingVolume = docker volume ls --quiet --filter "name=^$workspaceVolume$"
if ($LASTEXITCODE -ne 0) { throw 'Could not query Docker volumes.' }
if ($existingVolume -ne $workspaceVolume) {
    docker volume create $workspaceVolume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create build workspace.' }
}

$bindMount = "type=bind,source=$repoRoot,target=/external"
$volumeMount = "type=volume,source=$workspaceVolume,target=/workspace"
docker run --rm `
    --mount $bindMount `
    --mount $volumeMount `
    $imageName `
    /bin/sh -c 'PHANTOWD_PREPARE_ONLY=1 /external/support/container/build-qemu.sh && /external/support/container/build-ex4-stage-b.sh'
if ($LASTEXITCODE -ne 0) { throw 'The verified-source preparation or Stage B compile failed.' }
