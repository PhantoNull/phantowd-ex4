[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

$ErrorActionPreference = 'Stop'
$projectVolumes = @(
    'phantowd-ex4-buildroot-2025-02-18',
    'phantowd-ex4-buildroot-ccache-2025-02-18'
)

docker info | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop is not available.'
}

foreach ($volume in $projectVolumes) {
    $foundVolumes = @(docker volume ls --quiet --filter "name=^$volume$")
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect Docker volume $volume."
    }
    if ($foundVolumes -notcontains $volume) {
        Write-Host "Not present: $volume"
        continue
    }

    $containerReferences = @(docker ps --all --quiet --filter "volume=$volume")
    if ($LASTEXITCODE -ne 0) {
        throw "Could not check container references for $volume."
    }
    if ($containerReferences.Count -gt 0) {
        Write-Warning "Keeping $volume because container references exist: $($containerReferences -join ', ')"
        continue
    }

    if ($PSCmdlet.ShouldProcess($volume, 'Remove this PhantoWD QEMU build cache volume')) {
        docker volume rm $volume | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not remove Docker volume $volume."
        }
        Write-Host "Removed: $volume"
    }
}

Write-Host 'Only the two exact PhantoWD QEMU volume names above are in scope. Docker images, other volumes, repository artifacts, and the Docker VHDX are not modified.'
