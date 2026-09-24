[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$moduleRoot = Join-Path $repoRoot 'src/phantowd-api'
$dashboardTest = Join-Path $repoRoot 'support/test-dashboard-ui.mjs'
$reportRoot = Join-Path $repoRoot 'artifacts/api-host-tests'
$coverageFile = Join-Path $reportRoot 'coverage.out'
$environmentNames = @('GOPROXY', 'GOTOOLCHAIN', 'GOFLAGS')
$originalEnvironment = @{}
foreach ($environmentName in $environmentNames) {
    $originalEnvironment[$environmentName] = [Environment]::GetEnvironmentVariable($environmentName, 'Process')
}

New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null
node $dashboardTest
if ($LASTEXITCODE -ne 0) { throw 'Dashboard interaction tests failed.' }
Push-Location $moduleRoot
try {
    $env:GOPROXY = 'off'
    $env:GOTOOLCHAIN = 'local'
    $env:GOFLAGS = '-mod=vendor'
    go version
    if ($LASTEXITCODE -ne 0) { throw 'A local Go 1.26+ compiler is required.' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go static checks failed.' }
    go test -count=1 "-coverprofile=$coverageFile" ./...
    if ($LASTEXITCODE -ne 0) { throw 'Diagnostics API tests failed.' }
    go test -tags=qemu -run '^TestQEMUDashboardAssetsMatchSelfTest$' -count=1 .
    if ($LASTEXITCODE -ne 0) { throw 'QEMU dashboard contract test failed.' }
} finally {
    Pop-Location
    foreach ($environmentName in $environmentNames) {
        [Environment]::SetEnvironmentVariable($environmentName, $originalEnvironment[$environmentName], 'Process')
    }
}
