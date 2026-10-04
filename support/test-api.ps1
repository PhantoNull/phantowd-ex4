[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$moduleRoot = Join-Path $repoRoot 'src/phantowd-api'
$dashboardTest = Join-Path $repoRoot 'support/test-dashboard-ui.mjs'
$reportRoot = Join-Path $repoRoot 'artifacts/api-host-tests'
$coverageFile = Join-Path $reportRoot 'coverage.out'
$environmentNames = @('GOPROXY', 'GOTOOLCHAIN', 'GOFLAGS', 'GOOS', 'GOARCH', 'GOARM')
$armv5TestBinary = Join-Path ([System.IO.Path]::GetTempPath()) "phantowd-api-qemu-armv5-$([guid]::NewGuid().ToString('N')).test"
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
    go test -tags=qemu -run '^(TestQEMUDashboardAssetsMatchSelfTest|TestQEMUTLSLoopbackSmoke|TestQEMUShareConfig|TestQEMUShareStore|TestQEMUSMBPreview|TestQEMUNFSPolicy|TestQEMUNetworkPolicy|TestQEMUISCSIPolicy|TestQEMUNFSFixture|TestQEMUFileServicePreviewHTTP|TestQEMUSMBStatusJSONReturnsOnlyTargetGenerations|TestQEMUSMBStatusJSONRejectsUnavailableOrUnqualifiedSessions|TestQEMUSMBStatusJSONAcceptsEmptySessionInventory|TestQEMUAPIReadinessWaitsWithoutMutatingBeforeReady|TestQEMUStateProcReaderObservesAndRedactsOwnerCWD)$' -count=1 .
    if ($LASTEXITCODE -ne 0) { throw 'QEMU dashboard contract test failed.' }

    $env:GOOS = 'linux'
    $env:GOARCH = 'arm'
    $env:GOARM = '5'
    go test -tags=qemu -c -o $armv5TestBinary .
    if ($LASTEXITCODE -ne 0) { throw 'ARMv5 QEMU-tagged API tests did not cross-compile.' }
    Write-Host 'ARMv5 QEMU-tagged API tests cross-compile successfully (not executed).'
} finally {
    Pop-Location
    foreach ($environmentName in $environmentNames) {
        [Environment]::SetEnvironmentVariable($environmentName, $originalEnvironment[$environmentName], 'Process')
    }
    if (Test-Path -LiteralPath $armv5TestBinary) {
        Remove-Item -LiteralPath $armv5TestBinary -Force
    }
}
