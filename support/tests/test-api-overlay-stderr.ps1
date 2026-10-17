# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$wrapper = Join-Path $PSScriptRoot '../test-api-overlay.ps1'
$previousExitCode = $global:LASTEXITCODE
if (Get-Variable phantowdOverlayWrapperTest -Scope Global -ErrorAction SilentlyContinue) { throw 'Overlay test context already active.' }
$global:phantowdOverlayWrapperTest = @{
    Calls = [System.Collections.Generic.List[object]]::new()
    Exit = 0
    Failure = ''
    CommandMissing = $false
}
# Additional stderr controls; the original admission/limit suite stays separate.
# Mock resource admission and Docker only. The run boundary emits actual native
# stderr from a short local PowerShell child: no Docker, guest or files created.
function Test-Path { param($LiteralPath, $PathType) $true }
function Resolve-Path {
    param($Path, $LiteralPath)
    if ($LiteralPath) { [pscustomobject]@{Path = 'C:\synthetic-overlay-base'} }
    else { Microsoft.PowerShell.Management\Resolve-Path -Path $Path }
}
function Get-Item {
    param($LiteralPath)
    [pscustomobject]@{Attributes = [IO.FileAttributes]::Normal; PSDrive = [pscustomobject]@{Name = 'C'}}
}
function Get-PSDrive { param($Name) [pscustomobject]@{Free = 20GB} }
function docker {
    $state = $global:phantowdOverlayWrapperTest
    $state.Calls.Add(@($args))
    $operation = ($args | Select-Object -First 2) -join ' '
    if ($args[0] -eq 'run') {
        if ($state.CommandMissing) { Write-Error 'synthetic command disappeared'; return }
        $child = '[Console]::Error.WriteLine("synthetic native diagnostic"); [Console]::Out.WriteLine("synthetic terminal output"); exit ' + $state.Exit
        $encodedChild = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
        $childName = if ($PSVersionTable.PSEdition -eq 'Core') { if ($env:OS -eq 'Windows_NT') { 'pwsh.exe' } else { 'pwsh' } } else { 'powershell.exe' }
        & (Join-Path $PSHOME $childName) -NoProfile -NonInteractive -EncodedCommand $encodedChild
        # A function has its own scope; propagate the actual native exit code
        # just as the external docker.exe command does for its script caller.
        $global:LASTEXITCODE = $LASTEXITCODE
    } else {
        $global:LASTEXITCODE = [int]($state.Failure -ne '' -and $operation.StartsWith($state.Failure))
    }
}
try {
    $state = $global:phantowdOverlayWrapperTest
    $rows = @(& $wrapper -ReuseBaseVolumeProbe 2>&1 | ForEach-Object { $_.ToString() })
    if (-not ($rows -match 'synthetic native diagnostic') -or -not ($rows -match 'synthetic terminal output')) {
        throw 'Successful native diagnostics must not discard terminal output.'
    }
    if ($ErrorActionPreference -ne 'Stop') { throw 'Caller error preference changed.' }
    $run = @($state.Calls | Where-Object { $_[0] -eq 'run' })
    if ($run.Count -ne 1) { throw 'Expected one run, without retry.' }
    foreach ($option in @('--rm', '--read-only', '--pull', 'never', '--network', 'none', '--cap-drop', 'ALL', '--pids-limit', '256')) {
        if ($option -notin $run[0]) { throw 'Original bounded container option missing.' }
    }
    if ($run[0][-1] -notmatch 'exec timeout --signal=TERM --kill-after=10s 360s ') { throw 'Original timeout changed.' }
    if (@($run[0] | Where-Object { $_ -match '^type=(bind|volume),.*readonly' }).Count -ne 3) { throw 'Original read-only mounts changed.' }
    foreach ($code in @(1,124,137)) {
        $state.Calls.Clear()
        $state.Exit = $code
        $refused = $false
        try { & $wrapper -ReuseBaseVolumeProbe 2>&1 | ForEach-Object { $_.ToString() } | Out-Null } catch { $refused = $true }
        if (-not $refused -or @($state.Calls | Where-Object { $_[0] -eq 'run' }).Count -ne 1) {
            throw 'Failure, timeout or OOM must refuse without retry.'
        }
        if ($ErrorActionPreference -ne 'Stop') { throw 'Failed run changed caller preference.' }
    }
    foreach ($failure in @('info', 'image inspect', 'volume inspect')) {
        $state.Calls.Clear()
        $state.Failure = $failure
        $refused = $false
        try { & $wrapper -ReuseBaseVolumeProbe | Out-Null } catch { $refused = $true }
        if (-not $refused -or @($state.Calls | Where-Object { $_[0] -eq 'run' }).Count -ne 0) {
            throw 'Missing dependency must refuse before run.'
        }
    }
    $state.Failure = ''
    $state.CommandMissing = $true
    $refused = $false
    try { & $wrapper -ReuseBaseVolumeProbe 2>&1 | ForEach-Object { $_.ToString() } | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'Missing native invocation must not inherit a previous zero exit.' }
    'PHANTOWD_API_OVERLAY_WRAPPER_READY native_stderr=true nonzero_refused=true original_limits=true scope=local-command-boundary-only'
} finally {
    Remove-Variable phantowdOverlayWrapperTest -Scope Global
    $global:LASTEXITCODE = $previousExitCode
}
