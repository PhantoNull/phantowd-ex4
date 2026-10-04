# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$wrapper = Join-Path $PSScriptRoot '../test-qemu-lio.ps1'
$previousExitCode = $global:LASTEXITCODE
if (Get-Variable phantowdLIOWrapperTestState -Scope Global -ErrorAction SilentlyContinue) {
    throw 'LIO wrapper test context already active.'
}
$global:phantowdLIOWrapperTestState = @{
    Calls = [System.Collections.Generic.List[object]]::new()
    Failure = ''
}
# Mock command/file admission only. No Docker resource or fixture is created.
function docker {
    $global:phantowdLIOWrapperTestState.Calls.Add(@($args))
    $operation = ($args | Select-Object -First 2) -join ' '
    $failure = $global:phantowdLIOWrapperTestState.Failure
    $global:LASTEXITCODE = [int]($failure -ne '' -and $operation.StartsWith($failure))
}
function Test-Path {
    param([string]$LiteralPath, [string]$PathType)
    if (!$LiteralPath.EndsWith('libiscsi-1.20.0.tar.gz')) { throw 'Unexpected mock path.' }
    $global:phantowdLIOWrapperTestState.Failure -ne 'archive-missing'
}
function Get-FileHash {
    param([string]$LiteralPath, [string]$Algorithm)
    if (!$LiteralPath.EndsWith('libiscsi-1.20.0.tar.gz') -or $Algorithm -ne 'SHA256') { throw 'Unexpected mock hash.' }
    $hash = '6321d802103f2a363d3afd9a5ae772de0b4052c84fe6a301ecb576b34e853caa'
    if ($global:phantowdLIOWrapperTestState.Failure -eq 'archive-hash') { $hash = 'wrong' }
    [pscustomobject]@{ Hash = $hash }
}
function Get-Item {
    param([string]$LiteralPath)
    if ($LiteralPath -notmatch 'lio-research') { throw 'Unexpected mock candidate.' }
    [pscustomobject]@{ PSIsContainer = $false; Attributes = if ($global:phantowdLIOWrapperTestState.Failure -eq 'candidate-link') { [IO.FileAttributes]::ReparsePoint } else { [IO.FileAttributes]::Normal } }
}
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (!$Condition) { throw $Message }
}
try {
    $state = $global:phantowdLIOWrapperTestState
    foreach ($compile in @($false, $true)) {
        $state.Calls.Clear()
        & $wrapper -CompileKernel:$compile
        Assert-True ($state.Calls.Count -eq 3) 'Exactly two inspections and one run required.'
        $run = $state.Calls[2]
        foreach ($argument in @('run', '--rm', '--pull', 'never', '--entrypoint', '/bin/sh',
            '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt',
            'no-new-privileges', '--user', '1000:1000', '--cpus', '4', '--pids-limit', '512')) {
            Assert-True ($argument -in $run) "Missing isolation: $argument"
        }
        $memory = if ($compile) { '8g' } else { '2g' }
        $scratch = if ($compile) { '4g' } else { '512m' }
        Assert-True ($memory -in $run) 'Wrong memory budget.'
        Assert-True ("/tmp:rw,exec,nosuid,nodev,size=$scratch,mode=1777" -in $run) 'Wrong scratch budget.'
        Assert-True (@($run | Where-Object { $_ -match '^type=volume,.*readonly,volume-nocopy$' }).Count -eq 1) 'Read-only existing workspace required.'
        Assert-True (@($run | Where-Object { $_ -match '^type=bind,.*readonly$' }).Count -eq 1) 'Read-only checkout required.'
        Assert-True (-not ($run | Where-Object { $_ -match '^--(privileged|device|publish)$' })) 'Host privilege/device/port exposure.'
        Assert-True ($run[-1] -match "printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d") 'Encoded fixed Linux command missing.'
        $linux = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1]))
        foreach ($text in @('sha256sum -c INPUTS.sha256', 'sha256sum -c SHA256SUMS',
            'qemu_lio_inputs.py', 'qemu-lio-fixture.sh', 'build-qemu-iscsi-client.sh',
            'test-qemu-lio-snapshot-temp.sh', 'test-qemu-lio-result.py')) {
            Assert-True ($linux.Contains($text)) "Missing actual call boundary: $text"
        }
        Assert-True ($run[-1].Contains('timeout --signal=TERM --kill-after=10 900 sh')) 'Overall timeout missing.'
    }
    foreach ($failure in @('image inspect', 'volume inspect', 'archive-missing', 'archive-hash', 'candidate-link', 'run')) {
        $state.Calls.Clear()
        $state.Failure = $failure
        $refused = $false
        try { & $wrapper } catch { $refused = $true }
        Assert-True $refused 'Invalid dependency/failed run accepted.'
        Assert-True (@($state.Calls | Where-Object { $_[0] -eq 'run' }).Count -eq [int]($failure -eq 'run')) 'Refusal started/retried the guest.'
        Assert-True (-not ($state.Calls | Where-Object { $_[0] -in @('build', 'pull', 'system') })) 'Forbidden resource operation.'
    }
    'PHANTOWD_LIO_WRAPPER_TESTS_READY cached=true cold=true refusals=6 scope=mock-command-boundary-only'
} finally {
    Remove-Variable phantowdLIOWrapperTestState -Scope Global
    $global:LASTEXITCODE = $previousExitCode
}
