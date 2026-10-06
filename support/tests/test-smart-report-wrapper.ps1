# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$wrapper = Join-Path $PSScriptRoot '../test-smart-report.ps1'
$previousExitCode = $global:LASTEXITCODE
if (Get-Variable phantowdSmartWrapperTestState -Scope Global -ErrorAction SilentlyContinue) {
    throw 'SMART wrapper test context already active.'
}
$global:phantowdSmartWrapperTestState = @{
    Calls = [System.Collections.Generic.List[object]]::new()
    Files = [System.Collections.Generic.List[string]]::new()
    Failure = ''
    Base = ''
}
# Mock only filesystem admission and the Docker command boundary. No files,
# daemon, image, volume, toolchain or guest are created by this test.
function Resolve-Path {
    param([string]$Path, [string]$LiteralPath)
    if ($LiteralPath) {
        $global:phantowdSmartWrapperTestState.Base = $LiteralPath
        return [pscustomobject]@{ Path = $LiteralPath }
    }
    Microsoft.PowerShell.Management\Resolve-Path -Path $Path
}
function Get-Item {
    param([string]$LiteralPath)
    $global:phantowdSmartWrapperTestState.Files.Add($LiteralPath)
    [pscustomobject]@{ PSIsContainer = $false; Attributes = [IO.FileAttributes]::Normal }
}
function docker {
    $global:phantowdSmartWrapperTestState.Calls.Add(@($args))
    $operation = ($args | Select-Object -First 2) -join ' '
    $global:LASTEXITCODE = [int]($operation.StartsWith($global:phantowdSmartWrapperTestState.Failure) -and
        $global:phantowdSmartWrapperTestState.Failure -ne '')
}
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
try {
    $repoRoot = (Microsoft.PowerShell.Management\Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $state = $global:phantowdSmartWrapperTestState
    foreach ($baseArgument in @('', (Join-Path $repoRoot 'mock-explicit-base'))) {
        $state.Calls.Clear()
        $state.Files.Clear()
        if ($baseArgument) { & $wrapper -BaseArtifactDir $baseArgument } else { & $wrapper }
        $expectedBase = if ($baseArgument) { $baseArgument } else { Join-Path $repoRoot 'artifacts/qemu-armv5' }
        Assert-True ($state.Base -eq $expectedBase) 'Default/explicit base admission changed.'
        Assert-True ($state.Files.Count -eq 4) 'Must check all four required base inputs.'
        Assert-True ($state.Calls.Count -eq 3) 'Expected image inspect, volume inspect and one run.'
        $run = $state.Calls[2]
        foreach ($argument in @('run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
            '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '--cpus', '2', '--memory', '2g', '--pids-limit', '128', '--entrypoint', '/bin/sh',
            '/tmp:rw,exec,nosuid,nodev,size=2048m,uid=1000,gid=1000',
            '/var/tmp:rw,noexec,nosuid,nodev,size=128m,uid=1000,gid=1000')) {
            Assert-True ($argument -in $run) "Missing bounded argument: $argument"
        }
        Assert-True (@($run | Where-Object { $_ -match '^type=volume,.*readonly,volume-nocopy$' }).Count -eq 1) 'Workspace must remain read-only.'
        Assert-True (@($run | Where-Object { $_ -match '^type=bind,.*readonly$' }).Count -eq 2) 'Source/base must remain read-only.'
        Assert-True (-not ($run | Where-Object { $_ -match '^--(privileged|device|publish)$' })) 'Device/privilege/port exposure.'
    }
    foreach ($failure in @('image inspect', 'volume inspect', 'run')) {
        $state.Calls.Clear()
        $state.Failure = $failure
        $refused = $false
        try { & $wrapper } catch { $refused = $true }
        Assert-True $refused 'Missing dependency or failed run was accepted.'
        $runCount = @($state.Calls | Where-Object { $_[0] -eq 'run' }).Count
        Assert-True ($runCount -eq [int]($failure -eq 'run')) 'Refusal ran or retried the guest.'
        Assert-True (-not ($state.Calls | Where-Object { $_[0] -in @('build', 'pull', 'system') })) 'Forbidden resource operation.'
    }
    'PHANTOWD_SMART_WRAPPER_TESTS_READY defaults=true profile=true refusals=3 scope=mock-command-boundary-only'
} finally {
    Remove-Variable phantowdSmartWrapperTestState -Scope Global
    $global:LASTEXITCODE = $previousExitCode
}
