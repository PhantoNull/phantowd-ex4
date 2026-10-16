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
    [pscustomobject]@{ PSIsContainer = $false; Attributes = [IO.FileAttributes]::Normal; FullName = $LiteralPath }
}
function Get-FileHash {
    param([string]$LiteralPath, [string]$Algorithm)
    if ($Algorithm -ne 'SHA256' -or $LiteralPath -notmatch 'smartmontools-7\.5\.tar\.gz$') {
        throw 'Unexpected mocked archive hash request.'
    }
    [pscustomobject]@{ Hash = '690b83ca331378da9ea0d9d61008c4b22dde391387b9bbad7f29387f2595f76e' }
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
    # Regression for Windows PowerShell's empty PSScriptRoot during parameter
    # default evaluation. The actual ARM producer is NOT started here.
    $armWrapper = Join-Path $PSScriptRoot '../test-smart-replay-arm.ps1'
    $state.Failure = ''
    foreach ($baseArgument in @('', (Join-Path $repoRoot 'mock-explicit-base'))) {
        $state.Calls.Clear()
        $state.Files.Clear()
        if ($baseArgument) { & $armWrapper -BaseArtifactDir $baseArgument } else { & $armWrapper }
        $expectedBase = if ($baseArgument) { $baseArgument } else { Join-Path $repoRoot 'artifacts/qemu-armv5' }
        Assert-True ($state.Base -eq $expectedBase) 'ARM default/explicit base admission changed.'
        Assert-True ($state.Files.Count -eq 5) 'ARM must check archive and all four base inputs.'
        Assert-True ($state.Calls.Count -eq 3) 'ARM expected image/volume inspect and one run.'
        $run = $state.Calls[2]
        foreach ($argument in @('--rm', '--pull', 'never', '--network', 'none', '--read-only',
            '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--cpus', '2', '--memory', '1g', '--pids-limit', '128',
            '/tmp:rw,exec,nosuid,nodev,size=768m')) {
            Assert-True ($argument -in $run) "Missing bounded ARM argument: $argument"
        }
        Assert-True (@($run | Where-Object { $_ -match '^type=volume,.*readonly,volume-nocopy$' }).Count -eq 1) 'ARM workspace must remain read-only.'
        Assert-True (@($run | Where-Object { $_ -match '^type=bind,.*readonly$' }).Count -eq 3) 'ARM source/base/archive must remain read-only.'
        Assert-True (-not ($run | Where-Object { $_ -match '^--(privileged|device|publish)$' })) 'ARM device/privilege/port exposure.'
    }
    'PHANTOWD_SMART_ARM_WRAPPER_TESTS_READY defaults=true profile=true scope=mock-command-boundary-only'
} finally {
    Remove-Variable phantowdSmartWrapperTestState -Scope Global
    $global:LASTEXITCODE = $previousExitCode
}
