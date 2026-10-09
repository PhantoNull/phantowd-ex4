# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$wrapper = Join-Path $PSScriptRoot '../test-samba-root.ps1'
$previousExitCode = $global:LASTEXITCODE
if (Get-Variable phantowdSambaWrapperTestState -Scope Global -ErrorAction SilentlyContinue) {
    throw 'Samba wrapper test context already active.'
}
$global:phantowdSambaWrapperTestState = @{
    Calls = [System.Collections.Generic.List[object]]::new()
    Files = [System.Collections.Generic.List[string]]::new()
    Failure = ''
    Base = ''
}
# Mock artifact admission and Docker only: no daemon, image, volume or guest.
function Resolve-Path {
    param([string]$Path, [string]$LiteralPath)
    if ($LiteralPath) {
        $global:phantowdSambaWrapperTestState.Base = $LiteralPath
        return [pscustomobject]@{ Path = $LiteralPath }
    }
    Microsoft.PowerShell.Management\Resolve-Path -Path $Path
}
function Get-Item {
    param([string]$LiteralPath)
    $state = $global:phantowdSambaWrapperTestState
    $state.Files.Add($LiteralPath)
    [pscustomobject]@{
        PSIsContainer = ($state.Failure -eq 'directory')
        Attributes = if ($state.Failure -eq 'symlink') { [IO.FileAttributes]::ReparsePoint } else { [IO.FileAttributes]::Normal }
    }
}
function docker {
    $state = $global:phantowdSambaWrapperTestState
    # PowerShell functions parse unquoted comma tokens as arrays; native Docker
    # receives comma-separated tokens. Preserve that native-command boundary.
    $state.Calls.Add(@($args | ForEach-Object { if ($_ -is [Array]) { $_ -join ',' } else { $_ } }))
    $operation = ($args | Select-Object -First 2) -join ' '
    $global:LASTEXITCODE = [int]($state.Failure -ne '' -and $operation.StartsWith($state.Failure))
}
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
try {
    $repoRoot = (Microsoft.PowerShell.Management\Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $state = $global:phantowdSambaWrapperTestState
    foreach ($campaign in @('all', 'service', 'native', 'candidate', 'lifecycle', 'fault', 'data', 'exit', 'held')) {
        foreach ($baseArgument in @('', (Join-Path $repoRoot 'mock-explicit-base'))) {
            $state.Calls.Clear()
            $state.Files.Clear()
            if ($baseArgument) { & $wrapper -BaseArtifactDir $baseArgument -Campaign $campaign } else { & $wrapper -Campaign $campaign }
            $expectedBase = if ($baseArgument) { $baseArgument } else { Join-Path $repoRoot 'artifacts/qemu-armv5' }
            Assert-True ($state.Base -eq $expectedBase) 'Default/explicit artifact base changed.'
            Assert-True ($state.Files.Count -eq 4) 'All four required artifact inputs must be checked.'
            Assert-True ($state.Calls.Count -eq 3) 'Exactly two inspections and one run required.'
            $run = $state.Calls[2]
            foreach ($argument in @('run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
                '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--cpus', '2', '--memory', '2g', '--pids-limit', '256', '--entrypoint', '/bin/sh',
                '/tmp:rw,exec,nosuid,nodev,size=512m', '/var/tmp:rw,noexec,nosuid,nodev,size=128m')) {
                Assert-True ($argument -in $run) "Missing fixed isolation: $argument"
            }
            Assert-True (@($run | Where-Object { $_ -match '^type=volume,.*readonly,volume-nocopy$' }).Count -eq 1) 'Workspace must remain read-only.'
            Assert-True (@($run | Where-Object { $_ -match '^type=bind,.*readonly$' }).Count -eq 2) 'Source/base must remain read-only.'
            Assert-True (-not ($run | Where-Object { $_ -match '^--(privileged|device|publish)$' })) 'Privilege/device/port exposure.'
            Assert-True ($run[-1] -match "printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d \| sh") 'Encoded command missing.'
            $linux = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1]))
            Assert-True ($linux.Contains("/src '' '$campaign'")) 'Exact selected campaign not passed.'
            Assert-True (-not $linux.Contains("'diagnostic'")) 'Diagnostics must remain opt-in.'
        }
    }
    $state.Calls.Clear()
    & $wrapper -Campaign data -DiagnosticLogs
    Assert-True ($state.Calls.Count -eq 3) 'Diagnostics must not add a Docker operation.'
    $diagnosticRun = $state.Calls[2]
    Assert-True ($diagnosticRun[-1] -match "printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d \| sh") 'Diagnostic command missing.'
    $diagnosticLinux = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1]))
    Assert-True ($diagnosticLinux.Contains("/src '' 'data' 'diagnostic'")) 'Diagnostic mode not passed to the same guest driver.'
    foreach ($failure in @('image inspect', 'volume inspect', 'run', 'directory', 'symlink')) {
        $state.Calls.Clear()
        $state.Failure = $failure
        $refused = $false
        try { & $wrapper } catch { $refused = $true }
        Assert-True $refused 'Failed run or invalid dependency accepted.'
        Assert-True (@($state.Calls | Where-Object { $_[0] -eq 'run' }).Count -eq [int]($failure -eq 'run')) 'Refusal ran or retried a guest.'
        Assert-True (-not ($state.Calls | Where-Object { $_[0] -in @('build', 'pull', 'system') })) 'Forbidden resource operation.'
    }
    $state.Calls.Clear()
    $refused = $false
    try { & $wrapper -Campaign invalid } catch { $refused = $true }
    Assert-True ($refused -and $state.Calls.Count -eq 0) 'Invalid campaign reached Docker.'
    # Windows PowerShell -File evaluates defaults differently from script-to-
    # script invocation. A PATH-scoped native mock refuses the FIRST inspection;
    # no Docker daemon is contacted. This regression needs existing base inputs.
    if ($env:OS -eq 'Windows_NT' -and (Test-Path (Join-Path $repoRoot 'artifacts/qemu-armv5/SHA256SUMS'))) {
        $probeRoot = Join-Path ([IO.Path]::GetTempPath()) ('phantowd-samba-wrapper-' + [guid]::NewGuid().ToString('N'))
        $probeDocker = Join-Path $probeRoot 'docker.cmd'
        $oldPath = $env:PATH
        New-Item -ItemType Directory -Path $probeRoot | Out-Null
        try {
            [IO.File]::WriteAllLines($probeDocker, @('@echo off', 'exit /b 73'))
            $env:PATH = $probeRoot + ';' + $oldPath
            $oldErrorAction = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = (& powershell -NoProfile -File $wrapper -Campaign lifecycle 2>&1 | Out-String)
            } finally { $ErrorActionPreference = $oldErrorAction }
            Assert-True ($LASTEXITCODE -ne 0 -and $output.Contains('Existing pinned image required')) 'Windows -File default failed before the native mock boundary.'
        } finally {
            $env:PATH = $oldPath
            Remove-Item -LiteralPath $probeDocker -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $probeRoot -Force
        }
    }
    'PHANTOWD_SAMBA_WRAPPER_TESTS_READY defaults=true campaigns=8 refusals=6 scope=mock-command-boundary-only'
} finally {
    Remove-Variable phantowdSambaWrapperTestState -Scope Global
    $global:LASTEXITCODE = $previousExitCode
}
