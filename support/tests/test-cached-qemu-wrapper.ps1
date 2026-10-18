# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$wrapper = Join-Path $PSScriptRoot '../build-qemu.ps1'
$script:calls = [System.Collections.Generic.List[object]]::new()
$previousExitCode = $global:LASTEXITCODE
if (Get-Variable -Name phantowdCachedWrapperTestState -Scope Global -ErrorAction SilentlyContinue) {
    throw 'A cached wrapper test context is already active.'
}
$global:phantowdCachedWrapperTestState = @{ Calls = $script:calls; NodeCalls = [System.Collections.Generic.List[object]]::new(); Failure = ''; Free = 100GB; NodeFailure = $false }
$script:fixturePath = Join-Path ([IO.Path]::GetTempPath()) ('phantowd-wrapper-' + [guid]::NewGuid().ToString('N') + '.vhdx')
New-Item -Path $script:fixturePath -ItemType File | Out-Null

# Shadow the command boundary only. No Docker daemon, image, volume or guest.
function docker {
    $global:phantowdCachedWrapperTestState.Calls.Add(@($args))
    $operation = ($args | Select-Object -First 3) -join ' '
    $global:LASTEXITCODE = 0
    if ($global:phantowdCachedWrapperTestState.Failure -and $operation.StartsWith($global:phantowdCachedWrapperTestState.Failure)) {
        $global:LASTEXITCODE = 1
    }
}
function node {
    $global:phantowdCachedWrapperTestState.NodeCalls.Add(@($args))
    $global:LASTEXITCODE = [int]($global:phantowdCachedWrapperTestState.NodeFailure -or
        ($args[0] -like '*run-cached-qemu.mjs' -and $global:phantowdCachedWrapperTestState.Failure -eq 'runner'))
}
function Get-PSDrive {
    param([string]$Name)
    [pscustomobject]@{ Name = $Name; Free = $global:phantowdCachedWrapperTestState.Free }
}
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Invoke-Fixture {
    param([string]$Failure = '', [bool]$ExpectFailure = $false, [bool]$Guard = $true)
    $script:calls.Clear()
    $global:phantowdCachedWrapperTestState.NodeCalls.Clear()
    $global:phantowdCachedWrapperTestState.Failure = $Failure
    $caught = $false
    try {
        & $wrapper -CachedOnly -HostLifecycleGuard:$Guard -DockerDataVhdxPath $script:fixturePath
    } catch {
        $caught = $true
        if (-not $ExpectFailure) { throw }
    }
    Assert-True ($caught -eq $ExpectFailure) 'Unexpected wrapper outcome.'
    foreach ($call in $script:calls) {
        Assert-True ($call[0] -notin @('build', 'pull', 'system')) 'Forbidden Docker operation.'
        Assert-True (-not ($call[0] -eq 'volume' -and $call[1] -ne 'inspect')) 'Volume mutation requested.'
    }
}

try {
    Invoke-Fixture
    Assert-True ($global:phantowdCachedWrapperTestState.NodeCalls.Count -eq 2) 'Cached run must delegate to a bounded host runner after dashboard checks.'
    Assert-True ($script:calls.Count -eq 0) 'Cached Docker calls must all pass through the bounded runner.'
    $run = $global:phantowdCachedWrapperTestState.NodeCalls[1]
    Assert-True ($run[0] -like '*run-cached-qemu.mjs') 'Wrong host runner.'
    Assert-True ($run.Count -eq 11) 'Unexpected runner argument count.'
    foreach ($argument in @('--repo', '--image', 'phantowd/buildroot:2025.02.18',
        '--workspace', 'phantowd-ex4-buildroot-2025-02-18', '--ccache',
        'phantowd-ex4-buildroot-ccache-2025-02-18', '--command')) {
        Assert-True ($argument -in $run) "Missing runner argument: $argument"
    }
    Assert-True ($run[-1] -match "printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d") 'Missing encoded fixed preflight.'
    $scriptText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1]))
    foreach ($expected in @('config_hash=', '/workspace/.phantowd-owner-builder-v1',
        '/ccache/.phantowd-owner-builder-v1', '/external/artifacts/.phantowd-owner-builder-v1',
        '[ -x "$output_dir/host/bin/go" ]', '[ -d "$output_dir/target" ]',
        '[ -w /workspace ] && [ -w /ccache ] && [ -w /external/artifacts ]',
        'export PHANTOWD_OUTER_GROUP_TIMEOUT=1',
        'exec /bin/sh /external/support/container/build-qemu.sh')) {
        Assert-True ($scriptText.Contains($expected)) "Missing preflight contract: $expected"
    }
    Invoke-Fixture -Failure 'runner' -ExpectFailure $true
    Assert-True ($global:phantowdCachedWrapperTestState.NodeCalls.Count -eq 2) 'Host runner must not retry.'
    Invoke-Fixture -Guard $false
    Assert-True ($script:calls.Count -eq 5) 'Default adoption must remain separate: info/image/two volumes/one legacy run.'
    Assert-True ($global:phantowdCachedWrapperTestState.NodeCalls.Count -eq 1) 'Experimental runner must remain opt-in.'
    $legacy = $script:calls[4]
    Assert-True ($legacy[-1] -ceq $run[-1]) 'Both modes must use the same fixed in-container preflight.'
    foreach ($argument in @('--rm', '--pull', 'never', '--user', '1000:1000', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--cpus', '4', '--memory', '6g', '--pids-limit', '512',
        '--entrypoint', '/usr/bin/timeout', '--signal=TERM', '--kill-after=30', '1800',
        'PHANTOWD_CCACHE_DIR=/ccache', 'GOMAXPROCS=4', 'GIT_CONFIG_COUNT=1',
        'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=/external',
        '/tmp:rw,exec,nosuid,nodev,size=2048m,uid=1000,gid=1000',
        '/phantowd-qemu-fixture-tmp:rw,exec,nosuid,nodev,size=512m,uid=1000,gid=1000',
        '/workspace/api-host-cache:rw,exec,nosuid,nodev,size=768m,uid=1000,gid=1000',
        '/workspace/lab-tools-host-cache:rw,exec,nosuid,nodev,size=768m,uid=1000,gid=1000')) {
        Assert-True ($argument -in $legacy) "Missing legacy profile argument: $argument"
    }
    foreach ($refusal in @('info', 'image inspect',
        'volume inspect phantowd-ex4-buildroot-2025-02-18',
        'volume inspect phantowd-ex4-buildroot-ccache-2025-02-18', 'run')) {
        Invoke-Fixture -Guard $false -Failure $refusal -ExpectFailure $true
        Assert-True (@($script:calls | Where-Object { $_[0] -eq 'run' }).Count -eq [int]($refusal -eq 'run')) 'Legacy refusal must not run or retry.'
    }
    $global:phantowdCachedWrapperTestState.NodeFailure = $true
    Invoke-Fixture -ExpectFailure $true
    Assert-True ($script:calls.Count -eq 0) 'Dashboard failure must precede Docker.'
    $global:phantowdCachedWrapperTestState.NodeFailure = $false
    $global:phantowdCachedWrapperTestState.Free = 39GB
    Invoke-Fixture -ExpectFailure $true
    Assert-True ($script:calls.Count -eq 0) 'Host headroom refusal must precede Docker.'
    'PHANTOWD_CACHED_WRAPPER_TESTS_READY delegation=true opt_in=true preflight=true refusals=8 scope=mock-command-boundary-only'
} finally {
    # Only this explicitly created regular temporary fixture, never a Docker VHDX.
    Remove-Item -LiteralPath $script:fixturePath
    Remove-Variable -Name phantowdCachedWrapperTestState -Scope Global
    $global:LASTEXITCODE = $previousExitCode
}
