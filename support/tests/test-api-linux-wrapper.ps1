# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$wrapper = Join-Path $PSScriptRoot '../test-api-linux.ps1'
$previousExitCode = $global:LASTEXITCODE
if (Get-Variable phantowdLinuxAPIWrapperTestState -Scope Global -ErrorAction SilentlyContinue) {
    throw 'Linux API wrapper test context already active.'
}
$global:phantowdLinuxAPIWrapperTestState = @{
    Calls = [System.Collections.Generic.List[object]]::new()
    Failure = ''
    FailureCode = 1
}
# Replace only the external Docker command. Real pins and wrapper orchestration
# are read; no daemon, image, workspace, cache, container or files are created.
function docker {
    $state = $global:phantowdLinuxAPIWrapperTestState
    $state.Calls.Add(@($args))
    $operation = ($args | Select-Object -First 2) -join ' '
    $global:LASTEXITCODE = if ($state.Failure -ne '' -and $operation.StartsWith($state.Failure)) {
        $state.FailureCode
    } else { 0 }
}
function Assert-Option {
    param([object[]]$Arguments, [string]$Name, [string]$Value)
    $positions = @(for ($i = 0; $i -lt $Arguments.Count; $i++) {
        if ($Arguments[$i] -eq $Name) { $i }
    })
    if ($positions.Count -ne 1 -or $positions[0] + 1 -ge $Arguments.Count -or
        $Arguments[$positions[0] + 1] -ne $Value) {
        throw "Missing or incorrect bounded option: $Name $Value"
    }
}
try {
    $state = $global:phantowdLinuxAPIWrapperTestState
    & $wrapper
    $runs = @($state.Calls | Where-Object { $_[0] -eq 'run' })
    if ($runs.Count -ne 1) { throw 'Exactly one local test container is required.' }
    Assert-Option $runs[0] '--cpus' '4'
    Assert-Option $runs[0] '--memory' '2g'
    Assert-Option $runs[0] '--pids-limit' '256'
    Assert-Option $runs[0] '--pull' 'never'
    Assert-Option $runs[0] '--entrypoint' '/bin/sh'
    Assert-Option $runs[0] '--user' '1000:1000'
    Assert-Option $runs[0] '--cap-drop' 'ALL'
    Assert-Option $runs[0] '--security-opt' 'no-new-privileges:true'
    Assert-Option $runs[0] '--network' 'none'
    Assert-Option $runs[0] '--tmpfs' '/tmp:rw,exec,nosuid,nodev,size=1024m,uid=1000,gid=1000'
    $command = $runs[0][-1]
    if ($command -notmatch 'exec timeout --signal=TERM --kill-after=10s 180s /bin/sh /tmp/phantowd-test-api-linux.sh$') {
        throw 'Entire Linux test process tree needs one bounded timeout.'
    }
    if ('--rm' -notin $runs[0] -or '--read-only' -notin $runs[0]) {
        throw 'Container must auto-remove and keep its root filesystem read-only.'
    }
    $mounts = @($runs[0] | Where-Object { $_ -match '^type=(bind|volume),' })
    if ($mounts.Count -ne 2 -or @($mounts | Where-Object { $_ -match '^type=bind,.*target=/external,readonly$' }).Count -ne 1 -or
        @($mounts | Where-Object { $_ -match '^type=volume,.*target=/workspace,readonly,volume-nocopy$' }).Count -ne 1) {
        throw 'Only read-only source and existing no-copy workspace may be mounted.'
    }
    if ($runs[0] | Where-Object { $_ -match '^--(privileged|device|publish|volume)(=|$)' }) {
        throw 'Physical devices, ports, privilege or extra volumes are forbidden.'
    }
    if ($command -notmatch "printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d") {
        throw 'Missing bounded encoded Linux command.'
    }
    $linux = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1]))
    foreach ($check in @('"$go_binary" vet ./...', '"$go_binary" test -count=1 ./...',
        '"$go_binary" vet -tags=qemu ./...',
        '"$go_binary" test -tags=qemu -run ''^TestQEMUStateProcReaderObservesAndRedactsOwnerCWD$'' -count=1 .',
        '"$go_binary" test -tags=qemu -run ''^(TestQEMUNFSReboot|TestQEMURebootShutdown)'' -count=1 -v .')) {
        if ($check -notin ($linux -split "`n")) { throw 'A previous Go qualification command was removed or changed.' }
    }
    foreach ($failure in @('info', 'image inspect', 'volume inspect', 'run')) {
        foreach ($code in $(if ($failure -eq 'run') { @(1, 124, 137) } else { @(1) })) {
            $state.Calls.Clear()
            $state.Failure = $failure
            $state.FailureCode = $code
            $refused = $false
            try { & $wrapper } catch { $refused = $true }
            if (-not $refused) { throw 'Failed dependency/run/timeout/OOM must refuse.' }
            $runCount = @($state.Calls | Where-Object { $_[0] -eq 'run' }).Count
            if ($runCount -ne [int]($failure -eq 'run')) { throw 'Refusal started or retried a test container.' }
            if ($state.Calls | Where-Object { $_[0] -in @('build', 'pull', 'system', 'create', 'stop', 'rm') -or
                ($_[0] -in @('volume', 'image') -and $_[1] -ne 'inspect') }) {
                throw 'Wrapper must not mutate resources or perform cleanup outside its one --rm run.'
            }
        }
    }
    'PHANTOWD_LINUX_API_WRAPPER_TESTS_READY scope=mock-command-boundary-only bounded=true isolated=true refusals=6 original-checks=4'
} finally {
    Remove-Variable phantowdLinuxAPIWrapperTestState -Scope Global
    $global:LASTEXITCODE = $previousExitCode
}
