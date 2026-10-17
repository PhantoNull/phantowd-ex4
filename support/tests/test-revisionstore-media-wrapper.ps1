# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if (Get-Variable phantowdMediaWrapperTest -Scope Global -ErrorAction SilentlyContinue) { throw 'Media wrapper fixture already active.' }
$wrapper = Join-Path $PSScriptRoot '../test-revisionstore-media.ps1'
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('phantowd-media-wrapper-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
$files = @('rootfs.ext2','zImage','versatile-pb.dtb','SHA256SUMS','fixture.vhdx') | ForEach-Object { Join-Path $fixtureRoot $_ }
foreach ($file in $files) { New-Item -ItemType File -Path $file | Out-Null }
$oldExit = $global:LASTEXITCODE
$global:phantowdMediaWrapperTest = @{Calls=[Collections.Generic.List[object]]::new(); Free=32GB; Failure=''; Code=1}
function Get-PSDrive { param([string]$Name) [pscustomobject]@{Name=$Name; Free=$global:phantowdMediaWrapperTest.Free} }
function docker {
    $state=$global:phantowdMediaWrapperTest
    $state.Calls.Add(@($args))
    $operation=($args | Select-Object -First 2) -join ' '
    $global:LASTEXITCODE=if ($state.Failure -ne '' -and $operation.StartsWith($state.Failure)) { $state.Code } else { 0 }
}
function Assert-MediaOption([object[]]$Arguments,[string]$Name,[string]$Value) {
    $positions=@(for($i=0;$i -lt $Arguments.Count;$i++){if($Arguments[$i] -ceq $Name){$i}})
    if($positions.Count -ne 1 -or $Arguments[$positions[0]+1] -cne $Value){throw "Invalid option $Name"}
}
try {
    $state=$global:phantowdMediaWrapperTest
    foreach($profile in @('history-reboot','history-ext4','baseline')) {
        $state.Calls.Clear()
        & $wrapper -BaseArtifactDir $fixtureRoot -DockerDataVhdxPath $files[-1] -Profile $profile
        $runs=@($state.Calls | Where-Object {$_[0] -eq 'run'})
        if($runs.Count -ne 1){throw 'Exactly one auto-removed qualification run required'}
        foreach($pair in @(@('--cpus','4'),@('--memory','2g'),@('--memory-swap','2g'),@('--pids-limit','256'),@('--pull','never'),@('--network','none'),@('--user','1000:1000'),@('--cap-drop','ALL'),@('--security-opt','no-new-privileges'))){Assert-MediaOption $runs[0] $pair[0] $pair[1]}
        if('--rm' -notin $runs[0] -or '--read-only' -notin $runs[0]){throw 'Missing disposable read-only container'}
        if($runs[0] | Where-Object {$_ -match '^--(privileged|device|publish|volume)(=|$)'}){throw 'Host authority unexpectedly added'}
        $mounts=@($runs[0] | Where-Object {$_ -match '^type=(bind|volume),'})
        if($mounts.Count -ne 3 -or @($mounts | Where-Object {$_ -notmatch ',readonly(,volume-nocopy)?$'}).Count -ne 0){throw 'All three persistent inputs must stay read-only'}
        Assert-MediaOption $runs[0] '--tmpfs' '/tmp:rw,exec,nosuid,nodev,size=1024m,uid=1000,gid=1000'
        $command=$runs[0][-1]
        if($command -notmatch "printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d \| sh$"){throw 'Missing fixed encoded transport'}
        $linux=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1]))
        if($linux -notmatch ('(?m)^bash /src/support/tests/test-revisionstore-media-qemu.sh /base "\$output" /src '+[regex]::Escape($profile)+'$')){throw 'Wrong closed media profile'}
        $bound=($runs[0] -join ' ')
        if($bound -notmatch '--signal=TERM --kill-after=5 180 /bin/sh -ec '){throw 'Outer deadline changed'}
    }
    foreach($free in @(0,(8GB - 1))) {
        $state.Free=$free; $state.Calls.Clear(); $refused=$false
        try { & $wrapper -BaseArtifactDir $fixtureRoot -DockerDataVhdxPath $files[-1] -Profile history-ext4 } catch { $refused=$true }
        if(!$refused -or $state.Calls.Count -ne 0){throw 'Low headroom must refuse before Docker'}
    }
    $state.Free=8GB; $state.Calls.Clear()
    & $wrapper -BaseArtifactDir $fixtureRoot -DockerDataVhdxPath $files[-1]
    if(@($state.Calls|Where-Object {$_[0] -eq 'run'}).Count -ne 1){throw 'Default baseline or inclusive headroom boundary refused'}
    foreach($failure in @('image inspect','volume inspect','run')) {
        $state.Calls.Clear(); $state.Failure=$failure; $refused=$false
        try { & $wrapper -BaseArtifactDir $fixtureRoot -DockerDataVhdxPath $files[-1] -Profile history-ext4 } catch { $refused=$true }
        if(!$refused -or @($state.Calls|Where-Object {$_[0] -eq 'run'}).Count -ne [int]($failure -eq 'run')){throw 'Failed dependency retried or accepted'}
    }
    foreach($code in @(124,137)) {
        $state.Calls.Clear(); $state.Failure='run'; $state.Code=$code; $refused=$false
        try { & $wrapper -BaseArtifactDir $fixtureRoot -DockerDataVhdxPath $files[-1] -Profile history-ext4 } catch { $refused=$true }
        if(!$refused -or @($state.Calls|Where-Object {$_[0] -eq 'run'}).Count -ne 1){throw 'Timeout/OOM retried or accepted'}
    }
    $state.Failure=''; $state.Code=1; $state.Calls.Clear(); $refused=$false
    try { & $wrapper -BaseArtifactDir $fixtureRoot -DockerDataVhdxPath $files[-1] -Profile foreign } catch { $refused=$true }
    if(!$refused -or $state.Calls.Count -ne 0){throw 'Unknown profile admitted'}
    $state.Calls.Clear(); $refused=$false
    try { & $wrapper -BaseArtifactDir $fixtureRoot -DockerDataVhdxPath (Join-Path $fixtureRoot 'missing') -Profile history-ext4 } catch { $refused=$true }
    if(!$refused -or $state.Calls.Count -ne 0){throw 'Missing data drive admitted'}
    'PHANTOWD_MEDIA_WRAPPER_TESTS_READY profiles=3 scope=mock-boundary-only actual_qemu=false'
} finally {
    Remove-Variable phantowdMediaWrapperTest -Scope Global
    $global:LASTEXITCODE=$oldExit
    foreach ($file in $files) { Remove-Item -LiteralPath $file }
    Remove-Item -LiteralPath $fixtureRoot
}
