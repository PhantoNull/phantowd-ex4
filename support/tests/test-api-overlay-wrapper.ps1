# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if (Get-Variable phantowdOverlayWrapperTest -Scope Global -ErrorAction SilentlyContinue) {
    throw 'Overlay wrapper test context already active.'
}
$wrapper = Join-Path $PSScriptRoot '../test-api-overlay.ps1'
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('phantowd-overlay-wrapper-' + [guid]::NewGuid().ToString('N'))
$base = Join-Path $fixtureRoot 'base'
New-Item -ItemType Directory -Path $base -Force | Out-Null
$files = @('rootfs.ext2','zImage','versatile-pb.dtb','SHA256SUMS') | ForEach-Object { Join-Path $base $_ }
$disk = Join-Path $fixtureRoot 'fixture.vhdx'
foreach ($file in @($files) + @($disk)) { New-Item -ItemType File -Path $file | Out-Null }
$previousExit = $global:LASTEXITCODE
$global:phantowdOverlayWrapperTest = @{ Calls=[Collections.Generic.List[object]]::new(); Free=32GB; Failure=''; FailureCode=1 }
function Get-PSDrive { param([string]$Name) [pscustomobject]@{Name=$Name;Free=$global:phantowdOverlayWrapperTest.Free} }
function docker {
    $state=$global:phantowdOverlayWrapperTest
    $state.Calls.Add(@($args))
    $operation=($args | Select-Object -First 2) -join ' '
    $global:LASTEXITCODE=if ($state.Failure -ne '' -and $operation.StartsWith($state.Failure)) { $state.FailureCode } else { 0 }
}
function Assert-Option([object[]]$Arguments,[string]$Name,[string]$Value) {
    $positions=@(for($i=0;$i -lt $Arguments.Count;$i++){if($Arguments[$i] -eq $Name){$i}})
    if($positions.Count -ne 1 -or $Arguments[$positions[0]+1] -ne $Value){throw "Invalid option $Name"}
}
try {
    & $wrapper -BaseArtifactDirectory $base -DockerDataVhdxPath $disk -ReuseBaseVolumeProbe
    $state=$global:phantowdOverlayWrapperTest
    $runs=@($state.Calls | Where-Object {$_[0] -eq 'run'})
    if($runs.Count -ne 1){throw 'One isolated run required at32GiB, below full-build40GiB'}
    foreach($pair in @(@('--cpus','2'),@('--memory','2g'),@('--memory-swap','2g'),@('--pids-limit','256'),@('--pull','never'),@('--network','none'),@('--user','1000:1000'),@('--cap-drop','ALL'),@('--security-opt','no-new-privileges:true'))){Assert-Option $runs[0] $pair[0] $pair[1]}
    if('--rm' -notin $runs[0] -or '--read-only' -notin $runs[0]){throw 'Root must be read-only and container disposable'}
    $mounts=@($runs[0] | Where-Object {$_ -match '^type=(bind|volume),'})
    if($mounts.Count -ne 3 -or @($mounts | Where-Object {$_ -notmatch ',readonly(,volume-nocopy)?$'}).Count -ne 0){throw 'Exactly three read-only mounts required'}
    if($runs[0] | Where-Object {$_ -match '^--(privileged|device|publish|volume)(=|$)'}){throw 'Unexpected host authority'}
    Assert-Option $runs[0] '--tmpfs' '/tmp:rw,exec,nosuid,nodev,size=1024m,uid=1000,gid=1000'
    $command=$runs[0][-1]
    if($command -notmatch 'exec timeout --signal=TERM --kill-after=10s 360s /bin/sh /tmp/phantowd-api-overlay.sh$'){throw 'Missing whole-run bound'}
    if($command -notmatch "printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d"){throw 'Missing encoded command'}
    $linux=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1]))
    foreach($line in @('export PHANTOWD_QEMU_OVERLAY_REUSE_BASE_VOLUME_PROBE=1','export PHANTOWD_QEMU_OVERLAY_SMOKE_ONLY=1')){
        if($line -notin ($linux -split "`n")){throw 'Fixed API-only scope changed'}
    }
    $state.Calls.Clear()
    & $wrapper -BaseArtifactDirectory $base -DockerDataVhdxPath $disk -ReuseBaseVolumeProbe -IncludeStateReboot
    $rebootRuns=@($state.Calls | Where-Object {$_[0] -eq 'run'})
    if($rebootRuns.Count -ne 1){throw 'Explicit state reboot must use one disposable run'}
    if($rebootRuns[0].Count -ne $runs[0].Count){throw 'Explicit reboot changed container admission'}
    for($i=0;$i -lt $runs[0].Count-1;$i++){
        if($rebootRuns[0][$i] -ne $runs[0][$i]){throw 'Explicit reboot changed an original container option'}
    }
    $rebootCommand=$rebootRuns[0][-1]
    if($rebootCommand -notmatch "printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d"){throw 'Missing explicit reboot command'}
    $rebootLinux=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1]))
    if('export PHANTOWD_QEMU_OVERLAY_SMOKE_ONLY=0' -notin ($rebootLinux -split "`n")){throw 'Explicit reboot did not select existing two-boot lane'}
    $state.Calls.Clear();$refused=$false
    try{& $wrapper -BaseArtifactDirectory $base -DockerDataVhdxPath $disk}catch{$refused=$true}
    if(!$refused -or $state.Calls.Count -ne 0){throw 'Probe-reuse acknowledgement required before Docker'}
    foreach($free in @(0,(8GB - 1))){
        $state.Calls.Clear();$state.Free=$free;$refused=$false
        try{& $wrapper -BaseArtifactDirectory $base -DockerDataVhdxPath $disk -ReuseBaseVolumeProbe}catch{$refused=$true}
        if(!$refused -or $state.Calls.Count -ne 0){throw 'Insufficient headroom must refuse before Docker'}
    }
    $state.Free=32GB
    foreach($includeReboot in @($false,$true)){
      foreach($failure in @('info','image inspect','volume inspect','run')){
        $state.Calls.Clear();$state.Failure=$failure;$refused=$false
        try{& $wrapper -BaseArtifactDirectory $base -DockerDataVhdxPath $disk -ReuseBaseVolumeProbe -IncludeStateReboot:$includeReboot}catch{$refused=$true}
        if(!$refused){throw 'Dependency/run failure was accepted'}
        if(@($state.Calls|Where-Object {$_[0] -eq 'run'}).Count -ne [int]($failure -eq 'run')){throw 'Refusal ran/retried a container'}
      }
      foreach($code in @(124,137)){
        $state.Calls.Clear();$state.Failure='run';$state.FailureCode=$code;$refused=$false
        try{& $wrapper -BaseArtifactDirectory $base -DockerDataVhdxPath $disk -ReuseBaseVolumeProbe -IncludeStateReboot:$includeReboot}catch{$refused=$true}
        if(!$refused -or @($state.Calls|Where-Object {$_[0] -eq 'run'}).Count -ne 1){throw 'Timeout/OOM accepted or retried'}
      }
    }
    $state.Failure='';$state.FailureCode=1;$state.Free=8GB;$state.Calls.Clear()
    & $wrapper -BaseArtifactDirectory $base -DockerDataVhdxPath $disk -ReuseBaseVolumeProbe
    if(@($state.Calls|Where-Object {$_[0] -eq 'run'}).Count -ne 1){throw 'Inclusive8GiB boundary refused'}
    foreach($missing in @('base','disk')){
        $state.Calls.Clear();$refused=$false
        try{
            if($missing -eq 'base') { & $wrapper -BaseArtifactDirectory (Join-Path $fixtureRoot 'missing') -DockerDataVhdxPath $disk -ReuseBaseVolumeProbe }
            else { & $wrapper -BaseArtifactDirectory $base -DockerDataVhdxPath (Join-Path $fixtureRoot 'missing') -ReuseBaseVolumeProbe }
        }catch{$refused=$true}
        if(!$refused -or $state.Calls.Count -ne 0){throw 'Missing input must refuse before Docker'}
    }
    'PHANTOWD_API_OVERLAY_WRAPPER_TESTS_READY scope=mock-boundary-only actual_qemu=false'
    'PHANTOWD_API_OVERLAY_REBOOT_OPTION_READY default_smoke=true explicit_reboot=true unchanged_limits=true no_retry=true scope=mock-boundary-only'
} finally {
    Remove-Variable phantowdOverlayWrapperTest -Scope Global
    $global:LASTEXITCODE=$previousExit
    foreach($file in @($files)+@($disk)){Remove-Item -LiteralPath $file -Force}
    Remove-Item -LiteralPath $base
    Remove-Item -LiteralPath $fixtureRoot
}
