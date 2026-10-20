# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$entrypoint = Join-Path $PSScriptRoot '../test-api.ps1'
# Stop at the first native phase. Only the real, existing mock-boundary suites
# may complete first: no actual Node, Go, Docker, compiler or guest is invoked.
function node { throw 'PHANTOWD_PREFLIGHT_NATIVE_BOUNDARY' }
function go { throw 'PHANTOWD_PREFLIGHT_NATIVE_BOUNDARY' }
function docker { throw 'Unexpected unmocked Docker execution.' }
$rows = @(& {
    try { & $entrypoint }
    catch {
        if ($_.Exception.Message -cne 'PHANTOWD_PREFLIGHT_NATIVE_BOUNDARY') { throw }
        'PHANTOWD_PREFLIGHT_NATIVE_BOUNDARY'
    }
} 2>&1 | ForEach-Object { $_.ToString() })
if ($rows.Count -gt 64) { throw 'Unexpected preflight output growth.' }
$cursor = -1
foreach ($prefix in @(
    'PHANTOWD_LINUX_API_WRAPPER_TESTS_READY ',
    'PHANTOWD_API_OVERLAY_WRAPPER_TESTS_READY ',
    'PHANTOWD_API_OVERLAY_REBOOT_OPTION_READY ',
    'PHANTOWD_API_OVERLAY_WRAPPER_READY ',
    'PHANTOWD_PREFLIGHT_NATIVE_BOUNDARY'
)) {
    $positions = @(for ($i = 0; $i -lt $rows.Count; $i++) {
        if ($rows[$i].StartsWith($prefix, [StringComparison]::Ordinal)) { $i }
    })
    if ($positions.Count -ne 1 -or $positions[0] -le $cursor) {
        throw 'All original command-boundary suites must pass once before native tools.'
    }
    $cursor = $positions[0]
}
# Replay the actual previously missed literal-command regression in a tiny,
# generated source fixture. Never edit the real entrypoint or its wrappers.
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('phantowd-api-preflight-' + [guid]::NewGuid().ToString('N'))
$fixtureOwned = $false
try {
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    $fixtureOwned = $true
    $support = Join-Path $fixtureRoot 'support'
    $tests = Join-Path $support 'tests'
    New-Item -ItemType Directory -Path $tests -Force | Out-Null
    $fixtureEntry = Join-Path $support 'test-api.ps1'
    Copy-Item -LiteralPath $entrypoint -Destination $fixtureEntry
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../../versions.env') -Destination (Join-Path $fixtureRoot 'versions.env')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'test-api-linux-wrapper.ps1') -Destination (Join-Path $tests 'test-api-linux-wrapper.ps1')
    $original = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '../test-api-linux.ps1'))
    $selection = '^TestNFS(Expected|Code|Configuration|Inputs|Table|RPCBind|Mountd)'
    if ([regex]::Matches($original, [regex]::Escape($selection)).Count -ne 1) {
        throw 'Original fixed command prerequisite changed.'
    }
    $changed = $original.Replace($selection, '^TestNFS(Expected|Code|Configuration|Inputs|Table|RPCBind|Mountd|Source|Daemon)')
    [IO.File]::WriteAllText((Join-Path $support 'test-api-linux.ps1'), $changed, [Text.UTF8Encoding]::new($false))
    $refusal = @(& {
        try {
            & $fixtureEntry
            throw 'Broken command contract was admitted.'
        } catch {
            if ($_.Exception.Message -cne 'A previous Go qualification command was removed or changed.') { throw }
            'PHANTOWD_PREFLIGHT_CONTRACT_REFUSED'
        }
    } 2>&1 | ForEach-Object { $_.ToString() })
    if ($refusal.Count -ne 1 -or $refusal[0] -cne 'PHANTOWD_PREFLIGHT_CONTRACT_REFUSED' -or
        (Test-Path -LiteralPath (Join-Path $fixtureRoot 'artifacts'))) {
        throw 'Command refusal must precede native tools and report creation.'
    }
} finally {
    if ($fixtureOwned -and (Test-Path -LiteralPath $fixtureRoot)) {
        # Resolve and verify this one freshly owned direct temporary child
        # before recursive removal. No repository/cache or existing task path.
        $item = Get-Item -LiteralPath $fixtureRoot
        $parent = (Get-Item -LiteralPath ([IO.Path]::GetTempPath())).FullName.TrimEnd(
            [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.FullName -cne [IO.Path]::GetFullPath($fixtureRoot) -or
            $item.Parent.FullName -cne $parent -or $item.Name -notmatch '^phantowd-api-preflight-[0-9a-f]{32}$') {
            throw 'Refuse cleanup of an unexpected fixture target.'
        }
        Remove-Item -LiteralPath $item.FullName -Recurse -Force
    }
}
'PHANTOWD_API_PREFLIGHT_ORDER_READY actual_entrypoint=true native_sentinel=true original_suites=3 contract_refusal=true node_go=false docker=false guests=false'
