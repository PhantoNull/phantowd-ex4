[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$versionLines = @(Get-Content (Join-Path $repoRoot 'versions.env') | Where-Object { $_ -match '^BUILDROOT_VERSION=' })
if ($versionLines.Count -ne 1) {
    throw 'versions.env must define exactly one BUILDROOT_VERSION.'
}

$buildrootVersion = ($versionLines[0] -split '=', 2)[1].Trim().Trim('"')
if ($buildrootVersion -notmatch '^\d{4}\.\d{2}(?:\.\d{1,2})?$') {
    throw "Unexpected Buildroot version format: $buildrootVersion"
}

$imageName = "phantowd/buildroot:$buildrootVersion"
$workspaceVolume = "phantowd-ex4-buildroot-$($buildrootVersion.Replace('.', '-'))"

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop is unavailable. This optional Linux test requires Docker to be running.'
}

docker image inspect $imageName *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Required local image is missing: $imageName. Run support/build-qemu.ps1 once to seed the pinned toolchain; this script never pulls or builds images."
}

docker volume inspect $workspaceVolume *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Required existing Buildroot workspace is missing: $workspaceVolume. Run support/build-qemu.ps1 once to seed it; this script never creates volumes."
}

$repoMount = "type=bind,source=$repoRoot,target=/external,readonly"
$workspaceMount = "type=volume,source=$workspaceVolume,target=/workspace,readonly,volume-nocopy"
$linuxScript = @'
set -eu
. /external/versions.env
config_hash="$(sha256sum /external/configs/phantowd_qemu_armv5_defconfig | cut -c1-16)"
go_binary="/workspace/output/${BUILDROOT_VERSION}-${config_hash}/host/bin/go"
if [ ! -x "$go_binary" ]; then
    printf 'Pinned Buildroot Go toolchain is missing: %s\nRun support/build-qemu.ps1 once to seed the existing workspace.\n' "$go_binary" >&2
    exit 2
fi

export GOPROXY=off
export GOTOOLCHAIN=local
export GOFLAGS=-mod=vendor
export GOCACHE=/tmp/go-cache
export HOME=/tmp/home
export TMPDIR=/tmp

cd /external/src/phantowd-api
"$go_binary" version
"$go_binary" vet ./...
"$go_binary" test -count=1 ./...
printf 'PHANTOWD_LINUX_API_TESTS_READY buildroot=%s scope=all-api-packages host=linux-amd64 network=none\n' "$BUILDROOT_VERSION"
'@
$linuxScript = $linuxScript.Replace("`r`n", "`n")
$encodedLinuxScript = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($linuxScript))
$linuxCommand = "set -eu; printf '%s' '$encodedLinuxScript' | base64 -d > /tmp/phantowd-test-api-linux.sh; exec /bin/sh /tmp/phantowd-test-api-linux.sh"

docker run --rm `
    --network none `
    --read-only `
    --tmpfs /tmp:rw,exec,nosuid,nodev,size=2048m `
    --mount $repoMount `
    --mount $workspaceMount `
    $imageName `
    sh -ec $linuxCommand

if ($LASTEXITCODE -ne 0) {
    throw 'Linux API vet/tests failed.'
}
