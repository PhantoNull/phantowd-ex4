#!/bin/sh
set -eu

go_binary="${1:?usage: test-api.sh GO_BINARY MODULE_DIR REPORT_DIR}"
module_dir="${2:?module directory required}"
report_dir="${3:?report directory required}"

export GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor
mkdir -p "$report_dir"
cd "$module_dir"
"$go_binary" version
"$go_binary" vet ./...
"$go_binary" test -count=1 -coverprofile="$report_dir/coverage.out" ./...
"$go_binary" test -tags=qemu -run '^(TestQEMUDashboardAssetsMatchSelfTest|TestQEMUTLSLoopbackSmoke|TestQEMUShareConfig|TestQEMUShareStore|TestQEMUSMBPreview|TestQEMUNFSPolicy|TestQEMUNFSFixture|TestQEMUFileServicePreviewHTTP|TestQEMUSMBEffectiveFixture|TestQEMUSMBDenialEvidence|TestQEMUCollisionFixture|TestQEMUStatePersistence|TestQEMUServiceStateBackend)$' -count=1 .
"$go_binary" test -race -count=1 ./...
# Fixed execution counts avoid false deadline failures in the pinned Go 1.26
# fuzz coordinator while keeping CI fuzz coverage reproducible across runners.
"$go_binary" test -run '^$' -fuzz '^FuzzParseMemory$' -fuzztime=100000x -parallel=2 .
"$go_binary" test -run '^$' -fuzz '^FuzzParseMDStat$' -fuzztime=50000x -parallel=2 .
"$go_binary" test -run '^$' -fuzz '^FuzzParsePHC$' -fuzztime=250000x -parallel=2 ./passwordhash
"$go_binary" test -run '^$' -fuzz '^FuzzDecode$' -fuzztime=25000x -parallel=2 ./shareconfig
"$go_binary" test -run '^$' -fuzz '^FuzzPreview$' -fuzztime=25000x -parallel=2 ./smbconfig
"$go_binary" test -run '^$' -fuzz '^FuzzPolicy$' -fuzztime=25000x -parallel=2 ./nfsconfig
"$go_binary" test -run '^$' -fuzz '^FuzzPreviewEnvelope$' -fuzztime=25000x -parallel=2 ./fileservice
"$go_binary" test -run '^$' -fuzz '^FuzzCombinedConfig$' -fuzztime=25000x -parallel=2 ./fileservice
"$go_binary" test -run '^$' -fuzz '^FuzzDecode$' -fuzztime=25000x -parallel=2 ./volumeprobe
"$go_binary" test -run '^$' -fuzz '^FuzzRegistry$' -fuzztime=25000x -parallel=2 ./serviceaccounts
"$go_binary" test -run '^$' -fuzz '^FuzzSnapshot$' -fuzztime=25000x -parallel=2 ./unixidentity
