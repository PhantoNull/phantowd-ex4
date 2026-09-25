#!/bin/sh
set -eu

go_binary="${1:?usage: test-lab-tools.sh GO_BINARY MODULE_DIR REPORT_DIR}"
module_dir="${2:?module directory required}"
report_dir="${3:?report directory required}"

export GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor
mkdir -p "$report_dir"
cd "$module_dir"
"$go_binary" version
"$go_binary" vet ./...
"$go_binary" test -count=1 -coverprofile="$report_dir/coverage.out" ./...
"$go_binary" test -race -count=1 ./...
# Fixed execution counts avoid false deadline failures in the pinned Go 1.26
# fuzz coordinator while keeping CI fuzz coverage reproducible across runners.
"$go_binary" test -run '^$' -fuzz '^FuzzInspect$' -fuzztime=100000x -parallel=2 ./vendorupdate
"$go_binary" test -run '^$' -fuzz '^FuzzStreamDecoder$' -fuzztime=100000x -parallel=2 ./mcuproto
"$go_binary" test -run '^$' -fuzz '^FuzzStorageInventoryAndDryRunNeverBecomeExecutable$' -fuzztime=100000x -parallel=2 ./storageinventory
