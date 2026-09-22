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
# Use a deterministic iteration budget: Go 1.26 can spuriously report
# "context deadline exceeded" when a time-limited fuzz run stops.
"$go_binary" test -run '^$' -fuzz '^FuzzInspect$' -fuzztime=10000x -parallel=2 -timeout=120s ./vendorupdate
"$go_binary" test -run '^$' -fuzz '^FuzzStreamDecoder$' -fuzztime=10000x -parallel=2 -timeout=120s ./mcuproto
