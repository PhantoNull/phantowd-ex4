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
"$go_binary" test -race -count=1 ./...
"$go_binary" test -run '^$' -fuzz '^FuzzParseMemory$' -fuzztime=5s -parallel=2 .
