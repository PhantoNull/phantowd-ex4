#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
helper="$repo_root/support/container/check-buildroot-go-sdk.sh"
[ -f "$helper" ]
temporary=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-go-sdk.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
cat > "$temporary/current-go" <<'EOF'
#!/bin/sh
[ "$#" = 1 ] && [ "$1" = version ] || exit 1
[ "$GOENV" = off ] && [ "$GOTOOLCHAIN" = local ] && [ "$GOWORK" = off ] || exit 1
printf '%s\n' 'go version go1.26.8 linux/amd64'
EOF
chmod 700 "$temporary/current-go"
sh "$helper" "$temporary/current-go" 1.26.8 >/dev/null
cat > "$temporary/go" <<'EOF'
#!/bin/sh
[ "$#" = 1 ] && [ "$1" = version ] || exit 1
printf '%s\n' 'go version go1.26.6 linux/amd64'
EOF
chmod 700 "$temporary/go"
if sh "$helper" \
    "$temporary/go" 1.26.8 >/dev/null 2>&1; then
    echo 'Stale installed Go SDK was accepted' >&2
    exit 1
fi
if sh "$helper" "$temporary/current-go" 1.26.6 >/dev/null 2>&1; then
    echo 'Mismatching selected Go pin was accepted' >&2
    exit 1
fi
if sh "$helper" "$temporary/current-go" '1.26.8 extra' >/dev/null 2>&1; then
    echo 'Malformed selected Go pin was accepted' >&2
    exit 1
fi
printf 'Installed Go SDK selection and stale/malformed pin refusal passed\n'
