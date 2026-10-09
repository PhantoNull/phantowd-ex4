#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
helper="$repo_root/support/container/check-buildroot-openssl-tool.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-openssl-tool.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
host="$temporary/host prefix"
mkdir -p "$host/bin"
cat > "$host/bin/openssl" <<'EOF'
#!/bin/sh
[ "$#" = 1 ] && [ "$1" = version ] || exit 1
[ "$OPENSSL_CONF" = /dev/null ] || exit 1
[ "$PATH" = /usr/bin:/bin ] || exit 1
[ "$LD_LIBRARY_PATH" = "${0%/bin/openssl}/lib:${0%/bin/openssl}/lib64" ] || exit 1
[ "${OPENSSL_MODULES+x}" != x ] || exit 1
cat "${0%/bin/openssl}/version-output"
EOF
chmod 700 "$host/bin/openssl"
printf '%s\n' 'OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 29 Sep 2026)' \
    > "$host/version-output"
OPENSSL_MODULES=/untrusted/modules OPENSSL_CONF=/untrusted/config \
    sh "$helper" "$host" 3.5.9 >/dev/null
refuse() {
    if sh "$helper" "$host" "$1" >/dev/null 2>&1; then
        echo 'Mismatching, incomplete or malformed installed OpenSSL selection accepted' >&2
        exit 1
    fi
}
for output in \
    'OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.8 7 Apr 2026)' \
    'OpenSSL 3.5.8 7 Apr 2026 (Library: OpenSSL 3.5.9 29 Sep 2026)' \
    'OpenSSL 3.5.8 7 Apr 2026 (Library: OpenSSL 3.5.8 7 Apr 2026)' \
    'OpenSSL 3.5.9 29 Sep 2026' \
    'OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 28 Sep 2026)' \
    'OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 29 Sep 2026) extra' \
    'OpenSSL 3.5.9-dev 29 Sep 2026 (Library: OpenSSL 3.5.9-dev 29 Sep 2026)' \
    ''; do
    printf '%s\n' "$output" > "$host/version-output"
    refuse 3.5.9
done
printf '%s\n' 'OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 29 Sep 2026)' \
    > "$host/version-output"
for pin in 3.5.8 '3.5.9 extra' '3.5.9
3.5.9' '' 3.5; do
    refuse "$pin"
done
printf '%s\n' 'extra row' >> "$host/version-output"
refuse 3.5.9
cat > "$host/bin/openssl" <<'EOF'
#!/bin/sh
printf '%s\n' 'OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 29 Sep 2026)'
exit 1
EOF
chmod 700 "$host/bin/openssl"
refuse 3.5.9
rm -- "$host/bin/openssl"
refuse 3.5.9
printf 'Installed OpenSSL CLI/library selection, sanitized environment and refusals passed\n'
