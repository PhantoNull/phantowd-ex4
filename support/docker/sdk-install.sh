#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
PATH=$PATH:/usr/lib/apt
export PATH
plan=$(mktemp)
trap 'rm -f "$plan"' EXIT HUP INT TERM
apt-get -o Acquire::ForceHash=SHA256 --print-uris "$@" > "$plan"
refuse() { printf 'PHANTOWD_SDK_PACKAGE_REFUSAL reason=%s\n' "$1" >&2; exit 65; }
prefetch() {
    set --
    while read -r uri file size hash extra; do
        case "$uri" in \'*) ;; *) continue ;; esac
        case "$uri" in \'*\') ;; *) refuse uri-quote ;; esac
        [ -z "$extra" ] || refuse fields
        uri=${uri#\'}; uri=${uri%\'}
        case "$uri" in
          file:/tmp/sdk-snapshot/debian/pool/*.deb)
            suffix=${uri#file:/tmp/sdk-snapshot/debian/}
            url=https://deb.debian.org/debian/$suffix ;;
          file:/tmp/sdk-snapshot/debian-security/pool/*.deb)
            suffix=${uri#file:/tmp/sdk-snapshot/debian-security/}
            url=https://deb.debian.org/debian-security/$suffix ;;
          *) refuse source ;;
        esac
        case "$file" in *.deb) ;; *) refuse filename ;; esac
        case "$file" in *[!a-zA-Z0-9._+%:~-]*|.*) refuse filename ;; esac
        case "$size" in ''|*[!0-9]*) refuse size ;; esac
        case "$hash" in SHA256:*) digest=${hash#SHA256:} ;; *) refuse hash ;; esac
        [ "${#digest}" -eq 64 ] || refuse hash
        case "$digest" in *[!0-9a-f]*) refuse hash ;; esac
        # Historical objects can leave the live pool; hashes remain signed.
        case "$digest" in
          04405c19b977d19c5e0fd7210e452b8044a065cb45a82012d45046738920ca75)
            url=https://snapshot.debian.org/file/4fd1e3742c4ad584c12ad55fa8a4b85a23d6ffe2 ;;
          ebcd139c31438e19f161bcf277a38708402ddd0e3acbe208cbbb27bff1c52bb9)
            url=https://snapshot.debian.org/file/0ed67619a7af7e8e00326f6de6c9b60c95427201 ;;
          62b08a77d985d4253894b1f69aebda5925034ca4e294add364167fad8cb64a44)
            url=https://snapshot.debian.org/file/85be8fcf3d5e2c7a62329c40f4d35762f186a8ab ;;
        esac
        set -- "$@" "$url" "/var/cache/apt/archives/$file" "$hash"
    done < "$plan"
    [ "$#" -eq 0 ] || apt-helper -o Acquire::Retries=0 \
        -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 \
        -o Acquire::https::CAInfo=/usr/share/phantowd-sdk-bootstrap-ca.crt \
        download-file "$@"
}
prefetch
rm -f "$plan"
trap - EXIT HUP INT TERM
exec apt-get --no-download "$@"
