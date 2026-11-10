#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/bin"
cat >"$tmp/bin/qemu-system-arm" <<'EOF'
#!/bin/sh
cat "$PHANTOWD_TEST_LOG"
EOF
chmod +x "$tmp/bin/qemu-system-arm"
export PATH="$tmp/bin:$PATH" PHANTOWD_TEST_LOG="$tmp/input"
cat >"$tmp/valid" <<'EOF'
PHANTOWD_NAS_BOOT_BEFORE_PROVIDER_READY init_exit_nonzero=true api_started=false
PHANTOWD_NAS_PROVIDER_READY root=true directory_mode=0710 socket_mode=0660 runtime=run scope=qemu-only
PHANTOWD_NAS_PROVIDER_INIT_READY before_api=true runtime=run
PHANTOWD_NAS_BOOT_MISSING_READY standard_main=true exit_nonzero=true no_fallback=true
PHANTOWD_NAS_BOOT_API_READY init=true nonroot=true https=verified authenticated=true config=provider scope=qemu-only
PHANTOWD_NAS_BOOT_STOP_READY provider_exited=true api_pid_unchanged=true socket_absent=true pidfile_absent=true readiness_absent=true
PHANTOWD_NAS_BOOT_REFUSED_READY https=verified authenticated=true first=503 second=503 code=nas_configuration_reconciliation_required reconnects=0 respawn=false
PHANTOWD_NAS_BOOT_API_STOP_READY exited=true close_error=false services_activated=false
PHANTOWD_NAS_BOOT_DONE
EOF
cp "$tmp/valid" "$tmp/input"
sh "$repo/support/qemu-nas-policy-boot.sh" unused "$tmp/output"
for marker in STOP_READY REFUSED_READY API_STOP_READY; do
    sed "/PHANTOWD_NAS_BOOT_$marker /d" "$tmp/valid" >"$tmp/input"
    if sh "$repo/support/qemu-nas-policy-boot.sh" unused "$tmp/output" 2>/dev/null; then
        echo "missing stop proof admitted: $marker" >&2; exit 1
    fi
done
for mutation in 's/first=503/first=200/' 's/reconnects=0/reconnects=1/' \
    's/respawn=false/respawn=true/' 's/close_error=false/close_error=true/' \
    '/BOOT_STOP_READY/p' '/BOOT_STOP_READY/{h;d;};/BOOT_REFUSED_READY/G'; do
    sed "$mutation" "$tmp/valid" >"$tmp/input"
    if sh "$repo/support/qemu-nas-policy-boot.sh" unused "$tmp/output" 2>/dev/null; then
        echo "invalid stop proof admitted: $mutation" >&2; exit 1
    fi
done
echo 'NAS boot stop-log acceptance and nine refusal controls passed'
