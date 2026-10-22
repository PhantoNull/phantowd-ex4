#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Stock producer experiment only: no daemon, account, share or physical device.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH
umask 077
holder_pid=
stop_holder() {
    [ -n "$holder_pid" ] || return 0
    printf 'quit\n' >&3 || return 1
    exec 3>&-
    wait "$holder_pid"
    holder_status=$?
    holder_pid=
    [ "$holder_status" -eq 0 ]
}
run_case() {
    case_name=$1
    case "$case_name" in empty|malformed) ;; *) return 1 ;; esac
    prefix=/run/phantowd-status-producer/$case_name
    mkdir -m 0700 "$prefix" || return 1
    for directory in private lock state cache pid rpc; do
        mkdir -m 0700 "$prefix/$directory" || return 1
    done
    database=$prefix/lock/smbXsrv_session_global.tdb
    [ ! -e "$database" ] && [ ! -L "$database" ] || return 1
    cat >"$prefix/smb.conf" <<EOF
[global]
server role = standalone server
security = user
interfaces = 127.0.0.1
bind interfaces only = yes
load printers = no
disable spoolss = yes
private dir = $prefix/private
lock directory = $prefix/lock
state directory = $prefix/state
cache directory = $prefix/cache
pid directory = $prefix/pid
ncalrpc dir = $prefix/rpc
log file = $prefix/log
EOF
    mkfifo -m 0600 "$prefix/control" || return 1
    exec 3<>"$prefix/control" || return 1
    /usr/bin/tdbtool <"$prefix/control" >"$prefix/tool.log" 2>&1 3>&- &
    holder_pid=$!
    printf 'create %s\n' "$database" >&3 || return 1
    : >"$prefix/expected"
    if [ "$case_name" = malformed ]; then
        # Use the string command's binary escapes. This pinned tdbtool's
        # storehex parser does not advance its loop counter.
        printf '%s\n' 'store \00\00\00\01 \01' >&3 || return 1
        printf '%s\n' '{' 'key(4) = "\00\00\00\01"' \
            'data(1) = "\01"' '}' >"$prefix/expected"
    fi
    # tdbtool's live TDB_CLEAR_IF_FIRST context holds its active lock. A closed
    # seed would be cleared by the consumer and would not test a bad record.
    ready=0
    for attempt in 1 2 3 4 5; do
        if /usr/bin/tdbdump "$database" >"$prefix/before.dump" 2>"$prefix/dump.err" &&
            cmp -s "$prefix/expected" "$prefix/before.dump"; then
            ready=1
            break
        fi
        kill -0 "$holder_pid" 2>/dev/null || return 1
        if [ "$attempt" -eq 5 ]; then
            [ "$(wc -c <"$prefix/before.dump")" -le 1024 ] || return 1
            observed=$(base64 "$prefix/before.dump" | tr -d '\n')
            printf 'PHANTOWD_STATUS_PRODUCER_SEED_FAILED case=%s dump_b64=%s\n' "$case_name" "$observed"
            return 1
        fi
        sleep 1
    done
    [ "$ready" -eq 1 ] || return 1
    kill -0 "$holder_pid" 2>/dev/null || return 1
    [ "$(wc -c <"$database")" -le 1048576 ] || return 1
    before=$(sha256sum "$database" | cut -d ' ' -f1)
    /usr/sbin/phantowd-status-producer-deadline "$case_name" \
        >"$prefix/stdout" 2>"$prefix/stderr"
    producer_status=$?
    kill -0 "$holder_pid" 2>/dev/null || return 1
    after=$(sha256sum "$database" | cut -d ' ' -f1)
    /usr/bin/tdbdump "$database" >"$prefix/after.dump" 2>"$prefix/dump.err" || return 1
    cmp -s "$prefix/expected" "$prefix/after.dump" || return 1
    [ "$before" = "$after" ] || return 1
    stop_holder || return 1
    [ "$(wc -c <"$prefix/stdout")" -le 8192 ] || return 1
    stderr_bytes=$(wc -c <"$prefix/stderr")
    [ "$stderr_bytes" -le 8192 ] || return 1
    if [ "$producer_status" -eq 127 ]; then
        diagnostic=$(base64 "$prefix/stderr" | tr -d '\n')
        printf 'PHANTOWD_STATUS_PRODUCER_EXEC_FAILED case=%s stderr_b64=%s\n' "$case_name" "$diagnostic"
    fi
    output=$(base64 "$prefix/stdout" | tr -d '\n')
    dump=$(base64 "$prefix/after.dump" | tr -d '\n')
    printf 'PHANTOWD_STATUS_PRODUCER_CASE case=%s exit=%s before_sha256=%s after_sha256=%s holder_live=true holder_exit=0 stderr_bytes=%s stdout_b64=%s dump_b64=%s\n' \
        "$case_name" "$producer_status" "$before" "$after" "$stderr_bytes" "$output" "$dump"
}
run_fixture() {
    [ "$(id -u)" -eq 0 ] && [ "$(id -g)" -eq 0 ] || return 1
    mount -t proc proc /proc || return 1
    mount -t sysfs sysfs /sys || return 1
    [ "$(tr -d '\000' </sys/firmware/devicetree/base/model)" = 'ARM Versatile PB' ] || return 1
    awk '{ for (i=1;i<=NF;i++) { if ($i == "phantowd_status_producer_fixture=1") good++;
        else if ($i ~ /^phantowd_status_producer_fixture(=|$)/) bad++ }
        } END { exit !(good == 1 && bad == 0) }' /proc/cmdline || return 1
    awk '$2 == "/" && $4 ~ /(^|,)ro(,|$)/ { found=1 } END { exit !found }' /proc/mounts || return 1
    pidof smbd >/dev/null && return 1
    mount -t tmpfs -o mode=0700,size=8m,nosuid,nodev,noexec tmpfs /run || return 1
    mount -t tmpfs -o mode=0700,size=1m,nosuid,nodev,noexec tmpfs /tmp || return 1
    ifconfig lo 127.0.0.1 up || return 1
    ulimit -f 2048 || return 1
    mkdir -m 0700 /run/phantowd-status-producer || return 1
    printf '%s\n' 'PHANTOWD_STATUS_PRODUCER_GUARD_READY readonly_root=true tmpfs_state=true no_daemon=true scope=qemu-only'
    status_hash=$(sha256sum /usr/bin/smbstatus | cut -d ' ' -f1)
    tool_hash=$(sha256sum /usr/bin/tdbtool | cut -d ' ' -f1)
    dump_hash=$(sha256sum /usr/bin/tdbdump | cut -d ' ' -f1)
    library_hash=$(sha256sum /usr/lib/libsmbconf.so.0.0.1 | cut -d ' ' -f1)
    printf 'PHANTOWD_STATUS_PRODUCER_INPUTS smbstatus=%s tdbtool=%s tdbdump=%s smbconf=%s\n' \
        "$status_hash" "$tool_hash" "$dump_hash" "$library_hash"
    run_case empty && run_case malformed || return 1
    pidof smbd >/dev/null && return 1
    printf '%s\n' 'PHANTOWD_STATUS_PRODUCER_DONE cases=2 scope=qemu-only'
}
if run_fixture; then
    : # Completion of the experiment is NOT qualification of its results.
else
    stop_holder || true
    printf '%s\n' 'PHANTOWD_STATUS_PRODUCER_FAILED scope=qemu-only'
fi
sync
reboot -f
