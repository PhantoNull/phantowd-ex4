#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Fixed root construction/admission only, no client or daemon execution.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
count_parent_fds() {
    # Self-globs see their directory iterator; capture pipes change parent FDs.
    # Read from a separate process without command substitution in the parent.
    /bin/sh -c '
        parent=$1
        set -- /proc/$parent/fd/[0-9]*
        [ "$#" -ge 3 ] && [ "$#" -le 128 ] || exit 1
        for parent_fd do
            [ -L "$parent_fd" ] || exit 1
        done
        printf "%s\n" "$#"
    ' parent-fds "$$" > /run/parent-fd-count || return 1
    IFS= read -r parent_fd_count < /run/parent-fd-count
}
run_fixture() {
    mount -t proc -o nosuid,nodev,noexec proc /proc || return 1
    mount -t sysfs -o nosuid,nodev,noexec sysfs /sys || return 1
    mount -t tmpfs -o mode=0755,size=48m,nosuid,nodev,noexec tmpfs /run || return 1
    mkdir -m 0700 /run/phantowd-pending-client-input /run/phantowd-pending-client-bootstrap || return 1
    mount -t tmpfs -o mode=0700,size=32m,nosuid,nodev tmpfs /run/phantowd-pending-client-input || return 1
    mount -t tmpfs -o mode=0700,size=1m,nosuid,nodev tmpfs /run/phantowd-pending-client-bootstrap || return 1
    /usr/sbin/phantowd-pending-client-inputs stage || return 1
    mount -o remount,ro,nosuid,nodev /run/phantowd-pending-client-input || return 1
    mount -o remount,ro,nosuid,nodev /run/phantowd-pending-client-bootstrap || return 1
    /usr/sbin/phantowd-pending-client-inputs retain || return 1
    count_parent_fds || return 1
    before_fds=$parent_fd_count
    /usr/sbin/phantowd-pending-client-inputs preclose-input-loss &
    fixture_pid=$!
    wait "$fixture_pid" || return 1
    [ ! -d "/proc/$fixture_pid" ] || return 1
    count_parent_fds || return 1
    after_fds=$parent_fd_count
    [ "$before_fds" = "$after_fds" ] || return 1
    echo 'PHANTOWD_PENDING_OWNER_INPUT_LOSS_PROCESS_READY exit0=true child_reaped=true parent_fd_count_equal=true client_executed=false scope=qemu-only'
}
if run_fixture; then
    echo PHANTOWD_PENDING_INPUTS_GUEST_DONE
else
    echo PHANTOWD_PENDING_INPUTS_GUEST_FAILED
fi
sync
reboot -f
