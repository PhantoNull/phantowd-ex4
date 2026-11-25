#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
boot() {
    mount -t proc proc /proc || return 1
    mount -t sysfs sysfs /sys || return 1
    mount -t tmpfs -o mode=0755,size=64m tmpfs /run || return 1
    export TMPDIR=/run
    ifconfig lo 127.0.0.1 up || return 1
    touch /run/phantowd-nas-policy-boot-profile || return 1
    export PHANTOWD_NAS_POLICY_SOCKET=/run/phantowd-nas-policy-boot/channel
    export PHANTOWD_TLS_CERT_FILE=/run/phantowd-nas-policy-boot/cert.pem
    export PHANTOWD_TLS_KEY_FILE=/run/phantowd-nas-policy-boot/key.pem
    export PHANTOWD_LISTEN_ADDR=127.0.0.1:8443 PHANTOWD_PUBLIC_ORIGIN=https://127.0.0.1:8443
    /etc/init.d/S49phantowd-dev-state start || return 1
    if /etc/init.d/S50phantowd-api start; then return 1; fi
    [ ! -e /run/phantowd-api.pid ] || return 1
    echo 'PHANTOWD_NAS_BOOT_BEFORE_PROVIDER_READY init_exit_nonzero=true api_started=false'
    /etc/init.d/S49phantowd-nas-policy-owner start || return 1
    /usr/bin/phantowd-api --qemu-nas-policy-client=boot-missing || return 1
    /usr/bin/phantowd-api --qemu-nas-policy-client=boot || return 1
}
if boot; then echo PHANTOWD_NAS_BOOT_DONE; else echo PHANTOWD_NAS_BOOT_FAILED; fi
reboot -f
