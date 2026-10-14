#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Dedicated RAM-only bootstrap/module composition, no client or file request.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
awk '$2 == "/dev" && $3 == "devtmpfs" { found = 1 } END { exit !found }' /proc/mounts
grep -Eq '^virtio_rng(\.[0-9]+)?$' /sys/class/misc/hw_random/rng_current
ifconfig lo up
mount -t tmpfs -o nosuid,nodev,size=96m,mode=0755 tmpfs /run
root=/run/phantowd-native-samba-root
state=/run/phantowd-native-samba-state
code=/run/phantowd-samba-code
mkdir -p "$root/etc" "$root/lib" "$root/usr" "$root/state" "$root/shares/readonly" "$root/shares/writable" "$state" /run/observer-readonly /run/observer-writable
mkdir -m 0700 "$code"
/usr/sbin/phantowd-runtime-bundle-probe stage
mount --bind "$code" "$code"
mount -o remount,bind,ro,nosuid,nodev "$code"
mount -t tmpfs -o nosuid,nodev,noexec,size=64k,mode=0755 tmpfs "$root/etc"
mkdir "$root/etc/samba"
printf 'root:x:0:0:root:/:/bin/false\nnobody:x:65534:65534:nobody:/:/bin/false\n' >"$root/etc/passwd"
printf 'root:x:0:\nnogroup:x:65534:\n' >"$root/etc/group"
printf 'passwd: files\ngroup: files\n' >"$root/etc/nsswitch.conf"
cat >"$root/etc/samba/smb.conf" <<'CONFIG'
[global]
server role = standalone server
workgroup = QEMU
netbios name = OBSERVER
interfaces = 127.0.0.1
bind interfaces only = yes
disable netbios = yes
smb ports = 1445
server min protocol = SMB3_02
server max protocol = SMB3_11
server signing = mandatory
passdb backend = tdbsam:/state/private/passdb.tdb
private dir = /state/private
lock directory = /state/lock
state directory = /state/state
cache directory = /state/cache
pid directory = /state/pid
ncalrpc dir = /state/rpc
load printers = no
printing = bsd
printcap name = /etc/passwd
log level = 0
[readonly]
path = /shares/readonly
read only = yes
guest ok = no
valid users = nobody
vfs objects = phantowd_open_qemu
CONFIG
chmod 0644 "$root/etc/passwd" "$root/etc/group" "$root/etc/nsswitch.conf"
chmod 0600 "$root/etc/samba/smb.conf"
mount -o remount,ro,nosuid,nodev,noexec "$root/etc"
mount -t tmpfs -o nosuid,nodev,noexec,size=8m,mode=0700 tmpfs "$state"
for role in private lock state cache pid rpc; do mkdir -m 0700 "$state/$role"; done
mount -t ext4 -o ro,nosuid,nodev,noexec /dev/sdb /run/observer-readonly
mount -t ext4 -o rw,nosuid,nodev,noexec /dev/sdc /run/observer-writable
if grep -qw 'phantowd_capture_client_open_fixture=1' /proc/cmdline; then
    mkdir -m 0700 /run/phantowd-pending-client-input /run/phantowd-pending-client-bootstrap /run/phantowd-pending-client-root
    mount -t tmpfs -o mode=0700,size=32m,nosuid,nodev tmpfs /run/phantowd-pending-client-input
    mount -t tmpfs -o mode=0700,size=1m,nosuid,nodev tmpfs /run/phantowd-pending-client-bootstrap
    /usr/sbin/phantowd-pending-client-inputs stage
    mount -o remount,ro,nosuid,nodev /run/phantowd-pending-client-input
    mount -o remount,ro,nosuid,nodev /run/phantowd-pending-client-bootstrap
    if /usr/sbin/phantowd-runtime-bundle-probe server-capture-open; then
        if grep -qw 'phantowd_capture_cancel_read_fixture=1' /proc/cmdline; then
            echo PHANTOWD_CAPTURE_CANCEL_READ_GUEST_DONE
        elif grep -qw 'phantowd_capture_uncertain_read_fixture=1' /proc/cmdline; then
            echo PHANTOWD_CAPTURE_UNCERTAIN_READ_GUEST_DONE
        elif grep -Eq '(^| )phantowd_capture_input_fault_fixture=(module|configuration|channel|source)( |$)' /proc/cmdline; then
            echo PHANTOWD_CAPTURE_INPUT_FAULT_GUEST_DONE
        elif grep -qw 'phantowd_capture_worker_exit_fixture=1' /proc/cmdline; then
            echo PHANTOWD_CAPTURE_WORKER_EXIT_GUEST_DONE
        else
            echo PHANTOWD_CAPTURE_OPEN_GUEST_DONE
        fi
    else
        echo PHANTOWD_CAPTURE_OPEN_GUEST_FAILED
    fi
else
    if /usr/sbin/phantowd-runtime-bundle-probe server-capture-runtime && \
        /usr/sbin/phantowd-capture-adapter-tests -test.run '^TestServerCaptureClient' -test.timeout 5s -test.count 1 -test.v; then
        echo PHANTOWD_CAPTURE_RUNTIME_GUEST_DONE
    else
        echo PHANTOWD_CAPTURE_RUNTIME_GUEST_FAILED
    fi
fi
sync
reboot -f
