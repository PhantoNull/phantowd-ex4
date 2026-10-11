#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# New disposable daemon/NEGOTIATE proof, not file access or product startup.
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
server max protocol = SMB3_02
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
CONFIG
chmod 0644 "$root/etc/passwd" "$root/etc/group" "$root/etc/nsswitch.conf"
chmod 0600 "$root/etc/samba/smb.conf"
mount -o remount,ro,nosuid,nodev,noexec "$root/etc"
mount -t tmpfs -o nosuid,nodev,noexec,size=8m,mode=0700 tmpfs "$state"
for role in private lock state cache pid rpc; do mkdir -m 0700 "$state/$role"; done
mount -t ext4 -o ro,nosuid,nodev,noexec /dev/sdb /run/observer-readonly
mount -t ext4 -o rw,nosuid,nodev,noexec /dev/sdc /run/observer-writable
if /usr/sbin/phantowd-runtime-bundle-probe server-observer-code-binding &&
    /usr/sbin/phantowd-server-observer-daemon-test -test.run '^TestNativeObserverSambaDaemonQEMU$' -test.v; then
    echo PHANTOWD_SERVER_OBSERVER_DAEMON_GUEST_DONE
else
    echo PHANTOWD_SERVER_OBSERVER_DAEMON_GUEST_FAILED
fi
sync
reboot -f
