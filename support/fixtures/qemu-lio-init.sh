#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Dedicated disposable guest PID1. Not part of any rootfs overlay/product init.
set -efu
[ "$$" -eq 1 ]
phase=init
trap 'echo "PHANTOWD_LIO_ERROR phase=$phase"; exec /sbin/reboot -f' EXIT
mount -t proc proc /proc
mount -t sysfs sysfs /sys
phase=mutual-profile
mutual_mode=$(awk '{ for (i=1; i<=NF; i++) if ($i ~ /^phantowd.lio_mutual=/) { count++; value=$i } } END { if (count != 1) exit 1; print value }' /proc/cmdline)
case "$mutual_mode" in phantowd.lio_mutual=default|phantowd.lio_mutual=strict) ;; *) exit 1 ;; esac
phase='devtmpfs'
grep -q ' /dev devtmpfs ' /proc/mounts
phase='root-readonly'
awk '$2 == "/" && $4 ~ /(^|,)ro(,|$)/ { found = 1 } END { exit !found }' /proc/mounts
phase='scratch'
mount -t tmpfs -o mode=0755,nosuid,nodev,size=64m tmpfs /run
mkdir /run/phantowd-lio
phase='loopback'
ifconfig lo 127.0.0.1 up
phase='interface-roster'
# No virtual NIC is attached. The pinned IPv6 kernel creates inactive sit0.
[ "$(ls -1 /sys/class/net)" = 'lo
sit0' ]
[ "$(cat /sys/class/net/sit0/operstate)" = down ]
awk '$6 != "lo" { exit 1 }' /proc/net/if_inet6
cfg=/sys/kernel/config
phase='configfs'
mount -t configfs none "$cfg"
core="$cfg/target/core/fileio_0"
fabric="$cfg/target/iscsi"
target=iqn.2026-10.invalid.phantowd:lio-fixture
initiator=iqn.2026-10.invalid.phantowd:client
tpg="$fabric/$target/tpgt_1"
acl="$tpg/acls/$initiator"
peer_acl="$tpg/acls/iqn.2026-10.invalid.phantowd:peer"
client=/usr/libexec/phantowd-iscsi-fixture-client
backing=/run/phantowd-lio/backing,comma.img
mkdir "$fabric" "$core"
phase='seed-allocate'
dd if=/dev/zero of="$backing" bs=1M count=32
phase='seed-content'
printf '%s' PHANTOWD-LIO-SEED | dd of="$backing" conv=notrunc
phase='seed-size'
[ "$(wc -c < "$backing")" = 33554432 ]
phase='seed-pin'
exec 9<>"$backing"
phase='seed-replace'
mv "$backing" /run/phantowd-lio/original
printf '%s' REPLACEMENT > "$backing"
replacement_hash=$(sha256sum "$backing" | cut -d ' ' -f 1)
phase='descriptor-refusals'
exec 8<>/run/phantowd-lio/original
exec 8>&-
[ ! -e /proc/1/fd/8 ]
for descriptor in 8 1234; do
    mkdir "$core/refusal"
    printf 'fd_dev_name=/proc/self/fd/%s,fd_dev_size=33554432\n' "$descriptor" > "$core/refusal/control"
    if printf '1\n' > "$core/refusal/enable" 2>/run/phantowd-lio/refusal-error; then
        exit 1
    fi
    [ "$(cat "$core/refusal/enable")" = 0 ]
    rmdir "$core/refusal"
done
[ "$(sha256sum "$backing" | cut -d ' ' -f 1)" = "$replacement_hash" ]
echo 'PHANTOWD_LIO_DESCRIPTOR_READY closed_refused=true missing_refused=true recreated=false'
make_storage() {
    mkdir "$core/data"
    printf 'fd_dev_name=/proc/self/fd/9,fd_dev_size=33554432\n' > "$core/data/control"
    printf '1\n' > "$core/data/enable"
    printf '0\n' > "$core/data/attrib/emulate_fua_write"
    [ "$(cat "$core/data/enable")" = 1 ]
    [ "$(cat "$core/data/attrib/block_size")" = 512 ]
    [ "$(cat "$core/data/attrib/emulate_write_cache")" = 0 ]
    [ "$(cat "$core/data/attrib/emulate_fua_write")" = 0 ]
}
make_target() {
    mkdir "$fabric/$target" "$tpg"
    printf '1\n' > "$tpg/attrib/authentication"
    printf '0\n' > "$tpg/attrib/generate_node_acls"
    printf '0\n' > "$tpg/attrib/prod_mode_write_protect"
    printf 'CHAP\n' > "$tpg/param/AuthMethod"
    mkdir "$tpg/lun/lun_0"
    ln -s "$core/data" "$tpg/lun/lun_0/backing"
    mkdir "$acl" "$acl/lun_0"
    # Unlike numeric attributes, these string stores do not trim newlines.
    printf '%s' fixture > "$acl/auth/userid"
    printf '%s' synthetic-chap-only-2026 > "$acl/auth/password"
    ln -s "$tpg/lun/lun_0" "$acl/lun_0/grant"
    printf '0\n' > "$acl/lun_0/write_protect"
    mkdir "$tpg/np/127.0.0.1:3260"
    printf '1\n' > "$tpg/enable"
    [ "$(cat "$tpg/enable")" = 1 ]
    [ "$(cat "$tpg/attrib/authentication")" = 1 ]
    [ "$(cat "$tpg/attrib/generate_node_acls")" = 0 ]
}
listeners() {
    awk '$4 == "0A" { if ($2 != "0100007F:0CBC") exit 1; count++ } END { if (count != 1) exit 1 }' /proc/net/tcp
    if [ -f /proc/net/tcp6 ]; then
        awk '$4 == "0A" { exit 1 }' /proc/net/tcp6
    fi
}
remove_target() {
    printf '0\n' > "$tpg/enable"
    [ "$(cat "$tpg/enable")" = 0 ]
    rmdir "$tpg/np/127.0.0.1:3260"
    rm "$acl/lun_0/grant"
    rmdir "$acl/lun_0" "$acl"
    rm "$tpg/lun/lun_0/backing"
    rmdir "$tpg/lun/lun_0" "$tpg" "$fabric/$target"
    rmdir "$core/data"
}
phase=target
make_storage
make_target
listeners
phase=rw
"$client" rw
phase=session-revocation
"$client" hold &
session_pid=$!
attempt=0
while [ ! -f /run/phantowd-lio/session-ready ] && [ "$attempt" -lt 30 ]; do
    kill -0 "$session_pid"
    sleep 1
    attempt=$((attempt + 1))
done
[ -f /run/phantowd-lio/session-ready ]
if grep -q '^No active iSCSI Session' "$acl/info"; then exit 1; fi
printf '0\n' > "$tpg/enable"
[ "$(cat "$tpg/enable")" = 0 ]
grep -q '^No active iSCSI Session' "$acl/info"
touch /run/phantowd-lio/revoke
wait "$session_pid"
"$client" disabled
printf '1\n' > "$tpg/enable"
[ "$(cat "$tpg/enable")" = 1 ]
"$client" reenabled
rm /run/phantowd-lio/session-ready /run/phantowd-lio/revoke
echo 'PHANTOWD_LIO_SESSION_READY observed=true revoked=true admission_disabled=true reenabled_data=true'
phase=authentication-refusals
"$client" wrong
"$client" none
"$client" foreign
phase='readonly'
printf '1\n' > "$acl/lun_0/write_protect"
[ "$(cat "$acl/lun_0/write_protect")" = 1 ]
"$client" ro
[ "$(sha256sum "$backing" | cut -d ' ' -f 1)" = "$replacement_hash" ]
phase=mutual-authentication
grep -q '^No active iSCSI Session' "$acl/info"
printf '%s' fixture-target > "$acl/auth/userid_mutual"
printf '%s' synthetic-outbound-only-2026 > "$acl/auth/password_mutual"
[ "$(cat "$acl/auth/authenticate_target")" = 1 ]
"$client" mutual
"$client" mutual-target-wrong
"$client" mutual-user-wrong
"$client" mutual-inbound-wrong
if [ "$mutual_mode" = phantowd.lio_mutual=strict ]; then
    # Exact authentication refusal, not TCP failure or client verification.
    "$client" mutual-oneway-refused
else
    # Keep measuring upstream default behavior without claiming enforcement.
    "$client" mutual-oneway
fi
grep -q '^No active iSCSI Session' "$acl/info"
if [ "$mutual_mode" = phantowd.lio_mutual=strict ]; then
    echo 'PHANTOWD_LIO_MUTUAL_READY exchange=true wrong_target_refused=true wrong_user_refused=true wrong_inbound_refused=true oneway_refused=true enforcement=login-when-configured'
else
    echo 'PHANTOWD_LIO_MUTUAL_READY exchange=true wrong_target_refused=true wrong_user_refused=true wrong_inbound_refused=true oneway_still_accepted=true enforcement=false'
fi
phase=credential-rotation
printf '%s' synthetic-rotated-only-2026 > "$acl/auth/password"
"$client" rotated-old
"$client" rotated
grep -q '^No active iSCSI Session' "$acl/info"
echo 'PHANTOWD_LIO_ROTATION_READY no_active_session=true old_refused=true new_verified=true data_preserved=true durable=false'
phase=independent-peers
mkdir "$peer_acl" "$peer_acl/lun_0"
printf '%s' fixture-peer > "$peer_acl/auth/userid"
printf '%s' synthetic-peer-only-2026 > "$peer_acl/auth/password"
ln -s "$tpg/lun/lun_0" "$peer_acl/lun_0/grant"
printf '1\n' > "$peer_acl/lun_0/write_protect"
[ "$(cat "$peer_acl/lun_0/write_protect")" = 1 ]
"$client" peer-cross
printf '0\n' > "$acl/lun_0/write_protect"
[ "$(cat "$acl/lun_0/write_protect")" = 0 ]
"$client" primary-hold &
primary_pid=$!
"$client" peer-ro-hold &
peer_pid=$!
attempt=0
while { [ ! -f /run/phantowd-lio/primary-ready ] || [ ! -f /run/phantowd-lio/peer-ready ]; } && [ "$attempt" -lt 30 ]; do
    kill -0 "$primary_pid"
    kill -0 "$peer_pid"
    sleep 1
    attempt=$((attempt + 1))
done
[ -f /run/phantowd-lio/primary-ready ] && [ -f /run/phantowd-lio/peer-ready ]
if grep -q '^No active iSCSI Session' "$acl/info"; then exit 1; fi
if grep -q '^No active iSCSI Session' "$peer_acl/info"; then exit 1; fi
touch /run/phantowd-lio/peer-release
wait "$peer_pid"
grep -q '^No active iSCSI Session' "$peer_acl/info"
if grep -q '^No active iSCSI Session' "$acl/info"; then exit 1; fi
touch /run/phantowd-lio/primary-release
wait "$primary_pid"
grep -q '^No active iSCSI Session' "$acl/info"
rm /run/phantowd-lio/primary-ready /run/phantowd-lio/peer-ready /run/phantowd-lio/primary-release /run/phantowd-lio/peer-release
rm "$peer_acl/lun_0/grant"
rmdir "$peer_acl/lun_0" "$peer_acl"
[ "$(sha256sum "$backing" | cut -d ' ' -f 1)" = "$replacement_hash" ]
echo 'PHANTOWD_LIO_PEERS_READY concurrent=2 separate_credentials=true cross_credentials_refused=true primary_readwrite=true peer_readonly=true logout_independent=true data_preserved=true'
phase=unlink-rebind
remove_target
rm /run/phantowd-lio/original
[ "$(wc -c < /proc/1/fd/9)" = 33554432 ]
make_storage
make_target
listeners
"$client" check
[ ! -e /run/phantowd-lio/original ]
[ "$(sha256sum "$backing" | cut -d ' ' -f 1)" = "$replacement_hash" ]
phase=teardown
remove_target
rmdir "$core" "$fabric"
exec 9>&-
awk '$4 == "0A" { exit 1 }' /proc/net/tcp
if [ -f /proc/net/tcp6 ]; then awk '$4 == "0A" { exit 1 }' /proc/net/tcp6; fi
umount "$cfg"
rm "$backing" /run/phantowd-lio/refusal-error
rmdir /run/phantowd-lio
umount /run
echo 'PHANTOWD_LIO_READY chap=true access=ro-rw retained_fd=true replacement_unchanged=true unlinked_rebind=true size=33554432 block_size=512 write_cache=false teardown=true scope=disposable-qemu-only'
trap - EXIT
exec /sbin/reboot -f
