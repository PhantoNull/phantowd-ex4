#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

[ "$#" -eq 3 ] || { echo 'Usage: qemu-rc0-profile.sh IMAGES_DIR HOST_GO LOG' >&2; exit 2; }
images=$1
host_go=$2
log=$3
qemu=${QEMU_SYSTEM_ARM:-qemu-system-arm}
for name in rootfs.ext2 zImage versatile-pb.dtb; do
    if [ ! -f "$images/$name" ] || [ -L "$images/$name" ]; then
        echo "Missing RC0 image input: $name" >&2
        exit 1
    fi
done

scratch=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-rc0-profile.XXXXXX")
pid=
# shellcheck disable=SC2317 # invoked through trap
cleanup() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -f "$scratch/api" "$scratch/buildinfo" "$scratch/rootfs.ext2" "$scratch/check-nfs"
    rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

stat_path() {
    debugfs -R "stat $1" "$images/rootfs.ext2" 2>/dev/null
}
[ -n "$(stat_path /usr/sbin/nft)" ] || { echo 'Missing RC0 nftables executable' >&2; exit 1; }
[ -n "$(stat_path /usr/bin/phantowd-api)" ]
[ -n "$(stat_path /etc/init.d/S51phantowd-management)" ]
for helper in /usr/sbin/rpcbind /usr/sbin/rpc.mountd /usr/sbin/rpc.nfsd /usr/sbin/exportfs /usr/bin/rpcinfo; do
    [ -n "$(stat_path "$helper")" ] || { echo "Missing RC0 NFS helper: $helper" >&2; exit 1; }
done
for path in /usr/lib/phantowd /etc/default/phantowd-api /etc/exports /etc/samba/smb.conf \
    /etc/init.d/S02phantowd-mdev /etc/init.d/S40phantowd-storage-broker \
    /etc/init.d/S30rpcbind /etc/init.d/S60nfs /etc/init.d/S99rc0-nfs-check \
    /etc/init.d/S49phantowd-dev-state /etc/init.d/S49phantowd-identity-owner \
    /etc/init.d/S49phantowd-nas-policy-owner /etc/init.d/S50phantowd-api \
    /etc/init.d/S91smb /etc/init.d/S99phantowd-ready; do
    if [ -n "$(stat_path "$path")" ]; then
        echo "Unexpected development payload in RC0: $path" >&2
        exit 1
    fi
done
[ "$(debugfs -R 'cat /etc/phantowd/product-profile' "$images/rootfs.ext2" 2>/dev/null)" = rc0 ]
release=$(debugfs -R 'cat /etc/phantowd-release' "$images/rootfs.ext2" 2>/dev/null)
printf '%s\n' "$release" | grep -Fx 'PHANTOWD_FLASHABLE=no' >/dev/null
printf '%s\n' "$release" | grep -Fx 'PHANTOWD_INSTALLABLE=no' >/dev/null
debugfs -R "dump /usr/bin/phantowd-api $scratch/api" "$images/rootfs.ext2" >/dev/null 2>&1
"$host_go" version -m "$scratch/api" > "$scratch/buildinfo"
grep -Eq '^[[:space:]]+build[[:space:]]+GOARCH=arm$' "$scratch/buildinfo"
grep -Eq '^[[:space:]]+build[[:space:]]+GOARM=5(,softfloat)?$' "$scratch/buildinfo"
if grep -Eq '^[[:space:]]+build[[:space:]]+-tags=.*qemu' "$scratch/buildinfo"; then
    echo 'RC0 API contains the QEMU build tag' >&2
    exit 1
fi

case "$scratch" in *[!a-zA-Z0-9_./:-]*) echo 'Unsupported fixture path' >&2; exit 1 ;; esac
image="$scratch/rootfs.ext2"
cp --sparse=always -- "$images/rootfs.ext2" "$image"
cat > "$scratch/check-nfs" <<'SH'
#!/bin/sh
check_nfs() {
    if pidof rpcbind rpc.mountd rpc.statd rpc.nfsd nfsd >/dev/null 2>&1; then
        return 1
    fi
    for family in tcp udp; do
        [ -r "/proc/net/$family" ] || return 1
        for table in "/proc/net/$family" "/proc/net/${family}6"; do
            [ -e "$table" ] || continue
            awk -v family="$family" 'NR > 1 && $2 ~ /:(006F|0801)$/ && (family == "udp" || $4 == "0A") { active=1 } END { exit active }' "$table" || return 1
        done
    done
    mount -t nfsd -o ro nfsd /proc/fs/nfsd || return 1
    threads=$(cat /proc/fs/nfsd/threads) && versions=$(cat /proc/fs/nfsd/versions) &&
        ports=$(cat /proc/fs/nfsd/portlist) &&
        awk '/^[[:space:]]*[^#[:space:]]/ { exported=1 } END { exit exported }' /proc/fs/nfsd/exports &&
        [ "$threads" = 0 ] && [ "$versions" = +3 ] && [ -z "$ports" ] || return 1
    umount /proc/fs/nfsd
}
if check_nfs; then
    echo 'PHANTOWD_RC0_NFS_DORMANT version=3 threads=0 rpc=absent listeners=absent exports=empty'
else
    echo 'PHANTOWD_RC0_NFS_ERROR dormant NFSD/RPC verification failed'
    exit 1
fi
SH
debugfs -w -R "write $scratch/check-nfs /etc/init.d/S99rc0-nfs-check" "$image" >/dev/null
debugfs -w -R 'set_inode_field /etc/init.d/S99rc0-nfs-check mode 0100755' "$image" >/dev/null

: > "$log"
"$qemu" -M versatilepb -cpu arm926 -m 256M \
    -kernel "$images/zImage" -dtb "$images/versatile-pb.dtb" \
    -drive "file=$image,if=none,id=rootdisk,format=raw,snapshot=on" \
    -device lsi53c895a,id=scsi0 -device scsi-hd,bus=scsi0.0,drive=rootdisk \
    -append 'rootwait root=/dev/sda console=ttyAMA0,115200' \
    -display none -serial stdio -monitor none -nic none -no-reboot > "$log" 2>&1 &
pid=$!
attempt=0
while [ "$attempt" -lt 60 ]; do
    if grep -E 'Kernel panic|PHANTOWD_QEMU_(READY|ERROR)|PHANTOWD_API_READY|PHANTOWD_RC0_NFS_ERROR' "$log" >/dev/null; then
        break
    fi
    if grep -F 'phantowd-rc0 login:' "$log" >/dev/null &&
        grep -F 'PhantoWD RC0 research image' "$log" >/dev/null &&
        grep -F 'PhantoWD management waiting for admitted boot state' "$log" >/dev/null &&
        awk '{ sub(/\r$/, "") } $0=="PHANTOWD_RC0_NFS_DORMANT version=3 threads=0 rpc=absent listeners=absent exports=empty" { n++ } END { exit(n!=1) }' "$log"; then
        echo 'PHANTOWD_RC0_PROFILE_READY boot=busybox fixtures=absent flashable=no installable=no'
        exit 0
    fi
    kill -0 "$pid" 2>/dev/null || break
    attempt=$((attempt + 1))
    sleep 1
done
tail -n 35 "$log" >&2
echo 'RC0 profile did not reach its expected serial login prompt' >&2
exit 1
