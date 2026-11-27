#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

[ "$#" -eq 3 ] || { echo 'Usage: qemu-rc0-samba-child.sh IMAGES_DIR HOST_GO LOG' >&2; exit 2; }
images=$1
host_go=$2
log=$3
qemu=${QEMU_SYSTEM_ARM:-qemu-system-arm}
support=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
for artifact in rootfs.ext2 zImage versatile-pb.dtb; do
    [ -f "$images/$artifact" ] && [ ! -L "$images/$artifact" ] || exit 1
done
image="$images/rootfs.ext2"
[ -z "$(debugfs -R 'stat /rc0-samba-fixture' "$image" 2>/dev/null)" ]
umask 077
scratch=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-rc0-samba.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 1' INT TERM
case "$scratch" in *[!a-zA-Z0-9_./:-]*) echo 'Unsupported fixture path' >&2; exit 1 ;; esac
sha256sum -- "$image" "$images/zImage" "$images/versatile-pb.dtb" > "$scratch/base.sha256"
root_copy="$scratch/rootfs.ext2"
virtual_data="$scratch/data.ext4"
cp --sparse=always -- "$image" "$root_copy"
truncate -s 24M "$virtual_data"
mkfs.ext4 -q -F "$virtual_data"
(
    cd "$support/../src/phantowd-api"
    CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 GOPROXY=off GOTOOLCHAIN=local GOWORK=off \
        "$host_go" build -mod=vendor -buildvcs=false -tags=qemu -trimpath -ldflags='-s -w' -o "$scratch/runner" ./cmd/rc0-samba-child-fixture
)
cat > "$scratch/init" <<'SH'
#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 022
mount -t proc proc /proc
mount -t sysfs sysfs /sys
test "$(tr -d '\000' < /sys/firmware/devicetree/base/model)" = 'ARM Versatile PB'
test "$(cat /sys/class/block/sdb/size)" = 49152
mount -t tmpfs -o mode=0755,nosuid,nodev,size=32m tmpfs /run
ifconfig lo 127.0.0.1 up
ifconfig lo:1 192.0.2.21 netmask 255.255.255.255 up
mkdir /run/data /run/rw /run/ro
mount -t ext4 -o rw,nosuid,nodev,noexec /dev/sdb /run/data
case " $(cat /proc/cmdline) " in
    *' phantowd.samba=prepare '*)
        phase=prepare
        mkdir -m 0700 /run/data/private /run/data/state /run/data/identities
        mkdir -m 0755 /run/data/writable /run/data/readonly
        echo 'rw marker' > /run/data/writable/marker
        echo 'ro marker' > /run/data/readonly/marker
        ;;
    *' phantowd.samba=verify '*) phase=verify ;;
    *) exit 1 ;;
esac
if ! /rc0-samba-fixture/runner "$phase"; then
    echo PHANTOWD_RC0_SAMBA_LAUNCH_FAILED
fi
if [ "$phase" = verify ]; then
    umount /run/ro
    umount /run/rw
fi
umount /run/data
sync
exec reboot -f
SH

debugfs -w -R 'mkdir /rc0-samba-fixture' "$root_copy"
for role in init runner; do
    dest="/rc0-samba-fixture/$role"
    debugfs -w -R "write $scratch/$role $dest" "$root_copy"
    debugfs -w -R "set_inode_field $dest mode 0100755" "$root_copy"
    debugfs -R "dump $dest $scratch/check-$role" "$root_copy"
    cmp -- "$scratch/$role" "$scratch/check-$role"
done
chmod a-w "$root_copy"
(umask 022; : > "$log")
for phase in prepare verify; do
    if ! timeout --signal=TERM --kill-after=5 70 "$qemu" \
    -M versatilepb -cpu arm926 -m 256M -nic none -serial stdio -display none -monitor none -no-reboot \
    -kernel "$images/zImage" -dtb "$images/versatile-pb.dtb" \
    -drive "file=$root_copy,if=none,id=rootdisk,format=raw,readonly=on" \
    -drive "file=$virtual_data,if=none,id=datadisk,format=raw,cache=writethrough" \
    -device lsi53c895a,id=scsi0 -device scsi-hd,bus=scsi0.0,drive=rootdisk,serial=RC0-SAMBA-ROOT \
    -device scsi-hd,bus=scsi0.0,drive=datadisk,serial=RC0-SAMBA-DISPOSABLE \
    -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 \
    -append "console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/rc0-samba-fixture/init phantowd.samba=$phase" > "$scratch/serial" 2>&1; then
        cat "$scratch/serial" >> "$log"
        tail -n 25 "$scratch/serial" >&2
        exit 1
    fi
    cat "$scratch/serial" >> "$log"
    case "$phase" in
        prepare) expected='PHANTOWD_RC0_NATIVE_GROUP persistent=recorded phase=group-confirmed' ;;
        verify) expected='PHANTOWD_RC0_SAMBA_CHILD actual_smbd=true native_reboot=verified image_accounts=untouched enrollment=verified disabled_login=refused protected_configuration=verified original_mounts=verified capabilities=verified anonymous=refused authenticated_rw=verified read_only=verified databases=retained owned_listener=verified restarted=verified ingress=staged-published-fenced-released unauthorized_stop=refused busy_stop=refused process_group=drained bad_handoffs=refused' ;;
    esac
    if ! awk -v expected="$expected" '{sub(/\r$/, "")} $0 == expected { n++ } END { exit n != 1 }' "$scratch/serial" ||
        ! grep -F 'reboot: Restarting system' "$scratch/serial" >/dev/null || grep -Eq 'PHANTOWD_RC0_SAMBA_LAUNCH_FAILED|Kernel panic' "$scratch/serial"; then
        tail -n 25 "$scratch/serial" >&2
        exit 1
    fi
    printf '%s\n' "$expected"
done
sha256sum -c "$scratch/base.sha256"
