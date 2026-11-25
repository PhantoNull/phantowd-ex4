#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

[ "$#" -eq 3 ] || { echo 'Usage: qemu-rc0-management.sh IMAGES_DIR HOST_GO LOG_PREFIX' >&2; exit 2; }
images=$1
host_go=$2
log_prefix=$3
qemu=${QEMU_SYSTEM_ARM:-qemu-system-arm}
support=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
for name in rootfs.ext2 zImage versatile-pb.dtb; do
    [ -f "$images/$name" ] && [ ! -L "$images/$name" ] || exit 1
done
[ -z "$(debugfs -R 'stat /rc0-fixture' "$images/rootfs.ext2" 2>/dev/null)" ]

umask 077
scratch=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-rc0-management.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 1' INT TERM
case "$scratch" in *[!a-zA-Z0-9_./:-]*) echo 'Unsupported fixture path' >&2; exit 1 ;; esac
sha256sum -- "$images/rootfs.ext2" "$images/zImage" "$images/versatile-pb.dtb" > "$scratch/base.sha256"
image="$scratch/rootfs.ext2"
data="$scratch/virtual-state.ext4"
cp --sparse=always -- "$images/rootfs.ext2" "$image"
truncate -s 32M "$data"
mkfs.ext4 -F -q "$data"
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 GOPROXY=off GOTOOLCHAIN=local GOWORK=off \
    "$host_go" build -trimpath -ldflags='-s -w' -o "$scratch/runner" "$support/fixtures/rc0-management.go"
od -An -N24 -tx1 /dev/urandom | tr -d ' \n' > "$scratch/password"
[ "$(wc -c < "$scratch/password")" -eq 48 ]
cat > "$scratch/init" <<'SH'
#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
test "$(tr -d '\000' < /sys/firmware/devicetree/base/model)" = 'ARM Versatile PB'
test "$(cat /sys/class/block/sdb/size)" = 65536
case "$(cat /sys/class/misc/hw_random/rng_current)" in
    virtio_rng.*) ;;
    *) echo 'RC0 fixture requires the virtual entropy source' >&2; exit 1 ;;
esac
mount -t tmpfs -o mode=0755,size=64m tmpfs /run
mount -t ext4 /dev/sdb /mnt
ifconfig lo 127.0.0.1 up
case "$(cat /proc/cmdline)" in
    *' phantowd.state=seed') phase=seed ;;
    *' phantowd.state=verify') phase=verify ;;
    *' phantowd.state=rotated') phase=rotated ;;
    *) exit 1 ;;
esac
/rc0-fixture/runner "$phase" || echo PHANTOWD_RC0_SUPERVISOR_FAILED
umount /mnt
echo "PHANTOWD_RC0_STATE_UNMOUNTED phase=$phase"
reboot -f
SH

debugfs -w -R 'mkdir /rc0-fixture' "$image"
install_fixture() {
    target="/rc0-fixture/$1"
    debugfs -w -R "write $scratch/$1 $target" "$image"
    debugfs -w -R "set_inode_field $target mode $2" "$image"
    debugfs -R "dump $target $scratch/check-$1" "$image"
    cmp -- "$scratch/$1" "$scratch/check-$1"
}
install_fixture runner 0100755
install_fixture init 0100755
install_fixture password 0100600
chmod a-w "$image"

for phase in seed verify rotated; do
    log="$log_prefix.$phase.log"
    # The hosted reader has a different UID. Keep the fixture inputs private.
    (umask 022; : > "$log")
    if ! timeout --signal=TERM --kill-after=5 75 "$qemu" \
        -M versatilepb -cpu arm926 -m 256M -display none -serial stdio -monitor none -no-reboot -nic none \
        -kernel "$images/zImage" -dtb "$images/versatile-pb.dtb" \
        -drive "file=$image,if=none,id=rootdisk,format=raw,readonly=on" \
        -device lsi53c895a,id=scsi0 -device scsi-hd,bus=scsi0.0,drive=rootdisk,serial=RC0-ROOT \
        -drive "file=$data,if=none,id=statedisk,format=raw,cache=writethrough" \
        -device scsi-hd,bus=scsi0.0,drive=statedisk,serial=RC0-STATE \
        -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 \
        -append "console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/rc0-fixture/init phantowd.state=$phase" \
        > "$log" 2>&1; then
        tail -n 25 "$log" >&2
        exit 1
    fi
    expected="PHANTOWD_RC0_SUPERVISOR_READY phase=$phase https_login=true tls=local_provisioned policy=confirmed same_file=refused wrong_bytes=refused synthetic_state=true clean_stop=true"
    if ! awk -v ready="$expected" -v stopped="PHANTOWD_RC0_STATE_UNMOUNTED phase=$phase" '
        { sub(/\r$/, "") }
        $0 == ready { startup++ }
        $0 == stopped { unmount++ }
        END { exit !(startup == 1 && unmount == 1) }
    ' "$log" || ! grep -F 'reboot: Restarting system' "$log" >/dev/null ||
        grep -Eq 'PHANTOWD_RC0_SUPERVISOR_FAILED|Kernel panic' "$log"; then
        tail -n 25 "$log" >&2
        exit 1
    fi
    printf '%s\n' "$expected"
done

fingerprint() {
    awk -v prefix="PHANTOWD_RC0_TLS_CERTIFICATE phase=$2 sha256=" '
        { sub(/\r$/, "") }
        index($0, prefix) == 1 {
            digest = substr($0, length(prefix) + 1)
            if (length(digest) != 64 || digest !~ /^[0-9a-f]+$/) exit 1
            seen++
        }
        END { if (seen != 1) exit 1; print digest }
    ' "$1"
}
original=$(fingerprint "$log_prefix.seed.log" seed)
reopened=$(fingerprint "$log_prefix.verify.log" verify)
replacement=$(fingerprint "$log_prefix.verify.log" replacement)
rotated=$(fingerprint "$log_prefix.rotated.log" rotated)
if [ "$original" != "$reopened" ] || [ "$original" = "$replacement" ] || [ "$replacement" != "$rotated" ]; then
    echo 'RC0 did not retain both authenticated TLS generations across boots' >&2
    exit 1
fi
tr -d '\r' < "$log_prefix.verify.log" |
    grep -Fx 'PHANTOWD_RC0_TLS_ROTATION live=refused wrong_fingerprint=refused stale=refused replacement=published' >/dev/null
echo 'PHANTOWD_RC0_TLS_PERSISTENCE initial=verified replacement=verified'
sha256sum -c "$scratch/base.sha256"
