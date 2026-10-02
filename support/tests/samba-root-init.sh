#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Disposable fixed-profile Samba proof, not product init or account migration.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
daemon_pid=
stop_attempted=0
stop_daemon() {
    [ -n "$daemon_pid" ] || return 0
    [ "$stop_attempted" -eq 0 ] || return 1
    stop_attempted=1
    /bin/busybox kill -TERM "-$daemon_pid" || return 1
    wait "$daemon_pid"
    stop_status=$?
    # Explicitly requested SIGTERM may be reported as 128+15 by BusyBox.
    # Neither outcome is accepted until the entire owned group is absent.
    if [ "$stop_status" -ne 0 ] && [ "$stop_status" -ne 143 ]; then
        echo "PHANTOWD_SAMBA_ROOT_STOP_WAIT_FAILED status=$stop_status"
        return 1
    fi
    i=0
    while /bin/busybox kill -0 "-$daemon_pid" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -lt 50 ] || {
            echo PHANTOWD_SAMBA_ROOT_STOP_GROUP_REMAINS
            return 1
        }
        sleep 0.1
    done
    daemon_pid=
    echo PHANTOWD_SAMBA_ROOT_STOPPED
}
client() {
    user=$1 share=$2 operation=$3
    /usr/sbin/phantowd-samba-root-launcher client "$user" "$share" "$operation" \
        >/run/client.log 2>&1
}
denied() {
    client "$1" "$2" "$3"
    status=$?
    [ "$status" -eq 1 ] || return 1
    grep -E "$4" /run/client.log >/dev/null || return 1
}
denied_mkdir() {
    # Pinned smbclient reports a failed mkdir in stdout but can exit zero.
    # This exception is only for these two fixed commands, not generic denial.
    case "$1:$2" in
        qpreader:reader-denied|qpoutsider:outsider-denied) ;;
        *) return 1 ;;
    esac
    client "$1" PosixACL "mkdir inherited/$2"
    status=$?
    case "$status" in 0|1) ;; *) return 1 ;; esac
    expected="NT_STATUS_ACCESS_DENIED making remote directory \\inherited\\$2"
    [ "$(grep '^NT_STATUS_' /run/client.log)" = "$expected" ] || return 1
    [ ! -e "/run/phantowd-samba-source/approved/inherited/$2" ] || return 1
}
run_fixture() {
    mount -t proc proc /proc || return 1
    mount -t sysfs sysfs /sys || return 1
    /usr/sbin/phantowd-samba-root-launcher guard || return 1
    grep -Eq '(^| )phantowd_samba_ext4_fixture=1( |$)' /proc/cmdline || return 1
    mount -t tmpfs -o mode=0755,size=96m tmpfs /run || return 1
    ifconfig lo up || return 1
    root=/run/phantowd-samba-root
    source=/run/phantowd-samba-source
    state=/run/phantowd-samba-state
    mkdir -m 0755 "$root" "$source" || return 1
    [ "$(cat /sys/block/sdb/size)" = 32768 ] || return 1
    [ -b /dev/sdb ] || return 1
    mount -t ext4 -o acl,nosuid,nodev,noexec /dev/sdb "$source" || return 1
    grep -F " /run/phantowd-samba-source ext4 " /proc/mounts >/dev/null || return 1
    mkdir -m 0700 "$state" || return 1
    mkdir -p "$source/approved" || return 1
    mkdir -m 0700 "$source/denied" || return 1
    while read -r digest canonical alias; do
        [ "$(readlink -f "$alias")" = "$canonical" ] || return 1
        [ "$(sha256sum "$alias" | cut -d ' ' -f1)" = "$digest" ] || return 1
        mkdir -p "$root$(dirname "$canonical")" || return 1
        if [ ! -f "$root$canonical" ]; then
            cp "$canonical" "$root$canonical" || return 1
            chmod 0555 "$root$canonical" || return 1
        fi
        [ "$(sha256sum "$root$canonical" | cut -d ' ' -f1)" = "$digest" ] || return 1
    done </usr/lib/phantowd/qemu-samba-root.manifest
    while read -r digest canonical alias; do
        if [ "$alias" != "$canonical" ]; then
            mkdir -p "$root$(dirname "$alias")" || return 1
            ln -s "$canonical" "$root$alias" || return 1
        fi
    done </usr/lib/phantowd/qemu-samba-root.manifest
    /usr/sbin/phantowd-samba-root-launcher runtime-bundle || return 1
    # Inspection does not authorize these separately generated state/grants.
    mkdir -p "$root/etc/samba" "$root/dev" "$root/state" "$root/tmp" \
        "$root/shares/rw" "$root/shares/ro" "$root/shares/denied" || return 1
    cp /usr/sbin/phantowd-samba-charset-probe \
        "$root/usr/sbin/phantowd-samba-charset-probe" || return 1
    chmod 0555 "$root/usr/sbin/phantowd-samba-charset-probe" || return 1
    printf '%s\n' 'root:x:0:0:root:/:/sbin/nologin' \
        'nobody:x:65534:65534:nobody:/:/sbin/nologin' \
        'qpwriter:x:1801:1800:writer:/:/sbin/nologin' \
        'qpreader:x:1802:1800:reader:/:/sbin/nologin' \
        'qpoutsider:x:1803:1800:outsider:/:/sbin/nologin' >"$root/etc/passwd"
    printf '%s\n' 'root:x:0:' 'nogroup:x:65534:' \
        'qpgroup:x:1800:qpwriter,qpreader,qpoutsider' >"$root/etc/group"
    printf '%s\n' 'passwd: files' 'group: files' 'shadow: files' \
        'hosts: files' 'networks: files' 'protocols: files' 'services: files' \
        >"$root/etc/nsswitch.conf"
    printf '%s\n' '127.0.0.1 localhost' >"$root/etc/hosts"
    printf '%s\n' 'tcp 6 TCP' 'udp 17 UDP' >"$root/etc/protocols"
    printf '%s\n' 'microsoft-ds 445/tcp' >"$root/etc/services"
    mknod -m 0666 "$root/dev/null" c 1 3 || return 1
    mknod -m 0666 "$root/dev/urandom" c 1 9 || return 1
    ln -s urandom "$root/dev/random" || return 1
    for name in private lock state cache pid rpc; do
        mkdir -m 0700 "$state/$name" || return 1
    done
    # Generated fixture config: one fixed, hash-verified streams module only.
    # This remains native Unix ownership, not Windows ACL qualification.
    printf '%s\n' '[global]' 'server role = standalone server' \
        'security = user' 'map to guest = Never' \
        'interfaces = 127.0.0.1' 'bind interfaces only = yes' 'smb ports = 1445' \
        'server min protocol = SMB3_00' 'server max protocol = SMB3_11' \
        'server signing = mandatory' 'load printers = no' 'printing = bsd' \
        'dos charset = CP850' 'unix charset = UTF-8' \
        'map archive = no' 'map system = no' 'map hidden = no' \
        'store dos attributes = yes' \
        'printcap name = /dev/null' 'disable spoolss = yes' 'dns proxy = no' \
        'name resolve order = host' 'vfs objects = streams_xattr' \
        'streams_xattr:prefix = user.DosStream.' \
        'streams_xattr:store_stream_type = yes' 'log file = /state/log.smbd' \
        'private dir = /state/private' 'lock directory = /state/lock' \
        'state directory = /state/state' 'cache directory = /state/cache' \
        'pid directory = /state/pid' 'ncalrpc dir = /state/rpc' \
        'passdb backend = tdbsam:/state/private/passdb.tdb' \
        '[ReadWrite]' 'path = /shares/rw' 'guest ok = no' 'read only = yes' \
        'valid users = qpwriter qpreader' 'read list = qpreader' \
        'write list = qpwriter' 'follow symlinks = no' 'wide links = no' \
        'create mask = 0660' 'directory mask = 0770' \
        '[KernelReadOnly]' 'path = /shares/ro' 'guest ok = no' \
        'read only = no' 'valid users = qpwriter' 'follow symlinks = no' \
        '[UnixDenied]' 'path = /shares/denied' 'guest ok = no' \
        'read only = no' 'valid users = qpwriter' \
        '[PosixACL]' 'path = /shares/rw' 'guest ok = no' \
        'read only = no' 'valid users = qpwriter qpreader qpoutsider' \
        '[OriginalAnchor]' 'path = /run/phantowd-samba-source/approved' \
        'guest ok = no' 'read only = no' 'valid users = qpwriter' \
        >"$root/etc/samba/smb.conf"
    chmod 0600 "$root/etc/samba/smb.conf" || return 1
    chown 1801:1800 "$source/approved" || return 1
    chmod 2770 "$source/approved" || return 1
    echo 'outside-selected-subtree' >"$source/ungranted"
    ln -s "$source/ungranted" "$source/approved/escape" || return 1
    /usr/sbin/phantowd-samba-root-launcher charset || return 1
    echo 'distinct-unix-writer-test' >/run/upload
    echo 'distinct-stream-fixture' >/run/upload-stream
    echo 'posix-acl-fixture' >/run/acl-expected
    for user in qpwriter qpreader qpoutsider; do
        # Public disposable credential, stdin/auth files only, never argv.
        printf '%s\n' 'disposable-qemu-only' 'disposable-qemu-only' | \
            /usr/sbin/phantowd-samba-root-launcher enroll "$user" \
            >/run/enroll.log 2>&1 || { cat /run/enroll.log; return 1; }
        printf 'username = %s\npassword = disposable-qemu-only\n' "$user" \
            >"/run/$user.auth"
        chmod 0600 "/run/$user.auth" || return 1
    done
    printf '%s\n' 'username = qpwriter' 'password = wrong-fixture-only' \
        >/run/qpwrong.auth
    chmod 0600 /run/qpwrong.auth || return 1
    /usr/sbin/phantowd-samba-root-launcher server </dev/null \
        >/run/server.log 2>&1 &
    daemon_pid=$!
    i=0
    while ! client qpwriter ReadWrite ls; do
        kill -0 "$daemon_pid" || { cat /run/server.log; return 1; }
        i=$((i + 1))
        [ "$i" -lt 15 ] || return 1
        sleep 0.2
    done
    grep -F 'PHANTOWD_SAMBA_ROOT_BOUNDARY_READY caps=00000000000000db nnp=true original_denied=true kernel_ro=true' /run/server.log || return 1
    grep -E '^Cap(Eff|Prm|Bnd):[[:space:]]+00000000000000db$' "/proc/$daemon_pid/status" |
        grep -c '^Cap' | grep -x 3 >/dev/null || return 1
    grep -E '^NoNewPrivs:[[:space:]]+1$' "/proc/$daemon_pid/status" >/dev/null || return 1
    [ "$(readlink "/proc/$daemon_pid/root")" = "$root" ] || return 1
    [ "$(readlink "/proc/$daemon_pid/ns/mnt")" != "$(readlink /proc/1/ns/mnt)" ] || return 1
    client qpwriter ReadWrite 'put /run/upload created' || { cat /run/client.log; return 1; }
    cmp /run/upload "$source/approved/created" || return 1
    /usr/sbin/phantowd-samba-root-launcher ownership || return 1
    client qpreader ReadWrite 'get created /run/download' || return 1
    cmp /run/upload /run/download || return 1
    client qpwriter ReadWrite 'put /run/upload created-é-β' || return 1
    client qpreader ReadWrite 'get created-é-β /run/download-unicode' || return 1
    cmp /run/upload /run/download-unicode || return 1
    client qpwriter ReadWrite 'put /run/upload-stream created:fixture' || return 1
    client qpreader ReadWrite 'get created:fixture /run/download-stream' || return 1
    cmp /run/upload-stream /run/download-stream || return 1
    cmp /run/upload "$source/approved/created" || return 1
    /usr/sbin/phantowd-samba-root-launcher stream-bytes || return 1
    [ ! -e "$source/approved/created:fixture" ] || return 1
    # Different rejected bytes make an accidental overwrite observable.
    denied qpreader ReadWrite 'put /run/upload created:fixture' \
        'NT_STATUS_ACCESS_DENIED' || return 1
    denied qpwriter KernelReadOnly 'put /run/upload created:fixture' \
        'NT_STATUS_(MEDIA_WRITE_PROTECTED|ACCESS_DENIED)' || return 1
    /usr/sbin/phantowd-samba-root-launcher stream-bytes || return 1
    cmp /run/upload "$source/approved/created" || return 1
    echo 'PHANTOWD_SAMBA_ROOT_STREAMS_READY module=streams_xattr xattr_bytes=true reader_write_denied=true kernel_ro=true scope=qemu-only'
    /usr/sbin/phantowd-samba-root-launcher acl-prepare || return 1
    denied qpreader PosixACL 'get acl-created /run/download-acl' \
        'NT_STATUS_ACCESS_DENIED' || return 1
    /usr/sbin/phantowd-samba-root-launcher acl-grant || return 1
    client qpreader PosixACL 'get acl-created /run/download-acl' || return 1
    cmp /run/acl-expected /run/download-acl || return 1
    denied qpreader PosixACL 'put /run/upload acl-created' \
        'NT_STATUS_ACCESS_DENIED' || return 1
    denied qpoutsider PosixACL 'get acl-created /run/download-acl' \
        'NT_STATUS_ACCESS_DENIED' || return 1
    /usr/sbin/phantowd-samba-root-launcher acl-revoke || return 1
    denied qpreader PosixACL 'get acl-created /run/download-acl' \
        'NT_STATUS_ACCESS_DENIED' || return 1
    cmp /run/acl-expected "$source/approved/acl-created" || return 1
    echo 'PHANTOWD_SAMBA_ROOT_POSIX_ACL_READY fs=ext4 bytes=true named_reader=true outsider_denied=true mask_revocation=true scope=qemu-only'
    /usr/sbin/phantowd-samba-root-launcher inheritance-prepare || return 1
    client qpwriter PosixACL 'mkdir inherited/child' || return 1
    client qpwriter PosixACL 'put /run/upload inherited/child/data' || return 1
    /usr/sbin/phantowd-samba-root-launcher inheritance-verify || return 1
    client qpreader PosixACL 'get inherited/child/data /run/download-inherited' || return 1
    cmp /run/upload /run/download-inherited || return 1
    client qpreader PosixACL 'allinfo inherited/child/data' || return 1
    grep -Ex 'attributes: A \(20\)' /run/client.log >/dev/null || return 1
    denied qpreader PosixACL 'put /run/upload-stream inherited/child/data' 'NT_STATUS_ACCESS_DENIED' || return 1
    denied_mkdir qpreader reader-denied || return 1
    denied qpoutsider PosixACL 'get inherited/child/data /run/download-inherited' 'NT_STATUS_ACCESS_DENIED' || return 1
    denied_mkdir qpoutsider outsider-denied || return 1
    /usr/sbin/phantowd-samba-root-launcher inheritance-verify || return 1
    cmp /run/upload "$source/approved/inherited/child/data" || return 1
    [ ! -e "$source/approved/inherited/reader-denied" ] || return 1
    [ ! -e "$source/approved/inherited/outsider-denied" ] || return 1
    echo 'PHANTOWD_SAMBA_ROOT_INHERITANCE_READY fs=ext4 directory_acl=true file_acl=true setgid=true reader_write_denied=true outsider_denied=true scope=qemu-only'
    denied qpwrong ReadWrite ls 'NT_STATUS_LOGON_FAILURE' || return 1
    denied qpreader ReadWrite 'put /run/upload reader-denied' 'NT_STATUS_ACCESS_DENIED' || return 1
    denied qpoutsider ReadWrite ls 'NT_STATUS_ACCESS_DENIED' || return 1
    denied qpwriter KernelReadOnly 'put /run/upload readonly-denied' \
        'NT_STATUS_(MEDIA_WRITE_PROTECTED|ACCESS_DENIED)' || return 1
    denied qpwriter OriginalAnchor ls 'NT_STATUS_BAD_NETWORK_NAME' || return 1
    denied qpwriter UnixDenied 'put /run/upload unix-denied' 'NT_STATUS_ACCESS_DENIED' || return 1
    denied qpwriter ReadWrite 'get escape /run/escaped' 'NT_STATUS_STOPPED_ON_SYMLINK' || return 1
    for file in reader-denied readonly-denied native-denied; do
        [ ! -e "$source/approved/$file" ] || return 1
    done
    [ ! -e /run/escaped ] || return 1
    [ ! -e "$source/denied/unix-denied" ] || return 1
    echo 'PHANTOWD_SAMBA_ROOT_POLICY_READY writer_uid=1801 reader_uid=1802 outsider_denied=true kernel_ro=true original_denied=true unix_ownership=true unix_denial=true utf8_roundtrip=true scope=qemu-only'
    stop_daemon || return 1
    # Neither the direct conversion nor Samba may hide missing runtime support.
    for log in /run/server.log /run/enroll.log "$state/log.smbd"; do
        [ -f "$log" ] || return 1
        if grep -Ei 'ASCII|conversion.*(not supported|failed)|unable to convert' "$log"; then
            return 1
        fi
    done
    echo PHANTOWD_SAMBA_ROOT_DONE
}
if ! run_fixture; then
    echo PHANTOWD_SAMBA_ROOT_FAILED
    [ ! -e /run/client.log ] || cat /run/client.log
    [ ! -e /run/server.log ] || tail -n 80 /run/server.log
    [ ! -e /run/phantowd-samba-state/log.smbd ] || tail -n 80 /run/phantowd-samba-state/log.smbd
    stop_daemon || true
fi
sync
reboot -f
