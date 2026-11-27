#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Run an RC0 normal-init file service over a private Ethernet socketpair."""
from contextlib import ExitStack
from pathlib import Path
import socket
import subprocess
import sys
import time


MARKERS = {
    "server": (
        "PHANTOWD_RC0_NFS_SERVER boot=init nftables=verified mounted_stop=refused "
        "https=preserved write=verified squash=verified drain=confirmed release=verified",
        "PHANTOWD_RC0_STATE_UNMOUNTED phase=nfs-server",
    ),
    "client": (
        "PHANTOWD_RC0_NFS_CLIENT transport=nfs3-tcp unlisted=dropped "
        "read=verified fsync=verified unmount=verified",
    ),
}
SMB_CLIENT = (
    "PHANTOWD_RC0_SMB_CLIENT read=verified write=verified authenticated=verified "
    "new_connection=dropped fenced_read=verified"
)
SMB_ENROLLMENT = (
    "PHANTOWD_RC0_SMB_ENROLLMENT cli=verified early_enable=refused "
    "replacement=refused live_state=refused"
)
PAIRS = {
    "nfs": MARKERS,
    "smb": {
        "server": (
            SMB_ENROLLMENT,
            "PHANTOWD_RC0_SMB_SERVER boot=init storage=approved busy_stop=refused "
            "https=preserved drain=verified release=verified",
            "PHANTOWD_RC0_STATE_UNMOUNTED phase=smb-server",
        ),
        "client": (SMB_CLIENT,),
    },
    "smb-legacy": {
        "server": (
            SMB_ENROLLMENT,
            "PHANTOWD_RC0_SMB_LEGACY_SERVER boot=init storage=approved "
            "busy_stop=refused https=preserved unqualified=refused",
        ),
        "client": (SMB_CLIENT,),
    },
    "smb-loss": {
        "server": (
            SMB_ENROLLMENT,
            "PHANTOWD_RC0_SMB_LOSS_SERVER boot=init leader=lost ingress=quarantined "
            "https=preserved stop=review grant=retained",
        ),
        "client": ("PHANTOWD_RC0_SMB_LOSS_CLIENT read=verified write=verified new_connection=dropped",),
    },
}


def check_guest(protocol, role, code, log):
    lines = log.read_text(errors="replace").splitlines()
    if (code or any(lines.count(marker) != 1 for marker in PAIRS[protocol][role])
            or not any("reboot: Restarting system" in line for line in lines)
            or any("PHANTOWD_RC0_SUPERVISOR_FAILED" in line or
                   "Kernel panic" in line for line in lines)):
        print("\n".join(lines[-32:]), file=sys.stderr)
        raise RuntimeError(f"RC0 {protocol} {role} fixture failed")


def run(qemu, kernel, root, state, data, output, protocol="nfs"):
    workers = {}
    try:
        with ExitStack() as stack:
            endpoints = socket.socketpair()
            for index, (role, endpoint) in enumerate(zip(PAIRS[protocol], endpoints), 1):
                stack.enter_context(endpoint)
                fd = endpoint.fileno()
                log = Path(f"{output}.{protocol}-{role}.log")
                capture = stack.enter_context(log.open("wb"))
                args = [
                    qemu, "-M", "versatilepb", "-cpu", "arm926", "-m", "256M",
                    "-display", "none", "-serial", "stdio", "-monitor", "none",
                    "-no-reboot", "-nic", "none",
                    "-kernel", str(kernel / "zImage"),
                    "-dtb", str(kernel / "versatile-pb.dtb"),
                    "-drive", f"file={root},if=none,id=root,format=raw,readonly=on",
                    "-device", "lsi53c895a,id=scsi0",
                    "-device", "scsi-hd,bus=scsi0.0,drive=root,serial=RC0-ROOT",
                    "-object", "rng-random,id=rng,filename=/dev/urandom",
                    "-device", "virtio-rng-pci,rng=rng",
                    "-netdev", f"socket,id=peer,fd={fd}",
                    "-device", f"rtl8139,netdev=peer,mac=52:54:00:12:34:0{index},romfile=",
                    "-append", "console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 "
                    f"init=/rc0-fixture/init phantowd.state={protocol}-{role}",
                ]
                if role == "server":
                    args.extend([
                        "-drive", f"file={state},if=none,id=statedisk,format=raw,cache=writethrough",
                        "-device", "scsi-hd,bus=scsi0.0,drive=statedisk,serial=RC0-STATE",
                        "-drive", f"file={data},if=none,id=datadisk,format=raw,cache=writethrough",
                        "-device", "scsi-hd,bus=scsi0.0,drive=datadisk,"
                        "serial=PHANTOWD-RC0-FIXTURE-DATA,wwn=0x500f000000000003,device_id=PHANTOWD-RC0-DATA",
                    ])
                workers[role] = (
                    subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=capture,
                                     stderr=subprocess.STDOUT, pass_fds=(fd,)),
                    log,
                )
        deadline = time.monotonic() + (95 if protocol == "nfs" else 205)
        pending = set(workers)
        while pending:
            for role in tuple(pending):
                worker, log = workers[role]
                code = worker.poll()
                if code is not None:
                    check_guest(protocol, role, code, log)
                    pending.remove(role)
            if pending:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"RC0 {protocol} guest deadline expired")
                time.sleep(0.1)
        prefix = protocol.replace("-", "_").upper()
        print(f"PHANTOWD_RC0_{prefix}_READY guests=2 normal_init=true nftables=true host_network=none")
    finally:
        for worker, _ in workers.values():
            if worker.poll() is None:
                worker.kill()
            worker.wait(timeout=10)


if __name__ == "__main__":
    _, executable, images, rootfs, state_disk, data_disk, logs, *mode = sys.argv
    protocol = mode[0] if mode else "nfs"
    if len(mode) > 1 or protocol not in PAIRS:
        sys.exit("Invalid RC0 network fixture")
    try:
        run(executable, Path(images), rootfs, state_disk, data_disk, logs, protocol)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
