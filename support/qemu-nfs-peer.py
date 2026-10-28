#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Real NFS client/server guests, isolated by inherited Unix socketpair FDs."""
import hashlib
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def run(images, log):
    files = [images / n for n in ("rootfs.ext2", "zImage", "versatile-pb.dtb")]
    if any(not p.is_file() or p.is_symlink() for p in files):
        raise RuntimeError("peer fixture requires regular image files")
    original = hashlib.sha256(files[0].read_bytes()).digest()
    processes, outputs = [], []
    with tempfile.TemporaryDirectory(prefix="phantowd-nfs-peer-") as scratch:
        root = Path(scratch) / "rootfs.ext2"
        shutil.copyfile(files[0], root)
        init = Path(__file__).parent / "fixtures/nfs-peer-init.sh"
        for request in (f"write {init} /nfs-peer-init",
                        "set_inode_field /nfs-peer-init mode 0100755"):
            subprocess.run(["debugfs", "-w", "-R", request, str(root)],
                           check=True, timeout=10, capture_output=True)
        endpoints = socket.socketpair()
        try:
            for index, role in enumerate(("server", "client")):
                output = open(f"{log}.{role}", "wb")
                outputs.append(output)
                fd = endpoints[index].fileno()
                args = [os.environ.get("QEMU_SYSTEM_ARM", "qemu-system-arm"),
                        "-M", "versatilepb", "-cpu", "arm926", "-m", "256M",
                        "-kernel", str(files[1]), "-dtb", str(files[2]),
                        "-drive", f"file={root},if=none,id=root,format=raw",
                        "-device", "lsi53c895a,id=scsi0", "-device",
                        "scsi-hd,bus=scsi0.0,drive=root", "-snapshot",
                        "-object", "rng-random,id=rng,filename=/dev/urandom",
                        "-device", "virtio-rng-pci,rng=rng",
                        "-append", "rootwait root=/dev/sda rw console=ttyAMA0 "
                        f"init=/nfs-peer-init phantowd_nfs_peer={role}",
                        "-display", "none", "-serial", "stdio", "-monitor",
                        "none", "-no-reboot", "-nic", "none", "-netdev",
                        f"socket,id=peer,fd={fd}", "-device",
                        "rtl8139,netdev=peer,"
                        f"mac=52:54:00:12:34:0{index+1},romfile="]
                processes.append(subprocess.Popen(
                    args, stdin=subprocess.DEVNULL, stdout=output,
                    stderr=subprocess.STDOUT, pass_fds=(fd,)))
            for endpoint in endpoints:
                endpoint.close()
            deadline = time.monotonic() + 180
            for role, process in zip(("server", "client"), processes):
                if process.wait(timeout=max(0.1, deadline-time.monotonic())):
                    raise RuntimeError("NFS peer guest failed")
                text = Path(f"{log}.{role}").read_text(errors="replace")
                marker = (
                    "PHANTOWD_NFS_PEER_SERVER_READY kernel_backend=true "
                    "activation=true remote_bytes=true teardown=clean "
                    "scope=isolated-two-guest-only" if role == "server" else
                    "PHANTOWD_NFS_PEER_CLIENT_READY protocol=nfs3 "
                    "transport=tcp "
                    "read=true write=true fsync=true unmount=clean "
                    "scope=isolated-two-guest-only")
                if text.count(marker) != 1 or any(word in text for word in (
                        "PHANTOWD_NFS_PEER_ERROR", "Kernel panic")):
                    raise RuntimeError(
                        f"NFS peer {role} proof missing or failed")
            if hashlib.sha256(files[0].read_bytes()).digest() != original:
                raise RuntimeError("NFS peer fixture changed base root")
            print("PHANTOWD_NFS_PEER_READY guests=2 kernel_backend=true "
                  "activation=true protocol=nfs3 transport=tcp read=true "
                  "write=true fsync=true teardown=clean host_network=none "
                  "scope=isolated-two-guest-only")
        finally:
            for endpoint in endpoints:
                endpoint.close()
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
            for output in outputs:
                output.close()


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
