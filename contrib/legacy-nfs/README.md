# Legacy firmware NFS integration

These files record the interim NFS persistence mechanism used while the
replacement firmware is only a research project. They target the WD My Cloud
EX4 vendor firmware and a Proxmox host.

The NAS APKG wrapper launches a persistent `/usr/local/config/start-nfs.sh`
after application discovery. The Proxmox example uses NFSv3 over TCP with a
systemd automount and makes an LXC service require the real mount.

Review and replace every example address, UID/GID, path, VMID, and unit name
before use. The APKG boot path has been tested manually but still needs a clean
NAS reboot test.

These helpers do not modify the firmware SquashFS or raw flash.
