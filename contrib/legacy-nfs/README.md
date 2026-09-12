# Legacy firmware NFS integration

These files record the interim NFS persistence mechanism used while the
replacement firmware is only a research project. They target the WD My Cloud
EX4 vendor firmware and a Proxmox host.

The NAS APKG wrapper launches a persistent `/usr/local/config/start-nfs.sh`
after application discovery. The Proxmox example uses NFSv3 over TCP with a
systemd automount and makes an LXC service require the real mount.

Review and replace every example address, UID/GID, path, VMID, and unit name
before use. The v1.1 wrapper has passed manual execution and a controlled live
APKG rescan. The first real boot test used the incomplete v1.0 package and did
not start rpcbind/NFS; a second reboot is still required to prove v1.1 boot
persistence.

These helpers do not modify the firmware SquashFS or raw flash.

The stop wrapper must remove its exact export after clients are quiesced.
Without that step, NFSD keeps a kernel reference to Volume 2 and the vendor
`diskmgr -p` shutdown stage cannot unmount the filesystem.

## APKG compatibility marker

The vendor scanner accepts `custom_id` 0 or 20 on this model and requires an
`apkg.sign` file whose decoded package name matches `NfsMediaStack`. Despite
its filename, this legacy Blowfish-CBC value is a compatibility marker, not an
authenticity signature.

The reviewable text file `nas/NfsMediaStack/apkg.sign.b64` contains the marker
used for this package. Decode it on the NAS after copying the directory:

```sh
cd /mnt/HD/HD_a2/Nas_Prog/NfsMediaStack
/usr/sbin/openssl base64 -d -in apkg.sign.b64 -out apkg.sign
chmod 0644 apkg.sign
```

The APKG directory is placed on Volume 1 so its backgrounded start script can
wait for the exported directory on Volume 2. The persistent NFS script remains
under `/usr/local/config`.
