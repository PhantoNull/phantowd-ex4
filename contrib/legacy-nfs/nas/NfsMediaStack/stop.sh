#!/bin/sh

EXPORT_PATH="/mnt/HD/HD_b2/MediaStack"
CLIENT="192.0.2.10"
LOG_FILE="/var/log/nfs-custom.log"

# The export keeps a kernel reference to Volume 2 and prevents the vendor
# diskmgr shutdown step from unmounting it. The client must be quiesced first.
echo "NfsMediaStack: removing NFS export" >> "$LOG_FILE"
/usr/sbin/exportfs -u "${CLIENT}:${EXPORT_PATH}" >> "$LOG_FILE" 2>&1
rm -rf /var/run/nfs-mediastack-starting

exit 0
