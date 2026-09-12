#!/bin/sh

START_SCRIPT="/usr/local/config/start-nfs.sh"
LOG_FILE="/var/log/nfs-custom.log"

if [ ! -x "$START_SCRIPT" ]; then
    echo "NfsMediaStack: missing executable $START_SCRIPT" >> "$LOG_FILE"
    exit 1
fi

echo "NfsMediaStack: starting NFS" >> "$LOG_FILE"
/bin/sh "$START_SCRIPT" >> "$LOG_FILE" 2>&1 &

exit 0
