#!/bin/sh

START_SCRIPT="/usr/local/config/start-nfs.sh"
LOG_FILE="/var/log/nfs-custom.log"
LOCK_DIR="/var/run/nfs-mediastack-starting"

if [ ! -x "$START_SCRIPT" ]; then
    echo "NfsMediaStack: missing executable $START_SCRIPT" >> "$LOG_FILE"
    exit 1
fi

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "NfsMediaStack: start already requested" >> "$LOG_FILE"
    exit 0
fi

echo "NfsMediaStack: starting NFS" >> "$LOG_FILE"
(
    /bin/sh "$START_SCRIPT" >> "$LOG_FILE" 2>&1
    status=$?
    [ "$status" -eq 0 ] || rm -rf "$LOCK_DIR"
    exit "$status"
) &

exit 0
