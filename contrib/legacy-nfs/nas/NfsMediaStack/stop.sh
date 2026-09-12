#!/bin/sh

# Deliberately a no-op: automatically unexporting an active hard-mounted NFS
# filesystem is more disruptive than leaving it available until shutdown.
exit 0
