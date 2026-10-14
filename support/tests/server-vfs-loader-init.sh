#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Loader only, no daemon/NIC/data disk. Test drops privileges before loading.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if /usr/sbin/phantowd-server-vfs-loader-test; then
    echo PHANTOWD_SERVER_VFS_LOADER_GUEST_DONE
else
    echo PHANTOWD_SERVER_VFS_LOADER_GUEST_FAILED
fi
sync
reboot -f
