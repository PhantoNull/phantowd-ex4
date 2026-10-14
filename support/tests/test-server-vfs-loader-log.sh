#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository required}
[ "$#" -eq 1 ] || exit 1
ready='PHANTOWD_SERVER_VFS_LOADER_READY canonical=true registry=true connect_refused=true loader_refusals=6 uid=65534 caps=0 nnp=true active_worker=false producer=false authority=false scope=qemu-only'
done='PHANTOWD_SERVER_VFS_LOADER_GUEST_DONE'
verify() { awk -f "$source/support/tests/verify-server-vfs-loader-log.awk"; }
refused() { if verify; then echo 'VFS loader verifier accepted malformed proof' >&2; exit 1; fi; }
printf '%s\n' "$ready" "$done" | verify
printf '%s\r\n' "$ready" "$done" | verify
printf '' | refused
printf '%s\n' "$ready" | refused
printf '%s\n' "$done" | refused
printf '%s\n' "$done" "$ready" | refused
printf '%s\n' "$ready" "$ready" "$done" | refused
printf '%s\n' "$ready" "$done" "$done" | refused
printf '%s\n' "$ready" 'PHANTOWD_SERVER_VFS_LOADER_GUEST_FAILED' "$done" | refused
printf '%s\n' "prefix $ready" "$done" | refused
printf '%s\n' "$ready suffix" "$done" | refused
printf '%s\n' "$ready" "$done" 'PHANTOWD_UNRELATED_SUCCESS' | refused
for mutation in 'canonical=true/canonical=false' 'registry=true/registry=false' \
    'connect_refused=true/connect_refused=false' 'loader_refusals=6/loader_refusals=5' \
    'uid=65534/uid=0' 'caps=0/caps=1' 'nnp=true/nnp=false' \
    'active_worker=false/active_worker=true' 'producer=false/producer=true' \
    'authority=false/authority=true' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "${ready/${mutation%%\/*}/${mutation#*\/}}" "$done" | refused
done
echo 'PHANTOWD_SERVER_VFS_LOADER_LOG_CONTROLS_DONE positive=2 negative=21 scope=host-parser-only guest=false'
