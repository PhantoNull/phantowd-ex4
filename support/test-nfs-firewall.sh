#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

if [ "${1:-}" != --isolated ]; then
    [ "$#" -eq 1 ] || { echo 'Usage: test-nfs-firewall.sh /absolute/path/to/nft' >&2; exit 2; }
    nft=$(realpath -- "$1")
    [ -f "$nft" ] && [ -x "$nft" ]
    root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
    scratch=$(mktemp -d)
    trap 'rm -f "$scratch/nfsowner.test"; rmdir "$scratch"' EXIT
    (cd "$root/src/phantowd-api" && go test -mod=vendor -c -o "$scratch/nfsowner.test" ./internal/nfsowner)
    unshare -Urnm -- sh "$root/support/test-nfs-firewall.sh" --isolated "$scratch/nfsowner.test" "$nft"
    exit
fi

[ "$#" -eq 3 ]
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
# The parent unshare creates both the user and network namespace. Require
# the mapped root and an empty namespace before configuring fixture devices.
[ "$(id -u)" -eq 0 ]
[ "$(ip -o link show | wc -l)" -eq 1 ]
server_ns=$(readlink /proc/self/ns/net)
[ "$server_ns" != "$(readlink /proc/1/ns/net)" ]
unshare -n -- sleep 45 &
peer=$!
trap 'kill "$peer" 2>/dev/null || true; wait "$peer" 2>/dev/null || true' EXIT
i=0
while [ "$(readlink "/proc/$peer/ns/net")" = "$server_ns" ]; do
    i=$((i + 1))
    [ "$i" -lt 50 ]
    sleep 0.02
done
ip link set lo up
ip link add pwnfs type veth peer name pwclient
ip link add pwlan2 type veth peer name pwother
ip link set pwclient netns "$peer"
ip link set pwother netns "$peer"
ip link set pwnfs up
ip link set pwlan2 up
ip addr add 192.0.2.1/29 dev pwnfs
ip addr add 192.0.2.5/29 dev pwnfs
ip addr add 198.51.100.1/29 dev pwlan2
nsenter -t "$peer" -n -- ip link set lo up
nsenter -t "$peer" -n -- ip link set pwclient up
nsenter -t "$peer" -n -- ip link set pwother up
nsenter -t "$peer" -n -- ip addr add 192.0.2.2/29 dev pwclient
nsenter -t "$peer" -n -- ip addr add 192.0.2.3/29 dev pwclient
nsenter -t "$peer" -n -- ip addr add 198.51.100.2/29 dev pwother
PHANTOWD_NFT_FIXTURE="$3" PHANTOWD_NFT_PEER_PID="$peer" "$2" -test.v -test.run '^Test(NFS|Samba)FirewallKernel$'
