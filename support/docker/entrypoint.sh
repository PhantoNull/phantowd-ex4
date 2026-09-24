#!/bin/sh
set -eu

install -d -o builder -g builder -m 0755 /workspace
workspace_owner_marker=/workspace/.phantowd-owner-builder-v1
if [ ! -f "$workspace_owner_marker" ]; then
    chown -R builder:builder /workspace
    install -o builder -g builder -m 0644 /dev/null "$workspace_owner_marker"
fi

install -d -o builder -g builder -m 0755 /external/artifacts
artifacts_owner_marker=/external/artifacts/.phantowd-owner-builder-v1
if [ ! -f "$artifacts_owner_marker" ]; then
    chown -R builder:builder /external/artifacts
    install -o builder -g builder -m 0644 /dev/null "$artifacts_owner_marker"
fi

exec gosu builder "$@"
