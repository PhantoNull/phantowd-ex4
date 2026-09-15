#!/bin/sh
set -eu

install -d -o builder -g builder -m 0755 /workspace
chown -R builder:builder /workspace

install -d -o builder -g builder -m 0755 /external/artifacts
chown -R builder:builder /external/artifacts

exec gosu builder "$@"
