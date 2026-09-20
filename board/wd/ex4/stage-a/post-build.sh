#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PhantoWD EX4 contributors

set -eu

target_dir="$1"

chmod 0755 "$target_dir/init"
chmod 0644 "$target_dir/etc/phantowd-release"
