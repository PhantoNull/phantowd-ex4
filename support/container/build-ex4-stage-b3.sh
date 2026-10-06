#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PhantoWD EX4 contributors

set -eu

PHANTOWD_EX4_STAGE=b3
export PHANTOWD_EX4_STAGE
exec "$(dirname "$0")/build-ex4-stage-b2.sh"
