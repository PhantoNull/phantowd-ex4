# SPDX-License-Identifier: Apache-2.0
# Shared MAC classification for the diskless Stage B3 observation probe.

PHANTOWD_STAGE_B3_PLACEHOLDER_MAC='00:50:43:00:02:02'

stage_b3_mac_handoff_status() {
	[ -n "$1" ] && [ -n "$2" ] || return 2
	[ "$1" != "$2" ] || return 1

	if [ "$1" = "$PHANTOWD_STAGE_B3_PLACEHOLDER_MAC" ] ||
		[ "$2" = "$PHANTOWD_STAGE_B3_PLACEHOLDER_MAC" ]; then
		echo 'placeholder-warning'
	else
		echo 'distinct-nonplaceholder'
	fi
}
