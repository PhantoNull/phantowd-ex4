# shellcheck shell=sh
# SPDX-License-Identifier: Apache-2.0
# Shared MAC classification for the diskless Stage B3 observation probe.

PHANTOWD_STAGE_B3_PLACEHOLDER_MAC='00:50:43:00:02:02'

stage_b3_valid_unicast_mac() {
	case "$1" in
		[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F])
			;;
		*)
			return 1
			;;
	esac

	[ "$1" != '00:00:00:00:00:00' ] || return 1
	first_octet=${1%%:*}
	last_nibble=${first_octet#?}
	case "$last_nibble" in
		[13579bBdDfF]) return 1 ;;
	esac
	return 0
}

stage_b3_mac_handoff_status() {
	[ -n "$1" ] && [ -n "$2" ] || return 2
	stage_b3_valid_unicast_mac "$1" || return 2
	stage_b3_valid_unicast_mac "$2" || return 2
	[ "$1" != "$2" ] || return 1

	if [ "$1" = "$PHANTOWD_STAGE_B3_PLACEHOLDER_MAC" ] ||
		[ "$2" = "$PHANTOWD_STAGE_B3_PLACEHOLDER_MAC" ]; then
		echo 'placeholder-warning'
	else
		echo 'distinct-nonplaceholder'
	fi
}
