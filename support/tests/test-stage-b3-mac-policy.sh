#!/bin/sh
set -eu

policy_file=${1:?usage: test-stage-b3-mac-policy.sh POLICY_FILE}

# Stage B3 BusyBox is built without its printf applet and ash printf builtin.
# Shadow printf in this host-side test to reproduce that target constraint.
printf() {
	echo 'printf: not found' >&2
	return 127
}

. "$policy_file"

expect_status() {
	expected_rc="$1"
	expected_status="$2"
	mac0="$3"
	mac1="$4"

	if actual_status="$(stage_b3_mac_handoff_status "$mac0" "$mac1")"; then
		actual_rc=0
	else
		actual_rc=$?
	fi

	[ "$actual_rc" -eq "$expected_rc" ] || {
		echo "unexpected MAC policy rc=$actual_rc expected=$expected_rc" >&2
		exit 1
	}
	[ "$actual_status" = "$expected_status" ] || {
		echo "unexpected MAC policy status=$actual_status expected=$expected_status" >&2
		exit 1
	}
}

expect_status 0 distinct-nonplaceholder 00:90:a9:6a:6a:0a 00:90:a9:6a:6a:0b
expect_status 0 placeholder-warning 00:90:a9:6a:6a:0a 00:50:43:00:02:02
expect_status 1 '' 00:90:a9:6a:6a:0a 00:90:a9:6a:6a:0a
expect_status 1 '' 00:50:43:00:02:02 00:50:43:00:02:02
expect_status 2 '' '' 00:50:43:00:02:02

echo 'STAGE_B3_MAC_POLICY_TESTS_OK cases=5'
