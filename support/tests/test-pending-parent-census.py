#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Execute the init's actual parent-census call site with a harmless child."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text(encoding="utf-8")
helper = source[source.index("count_parent_fds() {"):
                source.index("\nrun_fixture() {")]
start = source.index(
    "/usr/sbin/phantowd-pending-client-inputs retain || return 1\n")
start = source.index("\n", start) + 1
end = source.index(
    "    echo 'PHANTOWD_PENDING_OWNER_INPUT_LOSS_PROCESS_READY", start)
cycle = source[start:end]
child = "/usr/sbin/phantowd-pending-client-inputs preclose-input-loss"
assert cycle.count(child) == 1
cycle = cycle.replace(child, "/bin/sh -c 'exit 0'")
reaped = '    [ ! -d "/proc/$fixture_pid" ] || return 1\n'
assert cycle.count(reaped) == 1
leak = cycle.replace(reaped, reaped + "    exec 9</dev/null\n")
helper = helper.replace("/run/parent-fd-count", '"$PHANTOWD_COUNT_FILE"')
body = f'''#!/bin/sh
{helper}
cycle() {{
{cycle}
}}
leak_cycle() {{
{leak}
}}
[ ! -e "/proc/$$/fd/9" ] || exit 40
i=0
while [ "$i" -lt 1000 ]; do
    i=$((i+1))
    cycle || {{ echo "PARENT_CENSUS_FALSE_REFUSAL iteration=$i"; exit 41; }}
done
if leak_cycle; then
    echo PARENT_CENSUS_MISSED_REAL_LEAK
    exit 42
fi
exec 9<&-
cycle || {{ echo PARENT_CENSUS_RESTORE_REFUSED; exit 43; }}
echo PARENT_CENSUS_CONTROLS_DONE stable=1000 \\
    real_leak_detected=true restored=true
'''
with tempfile.TemporaryDirectory(prefix="parent-census-test-") as directory:
    root = Path(directory)
    script = root / "exercise.sh"
    script.write_text(body, encoding="utf-8")
    environment = dict(os.environ, PHANTOWD_COUNT_FILE=str(root / "count"))
    result = subprocess.run(["/bin/sh", str(script)], env=environment,
                            text=True, capture_output=True, timeout=40)
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    sys.exit(result.returncode)
