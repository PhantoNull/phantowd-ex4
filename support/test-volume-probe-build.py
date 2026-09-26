#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Exercise actual package recipe flags without rebuilding Buildroot/libblkid.

Only the recipe's source/output/link-library arguments are replaced for a
preprocessor probe. This checks flag composition, not full package linking.
"""
import pathlib
import shlex
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
compiler = sys.argv[1] if len(sys.argv) == 2 else "cc"
for value in (str(root), compiler):
    if any(char.isspace() for char in value) or any(char in value for char in "$#\n"):
        raise SystemExit("unsupported test path")
with tempfile.TemporaryDirectory(prefix="phantowd-probe-flags-") as directory:
    fixture = pathlib.Path(directory) / "Makefile"
    fixture.write_text(
        f"BR2_EXTERNAL_PHANTOWD_EX4_PATH := {root}\n"
        f"TARGET_CC := {compiler}\n"
        "INSTALL := install\n"
        f"include {root}/package/phantowd-volume-probe/phantowd-volume-probe.mk\n"
        ".PHONY: check\ncheck:\n\t$(PHANTOWD_VOLUME_PROBE_BUILD_CMDS)\n",
        encoding="utf-8",
    )
    for level in (1, 2, 3):
        recipe = subprocess.check_output(
            ["make", "--no-print-directory", "-n", "-f", str(fixture),
             f"TARGET_CFLAGS=-O2 -D_FORTIFY_SOURCE={level}", "check"], text=True,
        ).replace("\\\n", " ")
        commands = [shlex.split(line) for line in recipe.splitlines()]
        commands = [args for args in commands if args and args[0] == compiler]
        if len(commands) != 1 or "-Werror" not in commands[0]:
            raise SystemExit("compiler recipe missing or warning errors disabled")
        args = []
        skip = False
        for arg in commands[0]:
            if skip:
                skip = False
                continue
            if arg == "-o":
                skip = True
                continue
            if arg.endswith("/probe.c") or arg == "probe.c" or arg == "-lblkid":
                continue
            args.append(arg)
        result = subprocess.run(args + ["-E", "-dM", "-x", "c", "/dev/null"],
                                text=True, capture_output=True, check=False)
        if result.returncode or f"#define _FORTIFY_SOURCE {level}" not in result.stdout.splitlines():
            raise SystemExit(f"package does not preserve FORTIFY level {level}:\n{shlex.join(args)}\n{result.stderr}")
print("Volume-probe package preserves Buildroot FORTIFY levels 1/2/3 with -Werror.")
