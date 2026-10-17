#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Closed synthetic two-boot receipt contract, never a product-state parser."""
import base64
import binascii
import json
import os
import re
import stat
import sys

MAX_PROOF = 32768
MAX_LOG = 262144
ROOT = re.compile(r"/run/phantowd-revisionstore-media/phantowd-transaction-[A-Za-z0-9]{1,32}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
RECORD = re.compile(r"operations/([0-9a-f]{32})\.json\Z")
KEYS = {"version", "phase", "nonce", "boot_id", "pid", "root", "entries"}
ENTRY_KEYS = {"name", "data", "inode", "mode", "uid", "gid", "links", "size",
              "atime_sec", "atime_nsec", "mtime_sec", "mtime_nsec", "ctime_sec", "ctime_nsec"}


def valid_nonce(value):
    return isinstance(value, str) and NONCE.fullmatch(value) and value != "0" * 32


def validate_proof(proof, phase, nonce):
    if (not isinstance(proof, dict) or set(proof) != KEYS or type(proof["version"]) is not int or
            proof["version"] != 1 or phase not in ("produce", "observe") or proof["phase"] != phase or
            not valid_nonce(nonce) or proof["nonce"] != nonce or type(proof["pid"]) is not int or
            not 1 <= proof["pid"] <= 4194304 or not isinstance(proof["root"], str) or
            not ROOT.fullmatch(proof["root"]) or not isinstance(proof["boot_id"], str) or
            not BOOT.fullmatch(proof["boot_id"]) or proof["boot_id"] == "00000000-0000-0000-0000-000000000000"):
        raise ValueError("invalid boot proof")
    entries = proof["entries"]
    if not isinstance(entries, list) or len(entries) != 6:
        raise ValueError("incomplete census")
    names, inodes, records = [], set(), 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS or not isinstance(entry["name"], str):
            raise ValueError("invalid entry")
        name = entry["name"]
        directory = name in (".", "policy", "operations")
        match = RECORD.fullmatch(name)
        if not directory and name != "policy/nas-services.json":
            if not match or match[1] == "0" * 32:
                raise ValueError("foreign entry")
            records += 1
        for field in ENTRY_KEYS - {"name", "data"}:
            if type(entry[field]) is not int or entry[field] < 0 or entry[field] > 2**64 - 1:
                raise ValueError("invalid metadata")
        if (entry["inode"] == 0 or entry["inode"] in inodes or entry["uid"] != 0 or entry["gid"] != 0 or
                entry["mode"] != (0o40700 if directory else 0o100600) or
                entry["links"] != ((4 if name == "." else 2) if directory else 1) or
                not 0 < entry["size"] <= MAX_PROOF):
            raise ValueError("unsafe metadata")
        for prefix in ("atime", "mtime", "ctime"):
            if entry[prefix + "_sec"] > 2**63 - 1 or entry[prefix + "_nsec"] >= 1000000000:
                raise ValueError("invalid timestamp")
        if directory:
            if entry["data"] is not None:
                raise ValueError("directory data")
        else:
            if not isinstance(entry["data"], str) or len(entry["data"]) > MAX_PROOF:
                raise ValueError("invalid file data")
            try:
                data = base64.b64decode(entry["data"], validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError("invalid encoding") from error
            if len(data) != entry["size"] or base64.b64encode(data).decode() != entry["data"]:
                raise ValueError("data metadata mismatch")
        names.append(name)
        inodes.add(entry["inode"])
    if (names != sorted(set(names)) or records != 2 or
            not {".", "policy", "operations", "policy/nas-services.json"}.issubset(names)):
        raise ValueError("incomplete or ambiguous census")
    return proof


def compare(first, second, nonce):
    validate_proof(first, "produce", nonce)
    validate_proof(second, "observe", nonce)
    if first["boot_id"] == second["boot_id"] or first["root"] != second["root"] or first["entries"] != second["entries"]:
        raise ValueError("boot continuity mismatch")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = item
    return value


def decode_proof(data, phase, nonce):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_PROOF:
        raise ValueError("bounded proof required")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError("invalid proof encoding") from error
    return validate_proof(value, phase, nonce)


def validate_log(data, phase, nonce):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_LOG or phase not in ("produce", "observe") or not valid_nonce(nonce):
        raise ValueError("bounded log required")
    try:
        lines = data.decode("utf-8").replace("\r\n", "\n").split("\n")
    except UnicodeError as error:
        raise ValueError("invalid log encoding") from error
    state, proof = 0, None
    for line in lines:
        if line == "PHANTOWD_HISTORY_REBOOT_PREPARED phase=" + phase + " scope=qemu-only":
            if state != 0:
                raise ValueError("duplicate or late preparation")
            state = 1
        elif line == "=== RUN   TestRuntimeHistoryAcrossCleanReboot":
            if state != 1:
                raise ValueError("unbound test")
            state = 2
        elif line.startswith("PHANTOWD_HISTORY_REBOOT_RECORD "):
            if state != 2:
                raise ValueError("duplicate or unbound record")
            proof = decode_proof(line.removeprefix("PHANTOWD_HISTORY_REBOOT_RECORD ").encode(), phase, nonce)
            state = 3
        elif re.fullmatch(r"--- PASS: TestRuntimeHistoryAcrossCleanReboot \([0-9]+(?:\.[0-9]+)?s\)", line):
            if state != 3:
                raise ValueError("unbound pass")
            state = 4
        elif line == "PASS":
            if state != 4:
                raise ValueError("duplicate or incomplete Go pass")
            state = 5
        elif line.startswith("PHANTOWD_HISTORY_REBOOT_DONE "):
            expected = ("PHANTOWD_HISTORY_REBOOT_DONE phase=" + phase + " pid=" + str(proof["pid"]) +
                        " normal_unmount=true scope=qemu-only") if proof is not None else ""
            if state != 5 or line != expected:
                raise ValueError("unbound closure")
            state = 6
        elif ("PHANTOWD_" in line or line.lstrip().startswith(("--- PASS:", "--- FAIL:", "--- SKIP:", "=== RUN", "PASS", "FAIL")) or
              any(error in line for error in ("Kernel panic", "runtime error:", "WARNING: DATA RACE", "INTERNAL ERROR", "testing: warning: no tests to run"))):
            raise ValueError("foreign or failed evidence")
    if state != 6:
        raise ValueError("incomplete boot")
    return proof


def read_bounded(path, limit):
    with open(path, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("regular input required")
        data = stream.read(limit + 1)
    if not 0 < len(data) <= limit:
        raise ValueError("bounded input required")
    return data


def main(args):
    if len(args) == 4 and args[0] == "log":
        value = validate_log(read_bounded(args[3], MAX_LOG), args[1], args[2])
        print(json.dumps(value, separators=(",", ":"), sort_keys=True))
    elif len(args) == 3 and args[0] == "bindings":
        value = decode_proof(read_bounded(args[2], MAX_PROOF), "produce", args[1])
        print(value["root"], value["boot_id"])
    elif len(args) == 4 and args[0] == "compare":
        first = decode_proof(read_bounded(args[2], MAX_PROOF), "produce", args[1])
        second = decode_proof(read_bounded(args[3], MAX_PROOF), "observe", args[1])
        compare(first, second, args[1])
        print("PHANTOWD_HISTORY_REBOOT_MATCH boots=2 distinct_kernels=true exact_bytes=true stable_metadata=true admission=false scope=qemu-only")
    else:
        raise ValueError("closed command required")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print("Synthetic history reboot proof refused.", file=sys.stderr)
        sys.exit(1)
