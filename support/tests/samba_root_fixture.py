#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Merge fixed programs/modules/catalog for a QEMU-only Samba test."""
import argparse
import hashlib
import json
import re
from pathlib import Path

from runtime_loader_fixture import MAX_LOG, MAX_REPORT, read_bounded, validate


ENTRIES = ("usr/sbin/smbd", "usr/bin/smbpasswd", "usr/bin/testparm",
           "usr/lib/samba/vfs/streams_xattr.so", "usr/lib/gconv/IBM850.so",
           "usr/bin/pdbedit", "usr/bin/smbstatus", "usr/bin/smbcontrol")
CATALOG_PATH = "usr/lib/gconv/gconv-modules"
CATALOG_ROWS = frozenset({
    ("alias", "CP850//", "IBM850//"),
    ("alias", "850//", "IBM850//"),
    ("alias", "CSPC850MULTILINGUAL//", "IBM850//"),
    ("alias", "OSF10020352//", "IBM850//"),
    ("module", "IBM850//", "INTERNAL", "IBM850", "1"),
    ("module", "INTERNAL", "IBM850//", "IBM850", "1"),
})
MARKERS = (
    "PHANTOWD_SAMBA_ROOT_ENTROPY_READY provider=virtio-rng scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true "
    "no_overwrite=true refusals=5 scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_CODE_ACL_READY baseline=true root=true "
    "directories=true files=true refusals=5 scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_BUNDLE_READY readonly=true complete_census=true "
    "hashes=true aliases=true refusals=5 scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_RETAINED_CODE_READY complete_code_pins=true "
    "caller_close=true dynamic_elf=true generic_dynamic_refused=true "
    "generic_root_refused=true canceled_refused=true "
    "released=true no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_CODE_VIEWS_READY code_only=true config_separate=true "
    "same_inodes=true readonly_views=true scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_CODE_VIEWS_REFUSAL_READY same_bytes_copy=true "
    "scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_CHARSET_READY charset=CP850 bytes=true "
    "roundtrip=true isolated_root=true scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_CONTEXT_READY original_fds_closed=true "
    "signal_mask_empty=true dispositions_default=true scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_BOUNDARY_READY caps=00000000000000db "
    "nnp=true original_denied=true kernel_ro=true",
    "PHANTOWD_SAMBA_ROOT_STREAMS_READY module=streams_xattr "
    "xattr_bytes=true reader_write_denied=true kernel_ro=true scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_POSIX_ACL_READY fs=ext4 bytes=true named_reader=true "
    "outsider_denied=true mask_revocation=true scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_INHERITANCE_READY fs=ext4 directory_acl=true "
    "file_acl=true setgid=true reader_write_denied=true outsider_denied=true "
    "scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_POLICY_READY writer_uid=1801 reader_uid=1802 "
    "outsider_denied=true kernel_ro=true original_denied=true "
    "unix_ownership=true unix_denial=true utf8_roundtrip=true scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_STOPPED",
    "PHANTOWD_SAMBA_OWNER_GROUP_READY nonleader_refused=true "
    "pinned_helper=true caller_close=true canceled_refused=true "
    "same_group=true caps=db distinct_accounts=true "
    "writer_bytes=true unix_ownership=true kernel_ro=true "
    "duplicate_refused=true live_close_refused=true "
    "stopped_reaped=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_CODE_LIFETIME_READY caller_close=true "
    "live_code_pins=true normal_stop=true drift_stopped=true "
    "forced_stop_review=true "
    "review_retained=true restoration_refused=true released=true "
    "no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_CONFIG_LIFETIME_READY exact_contents=true "
    "caller_close=true live_pins=true same_child_objects=true "
    "readonly_noexec=true normal_stop=true drift_stopped=true "
    "review_retained=true restoration_refused=true released=true "
    "scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_STATE_LIFETIME_READY caller_close=true "
    "live_directory_pins=true same_child_objects=true writable_noexec=true "
    "mutable_passdb=true normal_stop=true drift_stopped=true "
    "review_retained=true restoration_refused=true released=true "
    "scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_STATE_HANDOFF_READY inputs=7 "
    "source_path_masked=true same_child_objects=true "
    "closed_before_exec=true no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_STATE_ADMISSION_READY refusals=5 "
    "before_launch=true caller_inputs_closed=true copied_spec=true "
    "partial_cleanup=true forced_stop_review=true review_pins=true "
    "explicit_release=true no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_STATE_OBSERVER_READY inputs=7 refusals=1 "
    "caller_inputs_closed=true source_path_masked=true same_objects=true "
    "closed_before_exec=true listing_redacted=true single_use=true "
    "stopped_reaped=true released=true no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_STATE_OBSERVER_REFUSAL_READY "
    "late_mode_drift=true before_launch=true "
    "cancellation_before_admission=true "
    "review_pins=true restoration_refused=true stopped_reaped=true "
    "released=true no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_NSS_READY accounts=2 owner_derived=true "
    "libc=true private_groups=true foreign_omitted=true readonly_root=true "
    "caps_zero=true no_state=true unchanged_owner=true stopped_reaped=true "
    "daemon_installed=false scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_NSS_REFUSAL_READY changed_uid=true "
    "supplementary_group=true foreign_user=true restored_lookup=true "
    "unchanged_owner=true stopped_reaped=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_CONFIG_READY owner_derived=true "
    "exact_census=true readonly_noexec=true caller_close=true "
    "libc=true drift_refused=true restoration_mismatch=true "
    "stopped_reaped=true released=true no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_HANDOFF_READY inputs=4 refusals=7 "
    "source_path_masked=true same_objects=true caller_close=true "
    "readonly_noexec=true closed_before_exec=true late_drift_refused=true "
    "review_sticky=true partial_cleanup=true stopped_reaped=true "
    "no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY accounts=2 "
    "owner_bound=true original_config=true original_state=true "
    "disabled_first=true stdin_only=true same_sid=true explicit_enable=true "
    "stopped_reaped=true no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_DAEMON_READY accounts=2 "
    "same_code=true same_config=true same_state=true authenticated=true "
    "wrong_password_denied=true owned_group=true stopped_reaped=true "
    "no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_DONE",
)

SCAN_PREFIX = "PHANTOWD_RUNTIME_SCAN_COST"


def scan_cost(log):
    rows = [line for line in log.splitlines() if line.startswith(SCAN_PREFIX)]
    if len(rows) != 1:
        raise ValueError("exactly one runtime scan measurement required")
    match = re.fullmatch(
        SCAN_PREFIX + r" files=([1-9][0-9]{0,2}) bytes=([1-9][0-9]{0,7}) "
        r"elapsed_ns=([1-9][0-9]{0,18}) scope=qemu-emulation-only", rows[0])
    if match is None:
        raise ValueError("invalid runtime scan measurement")
    files, size, elapsed = map(int, match.groups())
    if files > 256 or size > 64 * 1024 * 1024:
        raise ValueError("runtime scan exceeds fixed bundle budget")
    return files, size, elapsed


def check_guest(log):
    if not isinstance(log, str) or len(log.encode("utf-8")) > MAX_LOG:
        raise ValueError("oversized guest evidence")
    prefixes = ("PHANTOWD_SAMBA_ROOT_", "PHANTOWD_SAMBA_OWNER_")
    markers = [line for line in log.splitlines() if line.startswith(prefixes)]
    if markers != list(MARKERS):
        raise ValueError("incomplete, failed or repeated guest evidence")
    scan_cost(log)


def check_campaign(log, phase):
    if (not isinstance(log, str) or len(log.encode("utf-8")) > MAX_LOG
            or phase not in ("service", "native")):
        raise ValueError("invalid campaign evidence")
    split = next(i for i, row in enumerate(MARKERS)
                 if row.startswith("PHANTOWD_SAMBA_OWNER_NATIVE_NSS_READY"))
    expected = (MARKERS[:split] + ("PHANTOWD_SAMBA_ROOT_SERVICE_DONE",)
                if phase == "service" else MARKERS[:5] + MARKERS[split:])
    prefixes = ("PHANTOWD_SAMBA_ROOT_", "PHANTOWD_SAMBA_OWNER_")
    markers = tuple(line for line in log.splitlines()
                    if line.startswith(prefixes))
    if markers != expected:
        raise ValueError("incomplete, wrong-phase or repeated campaign proof")
    return scan_cost(log)


def check_campaigns(service, native):
    first = check_campaign(service, "service")
    second = check_campaign(native, "native")
    if first[:2] != second[:2]:
        raise ValueError("campaign runtime census differs")
    return first, second


def validate_catalog(catalog):
    if (not isinstance(catalog, str) or not catalog.isascii()
            or not 0 < len(catalog) <= 4096 or "\x00" in catalog):
        raise ValueError("invalid fixed conversion catalog")
    rows = [tuple(line.split()) for line in catalog.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    if len(rows) != len(CATALOG_ROWS) or set(rows) != CATALOG_ROWS:
        raise ValueError("unexpected conversion aliases or modules")
    return hashlib.sha256(catalog.encode("ascii")).hexdigest()


def merge(reports, catalog):
    catalog_digest = validate_catalog(catalog)
    if not isinstance(reports, list) or len(reports) != len(ENTRIES):
        raise ValueError("complete fixed runtime set required")
    objects, aliases = {}, {}
    for entry, report in zip(ENTRIES, reports):
        selected, bindings, _ = validate(report, fixed_entry=entry)
        for name in bindings:
            if (name not in ENTRIES
                    and not name.startswith(("lib/", "usr/lib/"))):
                raise ValueError("runtime overlaps generated fixture state")
        for item in selected:
            evidence = (item["sha256"], item["size"])
            previous = objects.setdefault(item["path"], evidence)
            if previous != evidence:
                raise ValueError("conflicting runtime bytes")
        for alias, canonical in bindings.items():
            previous = aliases.setdefault(alias, canonical)
            if previous != canonical:
                raise ValueError("conflicting runtime alias")
    if CATALOG_PATH in aliases or CATALOG_PATH in objects:
        raise ValueError("conversion catalog overlaps ELF roster")
    if (len(objects) + 1 > 256 or len(aliases) + 1 > 1024
            or sum(size for _, size in objects.values()) + len(catalog)
            > 64 * 1024 * 1024):
        raise ValueError("merged runtime budget exceeded")
    rows = []
    for alias, canonical in sorted(aliases.items()):
        digest, _ = objects[canonical]
        rows.append(f"{digest} /{canonical} /{alias}\n")
    rows.append(f"{catalog_digest} /{CATALOG_PATH} /{CATALOG_PATH}\n")
    return "".join(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("smbd")
    prepare.add_argument("smbpasswd")
    prepare.add_argument("testparm")
    prepare.add_argument("streams_xattr")
    prepare.add_argument("ibm850")
    prepare.add_argument("pdbedit")
    prepare.add_argument("smbstatus")
    prepare.add_argument("smbcontrol")
    prepare.add_argument("catalog")
    prepare.add_argument("manifest")
    verify = sub.add_parser("verify")
    verify.add_argument("log")
    verify.add_argument("--native-log")
    campaign = sub.add_parser("verify-campaign")
    campaign.add_argument("log")
    campaign.add_argument("phase", choices=("service", "native"))
    args = parser.parse_args()
    if args.command == "prepare":
        reports = [json.loads(read_bounded(name, MAX_REPORT)) for name in (
            args.smbd, args.smbpasswd, args.testparm, args.streams_xattr,
            args.ibm850, args.pdbedit, args.smbstatus, args.smbcontrol)]
        if Path(args.catalog).is_symlink() or not Path(args.catalog).is_file():
            raise ValueError("regular fixed conversion catalog required")
        catalog = read_bounded(args.catalog, 4096)
        Path(args.manifest).write_text(merge(reports, catalog))
    elif args.command == "verify-campaign":
        check_campaign(read_bounded(args.log, MAX_LOG), args.phase)
        print(f"Samba {args.phase} campaign verified")
    else:
        log = read_bounded(args.log, MAX_LOG)
        if args.native_log:
            native = read_bounded(args.native_log, MAX_LOG)
            _, (files, size, elapsed) = check_campaigns(log, native)
            print(f"PHANTOWD_SAMBA_CAMPAIGN_SCAN_COST phase=native "
                  f"files={files} bytes={size} elapsed_ns={elapsed} "
                  "scope=qemu-emulation-only")
        else:
            check_guest(log)
        files, size, elapsed = scan_cost(log)
        print(f"{SCAN_PREFIX} files={files} bytes={size} elapsed_ns={elapsed} "
              "scope=qemu-emulation-only")
        print("\n".join(MARKERS))


if __name__ == "__main__":
    main()
