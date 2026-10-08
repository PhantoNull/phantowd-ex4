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


CAMPAIGNS = ("service", "native", "candidate", "lifecycle", "fault", "data")
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
CENSUS_MARKER = ("PHANTOWD_SAMBA_ROOT_CENSUS_READY readonly=true "
                 "complete_census=true hashes=true aliases=true "
                 "negative_controls=false retained_control=false "
                 "scope=qemu-only")
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
    "PHANTOWD_SAMBA_OWNER_NATIVE_IDLE_DISABLE_READY owner_bound=true "
    "same_sid=true stable_absence=true new_login_denied=true "
    "other_login_allowed=true same_daemon=true no_new_privileges=true "
    "stopped_reaped=true no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_LIVE_REVOKE_READY accounts=2 "
    "qualified_pair=true owner_bound=true same_sid=true target_absent=true "
    "same_peer_session=true new_login_denied=true other_login_allowed=true "
    "same_daemon=true no_new_privileges=true stopped_reaped=true "
    "no_fd_leak=true scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_BACKEND_BINDING_READY "
    "owner_bound=true backend_bound=true unchanged_verified=true "
    "foreign_refused=true close_busy=true released_before_start=true "
    "release_no_mutation=true stopped_reaped=true no_fd_leak=true "
    "service_owner=false scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_DISABLE_HANDOFF_READY "
    "owner_bound=true backend_bound=true atomic_successor=true "
    "old_review=true new_verified=true close_busy=true same_peer_session=true "
    "retained_until_stop=true stopped_reaped=true no_fd_leak=true "
    "startup_bound=false service_owner=false scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_DATA_READY original_objects=true "
    "individual_clones=true readonly_EROFS=true smb_read=true smb_write=true "
    "unix_owner=true symlink_denied=true private_namespace=true "
    "stopped_before_release=true no_fd_leak=true "
    "complete_storage_identity=false scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_PLANNED_STARTUP_READY "
    "owner=actual_native_backend storage=mounted_roster "
    "same_authorities=true granted_only=true service_role=true "
    "original_views=true before_start_busy=true after_start_busy=true "
    "duplicate_refused=true canceled_start_refused=true "
    "fresh_observation=true runtime_close_before_release=true "
    "stopped_reaped=true no_fd_leak=true samba_data=false "
    "activation=false scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_PLANNED_DATA_READY "
    "same_authorities=true same_daemon=true granted_only=true "
    "ungranted_enabled_denied=true "
    "smb_read=true smb_write=true unix_owner=true readonly_EROFS=true "
    "readonly_denied=true symlink_denied=true fresh_observation=true "
    "stopped_before_release=true no_fd_leak=true "
    "activation=false scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_PLANNED_CANDIDATE_READY "
    "owner=actual_native_backend storage=mounted_roster locked_plan=true "
    "exact_declaration=true original_objects=true caller_close=true "
    "fresh_recompiled=true rendered=true granted_only=true "
    "paired_lookup=true management_complete=true shared_globals=true "
    "management_bound=true protected_role=true management_unchanged=true "
    "prepared_inputs=true service_config_bound=true share_inputs_bound=true "
    "coordinator_bound=true same_roster=true policy_copy=true "
    "startup_blocked=true "
    "identity_retained=true handoff_close_gated=true "
    "desired_roundtrip=true journals_unchanged=true stale_refused=true "
    "runtime_close_before_release=true "
    "released=true samba_data=false activation=false scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_IDENTITY_STARTUP_READY "
    "startup_bound=true exact_backend=true before_start_busy=true "
    "after_start_busy=true duplicate_refused=true canceled_start_refused=true "
    "complete_observation=true serialized_scans=true "
    "accepted_cancellation=true stopped_reaped=true "
    "close_before_release=true no_fd_leak=true "
    "coordinator_disable=true qualified_pair=true "
    "same_peer_session=true target_denied=true "
    "stale_revision_refused=true canceled_disable_refused=true "
    "serialized_disable=true prepared_disable_refused=true "
    "stopped_disable_refused=true "
    "service_owner=false scope=qemu-only",
    "PHANTOWD_SAMBA_OWNER_NATIVE_IDENTITY_FAULT_READY "
    "state_drift=true before_worker=true pending_retained=true "
    "groups_stopped=true capture_settled=true authority_busy=true "
    "inputs_retained=true restoration_refused=true close_no_retry=true "
    "subprocess_disposal=true no_fd_leak=true "
    "service_owner=false scope=qemu-only",
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
            or phase not in CAMPAIGNS):
        raise ValueError("invalid campaign evidence")
    enrollment = next(i for i, row in enumerate(MARKERS)
                      if row.startswith(
                          "PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY"))
    planned = next(row for row in MARKERS
                   if row.startswith(
                       "PHANTOWD_SAMBA_OWNER_PLANNED_CANDIDATE_READY"))
    access = tuple(row for row in MARKERS if row.startswith((
        "PHANTOWD_SAMBA_OWNER_PLANNED_STARTUP_READY",
        "PHANTOWD_SAMBA_OWNER_PLANNED_DATA_READY")))
    native = tuple(row for row in MARKERS[enrollment:-3]
                   if row not in (*access, planned))
    # Every guest still hashes its own complete code tree. The independently
    # exercised refusals/retention remain mandatory once, in the service guest;
    # neither a narrowed inspection nor another guest's state claims those.
    census = MARKERS[:3] + (CENSUS_MARKER,)
    expected = {
        "service": MARKERS[:enrollment]
        + ("PHANTOWD_SAMBA_ROOT_SERVICE_DONE",),
        "native": census + native
        + ("PHANTOWD_SAMBA_ROOT_NATIVE_DONE",),
        "candidate": (census + (MARKERS[enrollment], planned)
                      + ("PHANTOWD_SAMBA_ROOT_CANDIDATE_DONE",)),
        "lifecycle": (census + (MARKERS[enrollment], MARKERS[-3],
                                "PHANTOWD_SAMBA_ROOT_DONE")),
        "fault": (census + (MARKERS[enrollment], MARKERS[-2],
                            "PHANTOWD_SAMBA_ROOT_FAULT_DONE")),
        "data": (census + (MARKERS[enrollment],) + access
                 + ("PHANTOWD_SAMBA_ROOT_DATA_DONE",)),
    }[phase]
    prefixes = ("PHANTOWD_SAMBA_ROOT_", "PHANTOWD_SAMBA_OWNER_")
    markers = tuple(line for line in log.splitlines()
                    if line.startswith(prefixes))
    if markers != expected:
        raise ValueError("incomplete, wrong-phase or repeated campaign proof")
    return scan_cost(log)


def select_campaigns(selection):
    """A focused local probe is never the complete six-campaign proof."""
    if not isinstance(selection, str):
        raise ValueError("invalid campaign selection")
    if selection == "all":
        return CAMPAIGNS
    if selection not in CAMPAIGNS:
        raise ValueError("invalid campaign selection")
    return (selection,)


def diagnostic_record(log, phase, status):
    """Bounded escaped fixture telemetry, never campaign acceptance."""
    if (not isinstance(log, str) or len(log.encode("utf-8")) > MAX_LOG
            or phase not in CAMPAIGNS
            or type(status) is not int or not 0 <= status <= 255):
        raise ValueError("invalid campaign diagnostics")
    return json.dumps({"format": "phantowd-qemu-campaign-diagnostic",
                       "schema_version": 1, "qualifying": False,
                       "phase": phase, "guest_exit": status, "log": log},
                      ensure_ascii=True, separators=(",", ":"))


def check_campaigns(service, native, candidate, lifecycle=None, fault=None,
                    data=None):
    costs = tuple(check_campaign(log, phase) for log, phase in zip(
        (service, native, candidate, lifecycle, fault, data), CAMPAIGNS))
    if any(costs[0][:2] != cost[:2] for cost in costs[1:]):
        raise ValueError("campaign runtime census differs")
    return costs


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
    verify.add_argument("--candidate-log")
    verify.add_argument("--lifecycle-log")
    verify.add_argument("--fault-log")
    verify.add_argument("--data-log")
    campaign = sub.add_parser("verify-campaign")
    campaign.add_argument("log")
    campaign.add_argument("phase", choices=CAMPAIGNS)
    selection = sub.add_parser("select-campaigns")
    selection.add_argument("selection", choices=("all", *CAMPAIGNS))
    diagnostics = sub.add_parser("diagnostic-log")
    diagnostics.add_argument("log")
    diagnostics.add_argument("phase", choices=CAMPAIGNS)
    diagnostics.add_argument("status", type=int)
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
    elif args.command == "select-campaigns":
        print(" ".join(select_campaigns(args.selection)))
    elif args.command == "diagnostic-log":
        if Path(args.log).is_symlink() or not Path(args.log).is_file():
            raise ValueError("regular fixture log required")
        print(diagnostic_record(read_bounded(args.log, MAX_LOG),
                                args.phase, args.status))
    else:
        log = read_bounded(args.log, MAX_LOG)
        paths = (args.native_log, args.candidate_log, args.lifecycle_log,
                 args.fault_log, args.data_log)
        if any(paths) and not all(paths):
            raise ValueError("all six campaign logs required")
        if args.native_log:
            costs = check_campaigns(
                log, *(read_bounded(path, MAX_LOG) for path in paths))
            for phase, (files, size, elapsed) in zip(
                    CAMPAIGNS[1:], costs[1:]):
                print(f"PHANTOWD_SAMBA_CAMPAIGN_SCAN_COST phase={phase} "
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
