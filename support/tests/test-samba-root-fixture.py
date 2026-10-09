#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Negative manifests and source-contract checks for a QEMU-only experiment."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import samba_root_fixture as fixture

CATALOG = """# Modules and aliases for: IBM850
alias CP850// IBM850//
alias 850// IBM850//
alias CSPC850MULTILINGUAL// IBM850//
alias OSF10020352// IBM850//
module IBM850// INTERNAL IBM850 1
module INTERNAL IBM850// IBM850 1
"""

SCAN_COST = ("PHANTOWD_RUNTIME_SCAN_COST files=104 bytes=12000000 "
             "elapsed_ns=123456789 scope=qemu-emulation-only")
CENSUS = ("PHANTOWD_SAMBA_ROOT_CENSUS_READY readonly=true "
          "complete_census=true hashes=true aliases=true "
          "negative_controls=false retained_control=false scope=qemu-only")


def merge(values):
    return fixture.merge(values, CATALOG)


def reports():
    return [{
        "format": "phantowd-elf-runtime-candidate", "schema_version": 1,
        "entry": entry, "static_dependencies_resolved": True,
        "runtime_qualified": False, "execution_authorized": False,
        "total_bytes": 200, "objects": [
            {"path": entry, "sha256": "a" * 64, "size": 100,
             "bindings": [entry]},
            {"path": "lib/ld-linux.so.3", "sha256": "b" * 64,
             "size": 100, "bindings": ["lib/ld-linux.so.3"]},
        ],
    } for entry in fixture.ENTRIES]


def campaign_rows():
    """Synthetic verifier inputs, not executed guest qualification."""
    enrollment = next(i for i, row in enumerate(fixture.MARKERS) if
                      row.startswith(
                          "PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY"))
    candidate = next(row for row in fixture.MARKERS if row.startswith(
        "PHANTOWD_SAMBA_OWNER_PLANNED_CANDIDATE_READY"))
    access = tuple(row for row in fixture.MARKERS if row.startswith((
        "PHANTOWD_SAMBA_OWNER_PLANNED_STARTUP_READY",
        "PHANTOWD_SAMBA_OWNER_PLANNED_DATA_READY",
        "PHANTOWD_SAMBA_OWNER_PLANNED_SUPERVISION_READY",
        "PHANTOWD_SAMBA_OWNER_PLANNED_STOP_READY")))
    census = [*fixture.MARKERS[:3], CENSUS, fixture.MARKERS[enrollment]]
    return {
        "service": [*fixture.MARKERS[:enrollment],
                    "PHANTOWD_SAMBA_ROOT_SERVICE_DONE", SCAN_COST],
        "native": [*fixture.MARKERS[:3], CENSUS,
                   *(row for row in fixture.MARKERS[enrollment:-4]
                     if row not in (*access, candidate,
                                    fixture.PLANNED_EXIT_FAULT_MARKER)),
                   "PHANTOWD_SAMBA_ROOT_NATIVE_DONE", SCAN_COST],
        "candidate": [*census, candidate,
                      "PHANTOWD_SAMBA_ROOT_CANDIDATE_DONE", SCAN_COST],
        "lifecycle": [*census, fixture.MARKERS[-4],
                      "PHANTOWD_SAMBA_ROOT_DONE", SCAN_COST],
        "fault": [*census, fixture.MARKERS[-3],
                  fixture.PLANNED_SOURCE_FAULT_MARKER,
                  "PHANTOWD_SAMBA_ROOT_FAULT_DONE", SCAN_COST],
        "data": [*census, *access,
                 "PHANTOWD_SAMBA_ROOT_DATA_DONE", SCAN_COST],
        "exit": [*census, fixture.PLANNED_EXIT_FAULT_MARKER,
                 "PHANTOWD_SAMBA_ROOT_EXIT_DONE", SCAN_COST],
        "held": [*census, fixture.PLANNED_HELD_CLOSE_MARKER,
                 "PHANTOWD_SAMBA_ROOT_HELD_DONE", SCAN_COST],
        "file": [*census, fixture.PLANNED_OPEN_FILE_MARKER,
                 "PHANTOWD_SAMBA_ROOT_FILE_DONE", SCAN_COST],
    }


class SambaRootFixture(unittest.TestCase):
    def test_complete_union_refuses_legacy_eight_without_open_file(self):
        logs = campaign_rows()
        old_phases = ("service", "native", "candidate", "lifecycle", "fault",
                      "data", "exit", "held")
        with self.assertRaises(ValueError):
            fixture.check_campaigns(
                *("\n".join(logs[phase]) for phase in old_phases))

    def test_open_file_probe_requires_original_object_proof(self):
        marker = (
            "PHANTOWD_SAMBA_OWNER_PLANNED_OPEN_FILE_READY "
            "same_authorities=true same_daemon=true data_verified=true "
            "original_object=true original_open=true "
            "exclusive_supervision=true "
            "accepted_cancellation=true client_daemon_stopped=true "
            "private_inputs=15 original_file_retained=true "
            "originals_busy=true "
            "old_observers_refused=true runtime_close_before_release=true "
            "repeated_close=true closed_refused=true no_fd_leak=true "
            "activation=false scope=qemu-only")
        enrollment = next(row for row in fixture.MARKERS if row.startswith(
            "PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY"))
        rows = [*fixture.MARKERS[:3], CENSUS, enrollment, marker,
                "PHANTOWD_SAMBA_ROOT_FILE_DONE", SCAN_COST]
        fixture.check_campaign("\n".join(rows), "file")
        self.assertEqual(fixture.select_campaigns("file"), ("file",))
        self.assertIn("file", fixture.select_campaigns("all"))
        for field in ("original_object", "original_open",
                      "original_file_retained",
                      "originals_busy", "client_daemon_stopped",
                      "runtime_close_before_release", "no_fd_leak"):
            for replacement in ("", field + "=false"):
                with self.subTest(field=field, replacement=replacement):
                    with self.assertRaises(ValueError):
                        fixture.check_campaign("\n".join(rows).replace(
                            field + "=true", replacement), "file")
        for replacement in ("", fixture.PLANNED_HELD_CLOSE_MARKER,
                            marker + "\n" + marker):
            with self.assertRaises(ValueError):
                fixture.check_campaign("\n".join(rows).replace(
                    marker, replacement), "file")

    def test_held_cancellation_requires_separate_complete_close_proof(self):
        marker = (
            "PHANTOWD_SAMBA_OWNER_PLANNED_HELD_CLOSE_READY "
            "same_authorities=true same_daemon=true data_verified=true "
            "original_session=true exclusive_supervision=true "
            "accepted_cancellation=true client_daemon_stopped=true "
            "private_inputs=15 originals_retained=true "
            "old_observers_refused=true runtime_close_before_release=true "
            "repeated_close=true closed_refused=true no_fd_leak=true "
            "activation=false scope=qemu-only")
        enrollment = next(row for row in fixture.MARKERS if row.startswith(
            "PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY"))
        rows = [*fixture.MARKERS[:3], CENSUS, enrollment, marker,
                "PHANTOWD_SAMBA_ROOT_HELD_DONE", SCAN_COST]
        fixture.check_campaign("\n".join(rows), "held")
        for field in ("same_authorities", "same_daemon", "data_verified",
                      "original_session", "exclusive_supervision",
                      "accepted_cancellation", "client_daemon_stopped",
                      "originals_retained", "old_observers_refused",
                      "runtime_close_before_release", "repeated_close",
                      "closed_refused", "no_fd_leak"):
            for replacement in ("", field + "=false"):
                with self.subTest(field=field, replacement=replacement):
                    changed = marker.replace(field + "=true", replacement)
                    with self.assertRaises(ValueError):
                        fixture.check_campaign("\n".join(
                            changed if row == marker else row for row in rows),
                            "held")
        for replacement in ("", marker + "\n" + marker,
                            marker.replace("private_inputs=15",
                                           "private_inputs=14"),
                            marker.replace("activation=false",
                                           "activation=true"),
                            marker.replace("scope=qemu-only",
                                           "scope=product")):
            with self.assertRaises(ValueError):
                fixture.check_campaign("\n".join(rows).replace(
                    marker, replacement), "held")

    def test_native_pair_continuity_requires_both_new_observations(self):
        marker = next(row for row in fixture.MARKERS if row.startswith(
            "PHANTOWD_SAMBA_OWNER_NATIVE_LIVE_REVOKE_READY"))
        fields = ("original_pair_rechecked", "revoked_pair_refused")
        for field in fields:
            self.assertIn(field + "=true", marker)
        rows = campaign_rows()["native"]
        fixture.check_campaign("\n".join(rows), "native")
        for field in fields:
            for replacement in ("", field + "=false"):
                changed = marker.replace(field + "=true", replacement)
                log = "\n".join(changed if row == marker else row
                                for row in rows)
                with self.assertRaises(ValueError):
                    fixture.check_campaign(log, "native")

    def test_planned_exit_requires_separate_owned_reviewed_stop_proof(self):
        proof = (
            "PHANTOWD_SAMBA_OWNER_PLANNED_EXIT_FAULT_READY "
            "same_authorities=true same_daemon=true data_verified=true "
            "original_handle=true single_use=true exclusive_supervision=true "
            "review_sticky=true stopped_reaped=true private_inputs=15 "
            "capture_retained=true capture_before_worker=true "
            "runtime_inputs_retained=true originals_busy=true "
            "restart_refused=true normal_stop_refused=true "
            "private_mount_namespace=true subprocess_disposal=true "
            "parent_fd_equal=true activation=false scope=qemu-only")
        self.assertIn(proof, fixture.MARKERS)

        logs = {phase: "\n".join(rows)
                for phase, rows in campaign_rows().items()}
        fixture.check_campaign(logs["exit"], "exit")
        for replacement in ("", proof + "\n" + proof,
                            proof.replace("original_handle=true",
                                          "original_handle=false"),
                            proof.replace("single_use=true",
                                          "single_use=false"),
                            proof.replace("stopped_reaped=true",
                                          "stopped_reaped=false"),
                            proof.replace("capture_retained=true",
                                          "capture_retained=false"),
                            proof.replace("capture_before_worker=true",
                                          "capture_before_worker=false"),
                            proof.replace("originals_busy=true",
                                          "originals_busy=false"),
                            proof.replace("normal_stop_refused=true",
                                          "normal_stop_refused=false")):
            with self.subTest(replacement=replacement):
                with self.assertRaises(ValueError):
                    fixture.check_campaign(
                        logs["exit"].replace(proof, replacement), "exit")
        for phase in fixture.CAMPAIGNS:
            if phase != "exit":
                with self.assertRaises(ValueError):
                    fixture.check_campaign(logs[phase] + "\n" + proof, phase)

    def test_planned_source_fault_requires_stop_retention_and_nonrevival(self):
        proof = (
            "PHANTOWD_SAMBA_OWNER_PLANNED_SOURCE_FAULT_READY "
            "same_authorities=true same_daemon=true data_verified=true "
            "original_session=true held_client_stopped=true "
            "held_client_retained=true old_observers_refused=true "
            "source_covered=true exclusive_supervision=true "
            "review_sticky=true stopped_reaped=true private_inputs=15 "
            "runtime_inputs_retained=true originals_busy=true "
            "cover_removed=true restoration_refused=true close_refused=true "
            "private_mount_namespace=true subprocess_disposal=true "
            "parent_fd_equal=true activation=false scope=qemu-only")
        self.assertIn(proof, fixture.MARKERS)
        logs = {phase: "\n".join(rows)
                for phase, rows in campaign_rows().items()}
        fixture.check_campaign(logs["fault"], "fault")
        for replacement in ("", proof + "\n" + proof,
                            proof.replace("stopped_reaped=true",
                                          "stopped_reaped=false"),
                            proof.replace("originals_busy=true",
                                          "originals_busy=false"),
                            proof.replace("restoration_refused=true",
                                          "restoration_refused=false"),
                            proof.replace("close_refused=true",
                                          "close_refused=false"),
                            proof.replace("close_refused=true ", ""),
                            proof.replace("private_inputs=15",
                                          "private_inputs=13"),
                            *(proof.replace(field + "=true", field + "=false")
                              for field in ("original_session",
                                            "held_client_stopped",
                                            "held_client_retained",
                                            "old_observers_refused")),
                            *(proof.replace(field + "=true ", "")
                              for field in ("original_session",
                                            "held_client_stopped",
                                            "held_client_retained",
                                            "old_observers_refused"))):
            with self.subTest(replacement=replacement):
                with self.assertRaises(ValueError):
                    fixture.check_campaign(
                        logs["fault"].replace(proof, replacement), "fault")
        for phase in fixture.CAMPAIGNS:
            if phase != "fault":
                with self.assertRaises(ValueError):
                    fixture.check_campaign(logs[phase] + "\n" + proof, phase)

    def test_planned_stop_requires_private_inputs_and_owned_daemon_proof(self):
        proof = (
            "PHANTOWD_SAMBA_OWNER_PLANNED_STOP_READY "
            "same_daemon=true private_inputs=15 runtime_inputs_retained=true "
            "live_not_stopped=true stopped_reaped=true "
            "legacy_clients_guard=true repeated_readonly=true "
            "closed_refused=true no_fd_leak=true activation=false "
            "scope=qemu-only")
        self.assertIn(proof, fixture.MARKERS)
        rows = campaign_rows()
        good = "\n".join(rows["data"])
        fixture.check_campaign(good, "data")
        for replacement in ("", proof + "\n" + proof,
                            proof.replace("private_inputs=15",
                                          "private_inputs=13"),
                            proof.replace("stopped_reaped=true",
                                          "stopped_reaped=false"),
                            proof.replace("legacy_clients_guard=true",
                                          "legacy_clients_guard=false"),
                            proof.replace("activation=false",
                                          "activation=true")):
            with self.subTest(replacement=replacement):
                with self.assertRaises(ValueError):
                    fixture.check_campaign(good.replace(proof, replacement),
                                           "data")
        for phase in fixture.CAMPAIGNS:
            if phase != "data":
                with self.subTest(wrong_phase=phase):
                    with self.assertRaises(ValueError):
                        fixture.check_campaign(
                            "\n".join(rows[phase] + [proof]), phase)

    def test_planned_supervision_is_required_once_in_the_data_trace(self):
        rows = campaign_rows()
        proof = (
            "PHANTOWD_SAMBA_OWNER_PLANNED_SUPERVISION_READY "
            "same_authorities=true complete_scan=true serialized=true "
            "cancellation_stopped=true originals_retained=true "
            "restart_refused=true close_before_release=true "
            "stopped_reaped=true no_fd_leak=true "
            "activation=false scope=qemu-only")
        valid = [row for row in rows["data"] if row != proof]
        valid.insert(-3, proof)
        fixture.check_campaign("\n".join(valid), "data")
        with self.assertRaises(ValueError):
            fixture.check_campaign(
                "\n".join(row for row in valid if row != proof), "data")
        with self.assertRaises(ValueError):
            fixture.check_campaign("\n".join(valid + [proof]), "data")
        for phase in fixture.CAMPAIGNS:
            if phase != "data":
                with self.subTest(wrong_phase=phase):
                    with self.assertRaises(ValueError):
                        fixture.check_campaign(
                            "\n".join(rows[phase] + [proof]), phase)

    def test_all_requires_independent_candidate_startup_fault_traces(self):
        rows = campaign_rows()
        phases = ("service", "native", "candidate", "lifecycle", "fault",
                  "data", "exit", "held", "file")
        logs = tuple("\n".join(rows[phase]) for phase in phases)
        self.assertEqual(fixture.check_campaigns(*logs),
                         ((104, 12000000, 123456789),) * 9)
        self.assertEqual(fixture.select_campaigns("all"), phases)
        self.assertEqual({row for values in rows.values() for row in values
                          if row in fixture.MARKERS}, set(fixture.MARKERS))

    def test_complete_cli_requires_all_nine_ordered_campaign_logs(self):
        with tempfile.TemporaryDirectory() as scratch:
            paths = {}
            for phase, rows in campaign_rows().items():
                path = Path(scratch) / (phase + ".log")
                path.write_text("\n".join(rows), encoding="utf-8")
                paths[phase] = str(path)
            base = [sys.executable, "-B", str(Path(fixture.__file__)),
                    "verify", paths["service"]]
            pairs = [["--" + phase + "-log", paths[phase]]
                     for phase in ("native", "candidate", "lifecycle",
                                   "fault", "data", "exit", "held", "file")]
            complete = [item for pair in pairs for item in pair]
            result = subprocess.run(base + complete, capture_output=True,
                                    text=True, check=False, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines().count(
                fixture.PLANNED_OPEN_FILE_MARKER), 1)
            fixture.check_guest("\n".join(
                row for row in result.stdout.splitlines()
                if row != fixture.PLANNED_OPEN_FILE_MARKER))
            for omitted in range(len(pairs)):
                partial = [item for index, pair in enumerate(pairs)
                           if index != omitted for item in pair]
                with self.subTest(omitted=omitted):
                    result = subprocess.run(
                        base + partial, capture_output=True, text=True,
                        check=False, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")

    def test_new_data_guest_is_required_without_replacing_old_campaigns(self):
        rows = tuple(campaign_rows().values())
        logs = tuple("\n".join(values) for values in rows)
        self.assertEqual(fixture.check_campaigns(*logs),
                         ((104, 12000000, 123456789),) * 9)
        self.assertEqual(fixture.select_campaigns("all"),
                         ("service", "native", "candidate", "lifecycle",
                          "fault", "data", "exit", "held", "file"))
        self.assertEqual(fixture.check_campaign(logs[5], "data"),
                         (104, 12000000, 123456789))
        self.assertEqual({row for values in rows for row in values
                          if row in fixture.MARKERS}, set(fixture.MARKERS))
        with self.assertRaises(ValueError):
            fixture.check_campaigns(*logs[:5])
        for omitted in rows[5][:-1]:
            with self.subTest(omitted=omitted):
                with self.assertRaises(ValueError):
                    fixture.check_campaigns(*logs[:5],
                                            logs[5].replace(omitted, ""),
                                            logs[6])

    def test_independent_lookup_moves_once_without_borrowed_native_state(self):
        enrollment = next(
            i for i, row in enumerate(fixture.MARKERS)
            if row.startswith("PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY"))
        logs = tuple("\n".join(rows) for rows in campaign_rows().values())
        fixture.check_campaigns(*logs)
        split = next(i for i, row in enumerate(fixture.MARKERS) if
                     row.startswith("PHANTOWD_SAMBA_OWNER_NATIVE_NSS_READY"))
        for proof in fixture.MARKERS[split:enrollment]:
            for other in logs[1:]:
                self.assertNotIn(proof, other)
            with self.assertRaises(ValueError):
                fixture.check_campaigns(logs[0].replace(proof, ""),
                                        *logs[1:])
            with self.assertRaises(ValueError):
                fixture.check_campaigns(logs[0], logs[1] + "\n" + proof,
                                        *logs[2:])

    def test_planned_data_requires_actual_retained_access_proof(self):
        marker = (
            "PHANTOWD_SAMBA_OWNER_PLANNED_DATA_READY "
            "same_authorities=true same_daemon=true granted_only=true "
            "ungranted_enabled_denied=true "
            "smb_read=true smb_write=true unix_owner=true readonly_EROFS=true "
            "readonly_denied=true symlink_denied=true fresh_observation=true "
            "stopped_before_release=true no_fd_leak=true "
            "activation=false scope=qemu-only")
        native_split = next(
            i for i, row in enumerate(fixture.MARKERS)
            if row.startswith("PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY"))
        startup = next(row for row in fixture.MARKERS if row.startswith(
            "PHANTOWD_SAMBA_OWNER_PLANNED_STARTUP_READY"))
        rows = [*fixture.MARKERS[:3], CENSUS,
                fixture.MARKERS[native_split], startup,
                marker, next(row for row in fixture.MARKERS if row.startswith(
                    "PHANTOWD_SAMBA_OWNER_PLANNED_SUPERVISION_READY")),
                next(row for row in fixture.MARKERS if row.startswith(
                    "PHANTOWD_SAMBA_OWNER_PLANNED_STOP_READY")),
                "PHANTOWD_SAMBA_ROOT_DATA_DONE", SCAN_COST]
        good = "\n".join(rows)
        fixture.check_campaign(good, "data")
        for replacement in ("", marker + "\n" + marker,
                            marker.replace("same_daemon=true",
                                           "same_daemon=false"),
                            marker.replace("same_authorities=true",
                                           "same_authorities=false"),
                            marker.replace("readonly_EROFS=true",
                                           "readonly_EROFS=false"),
                            marker.replace("ungranted_enabled_denied=true",
                                           "ungranted_enabled_denied=false"),
                            marker.replace("activation=false",
                                           "activation=true")):
            with self.subTest(replacement=replacement):
                with self.assertRaises(ValueError):
                    fixture.check_campaign(good.replace(marker, replacement),
                                           "data")
        with self.assertRaises(ValueError):
            fixture.check_campaign(good, "native")
        with self.assertRaises(ValueError):
            fixture.check_campaign(good, "lifecycle")

    def test_planned_startup_requires_complete_retained_authorities(self):
        marker = (
            "PHANTOWD_SAMBA_OWNER_PLANNED_STARTUP_READY "
            "owner=actual_native_backend storage=mounted_roster "
            "same_authorities=true granted_only=true service_role=true "
            "original_views=true before_start_busy=true after_start_busy=true "
            "duplicate_refused=true canceled_start_refused=true "
            "fresh_observation=true runtime_close_before_release=true "
            "stopped_reaped=true no_fd_leak=true samba_data=false "
            "activation=false scope=qemu-only")
        split = next(
            i for i, row in enumerate(fixture.MARKERS)
            if row.startswith("PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY"))
        self.assertIn(marker, fixture.MARKERS)
        data = next(row for row in fixture.MARKERS if row.startswith(
            "PHANTOWD_SAMBA_OWNER_PLANNED_DATA_READY"))
        rows = [*fixture.MARKERS[:3], CENSUS, fixture.MARKERS[split],
                marker, data,
                next(row for row in fixture.MARKERS if row.startswith(
                    "PHANTOWD_SAMBA_OWNER_PLANNED_SUPERVISION_READY")),
                next(row for row in fixture.MARKERS if row.startswith(
                    "PHANTOWD_SAMBA_OWNER_PLANNED_STOP_READY")),
                "PHANTOWD_SAMBA_ROOT_DATA_DONE", SCAN_COST]
        good = "\n".join(rows)
        fixture.check_campaign(good, "data")
        for invalid in (good.replace(marker, ""),
                        good.replace(marker, marker + "\n" + marker),
                        good.replace("same_authorities=true",
                                     "same_authorities=false"),
                        good.replace("original_views=true",
                                     "original_views=false"),
                        good.replace("activation=false", "activation=true")):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    fixture.check_campaign(invalid, "data")
        with self.assertRaises(ValueError):
            fixture.check_campaign(good, "native")
        with self.assertRaises(ValueError):
            fixture.check_campaign(good, "lifecycle")

    def test_native_phase_timing_cannot_replace_or_weaken_acceptance(self):
        timings = "\n".join(
            "PHANTOWD_DIAG_NATIVE_PHASE phase=" + phase
            + " elapsed_ms=123 qualifying=false scope=qemu-only"
            for phase in ("entered", "admitted", "enrolled",
                          "authority-closed", "data-verified"))
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(timings + "\n" + good)
        with self.assertRaises(ValueError):
            fixture.check_guest(timings + "\n" + SCAN_COST)
        for marker in fixture.MARKERS:
            with self.subTest(missing=marker):
                with self.assertRaises(ValueError):
                    fixture.check_guest(
                        timings + "\n" + good.replace(marker, ""))
        native_split = next(
            i for i, row in enumerate(fixture.MARKERS)
            if row.startswith("PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY"))
        planned = next(row for row in fixture.MARKERS
                       if row.startswith(
                           "PHANTOWD_SAMBA_OWNER_PLANNED_CANDIDATE_READY"))
        native = [*fixture.MARKERS[:3], CENSUS,
                  *(row for row in fixture.MARKERS[native_split:-4]
                    if row != planned and not row.startswith((
                        "PHANTOWD_SAMBA_OWNER_PLANNED_STARTUP_READY",
                        "PHANTOWD_SAMBA_OWNER_PLANNED_DATA_READY",
                        "PHANTOWD_SAMBA_OWNER_PLANNED_SUPERVISION_READY",
                        "PHANTOWD_SAMBA_OWNER_PLANNED_STOP_READY",
                        "PHANTOWD_SAMBA_OWNER_PLANNED_EXIT_FAULT_READY"))),
                  "PHANTOWD_SAMBA_ROOT_NATIVE_DONE",
                  SCAN_COST]
        fixture.check_campaign(timings + "\n" + "\n".join(native),
                               "native")
        for marker in native[:-1]:
            with self.subTest(native_missing=marker):
                with self.assertRaises(ValueError):
                    fixture.check_campaign(
                        timings + "\n" + "\n".join(native).replace(
                            marker, ""), "native")

    def test_diagnostic_record_is_bounded_nonqualifying_and_escaped(self):
        log = 'phase\nPHANTOWD_SAMBA_ROOT_DONE\n\x1b[31m'
        encoded = fixture.diagnostic_record(log, "lifecycle", 0)
        self.assertNotIn("\n", encoded)
        self.assertNotIn("\x1b", encoded)
        record = json.loads(encoded)
        self.assertEqual(record["format"],
                         "phantowd-qemu-campaign-diagnostic")
        self.assertEqual(record["schema_version"], 1)
        self.assertIs(record["qualifying"], False)
        self.assertEqual(record["log"], log)
        self.assertEqual(record["phase"], "lifecycle")
        self.assertEqual(record["guest_exit"], 0)
        with self.assertRaises(ValueError):
            fixture.check_campaign(encoded, "lifecycle")

    def test_diagnostic_record_refuses_invalid_inputs(self):
        for log, phase, status in ((None, "native", 0),
                                   ("x" * (fixture.MAX_LOG + 1), "native", 0),
                                   ("x", "all", 0), ("x", "../native", 0),
                                   ("x", "native", -1),
                                   ("x", "native", 256),
                                   ("x", "native", True)):
            with self.assertRaises(ValueError):
                fixture.diagnostic_record(log, phase, status)

    def test_diagnostic_cli_preserves_success_and_timeout_logs(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "guest.log"
            path.write_bytes(b"partial fixture\n")
            command = [sys.executable, "-B", str(Path(fixture.__file__)),
                       "diagnostic-log", str(path), "native"]
            for status in (0, 124):
                result = subprocess.run(command + [str(status)],
                                        capture_output=True, text=True,
                                        check=False, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                record = json.loads(result.stdout)
                self.assertIs(record["qualifying"], False)
                self.assertEqual(record["guest_exit"], status)
                self.assertEqual(record["log"], "partial fixture\n")

    def test_campaign_selection_defaults_to_complete_proof(self):
        self.assertEqual(fixture.select_campaigns("all"),
                         ("service", "native", "candidate", "lifecycle",
                          "fault", "data", "exit", "held", "file"))

    @unittest.skipUnless(os.name == "posix", "POSIX driver admission")
    def test_invalid_diagnostic_mode_never_calls_python(self):
        driver = Path(__file__).resolve().with_name(
            "test-qemu-samba-root.sh")
        with tempfile.TemporaryDirectory() as scratch:
            python = Path(scratch) / "python3"
            python.write_text(
                "#!/bin/sh\necho unexpected-python >&2\nexit 73\n")
            python.chmod(0o700)
            env = dict(os.environ, PATH=scratch + ":/usr/bin:/bin",
                       TMPDIR="/tmp")
            for extra in (("DIAGNOSTIC",), ("diagnostic;true",),
                          ("none", "extra")):
                result = subprocess.run(
                    ["sh", str(driver), *(["/unused"] * 6), "",
                     "lifecycle", *extra], env=env, check=False,
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")

    def test_campaign_selection_is_one_exact_phase(self):
        for phase in ("service", "native", "candidate", "lifecycle", "fault",
                      "data", "exit"):
            self.assertEqual(fixture.select_campaigns(phase), (phase,))

    def test_campaign_selection_refuses_untrusted_values(self):
        for value in (None, "", "ALL", "native lifecycle", "../native",
                      "native;true", ["lifecycle"]):
            with self.assertRaises(ValueError):
                fixture.select_campaigns(value)

    def test_campaign_selection_cli_has_exact_output(self):
        command = [sys.executable, "-B", str(Path(fixture.__file__)),
                   "select-campaigns"]
        for selection in ("all", "service", "native", "candidate", "lifecycle",
                          "fault", "data", "exit", "held", "file"):
            result = subprocess.run(command + [selection], check=False,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(result.stdout,
                             " ".join(fixture.select_campaigns(selection))
                             + "\n")
        for invalid in ("", "ALL", "native;true", "native lifecycle"):
            result = subprocess.run(command + [invalid], check=False,
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")

    def test_focused_completion_is_not_full_qualification(self):
        focused = ("PHANTOWD_SAMBA_FOCUSED_COMPLETE campaign=lifecycle "
                   "base_unchanged=true complete_image=false scope=qemu-only")
        with self.assertRaises(ValueError):
            fixture.check_guest(focused + "\n" + SCAN_COST)

    @unittest.skipUnless(os.name == "posix", "POSIX driver admission")
    def test_invalid_driver_selection_never_calls_python(self):
        driver = Path(__file__).resolve().with_name(
            "test-qemu-samba-root.sh")
        with tempfile.TemporaryDirectory() as scratch:
            python = Path(scratch) / "python3"
            python.write_text(
                "#!/bin/sh\necho unexpected-python >&2\nexit 73\n")
            python.chmod(0o700)
            env = dict(os.environ, PATH=scratch + ":/usr/bin:/bin",
                       TMPDIR="/tmp")
            for invalid in ("--help", "ALL", "native;true", "all service"):
                result = subprocess.run(
                    ["sh", str(driver), *(["/unused"] * 6), "", invalid],
                    env=env, check=False, capture_output=True, text=True,
                    timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")

    def test_native_data_requires_access_and_settlement(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_DATA_READY "
                    "original_objects=true individual_clones=true "
                    "readonly_EROFS=true smb_read=true smb_write=true "
                    "unix_owner=true symlink_denied=true "
                    "private_namespace=true stopped_before_release=true "
                    "no_fd_leak=true complete_storage_identity=false "
                    "scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("original_objects", "individual_clones",
                      "readonly_EROFS",
                      "smb_read", "smb_write", "unix_owner", "symlink_denied",
                      "private_namespace", "stopped_before_release",
                      "no_fd_leak"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    altered = expected.replace(field + "=true",
                                               field + "=false")
                    fixture.check_guest(good.replace(expected, altered))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("complete_storage_identity=false",
                                             "complete_storage_identity=true"),
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_planned_candidate_requires_native_roster_not_activation(self):
        expected = (
            "PHANTOWD_SAMBA_OWNER_PLANNED_CANDIDATE_READY "
            "owner=actual_native_backend storage=mounted_roster "
            "locked_plan=true exact_declaration=true original_objects=true "
            "caller_close=true fresh_recompiled=true rendered=true "
            "granted_only=true paired_lookup=true management_complete=true "
            "shared_globals=true management_bound=true protected_role=true "
            "management_unchanged=true prepared_inputs=true "
            "service_config_bound=true share_inputs_bound=true "
            "coordinator_bound=true same_roster=true policy_copy=true "
            "startup_blocked=true identity_retained=true "
            "handoff_close_gated=true desired_roundtrip=true "
            "journals_unchanged=true stale_refused=true "
            "runtime_close_before_release=true released=true "
            "samba_data=false activation=false scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("locked_plan", "exact_declaration", "original_objects",
                      "caller_close", "fresh_recompiled", "rendered",
                      "granted_only", "paired_lookup", "management_complete",
                      "shared_globals", "management_bound", "protected_role",
                      "management_unchanged", "prepared_inputs",
                      "service_config_bound", "share_inputs_bound",
                      "coordinator_bound", "same_roster", "policy_copy",
                      "startup_blocked", "identity_retained",
                      "handoff_close_gated", "desired_roundtrip",
                      "journals_unchanged", "stale_refused",
                      "runtime_close_before_release", "released"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    altered = expected.replace(field + "=true",
                                               field + "=false")
                    fixture.check_guest(good.replace(expected, altered))
        for replacement in (
                "", expected + "\n" + expected,
                expected.replace("actual_native_backend", "synthetic"),
                expected.replace("mounted_roster", "synthetic"),
                expected.replace("samba_data=false", "samba_data=true"),
                expected.replace("activation=false", "activation=true"),
                expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_nine_bounded_campaigns_require_every_original_proof(self):
        split = next(i for i, row in enumerate(fixture.MARKERS)
                     if row.startswith(
                         "PHANTOWD_SAMBA_OWNER_NATIVE_NSS_READY"))
        enrollment = next(i for i, row in enumerate(fixture.MARKERS)
                          if row.startswith(
                              "PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY"))
        planned = next(row for row in fixture.MARKERS
                       if row.startswith(
                           "PHANTOWD_SAMBA_OWNER_PLANNED_CANDIDATE_READY"))
        rows = campaign_rows()
        good = ["\n".join(values) for values in rows.values()]
        # Every original contract remains mandatory in the complete union.
        # Lifecycle must not claim the idle-disable proof exercised in native.
        covered = {row for values in rows.values() for row in values
                   if row in fixture.MARKERS}
        self.assertEqual(covered, set(fixture.MARKERS))
        self.assertIn(fixture.PLANNED_OPEN_FILE_MARKER, rows["file"])
        # Each fresh native guest inspects its OWN complete code census. All
        # independent negative/retention experiments stay mandatory in service,
        # never asserted by a guest that did not run them. New data work has
        # its own boot, with genuine enrollment and no inherited passdb/state.
        for proof in fixture.MARKERS[3:5]:
            self.assertIn(proof, rows["service"])
            self.assertNotIn(proof, rows["native"])
            self.assertNotIn(proof, rows["lifecycle"])
            self.assertNotIn(proof, rows["data"])
        self.assertFalse(any("NATIVE_IDLE_DISABLE_READY" in row
                             for row in rows["lifecycle"]))
        self.assertTrue(any("NATIVE_IDLE_DISABLE_READY" in row
                            for row in rows["native"]))
        self.assertNotIn(planned, rows["native"])
        self.assertIn(planned, rows["candidate"])
        self.assertNotIn(planned, rows["lifecycle"])
        self.assertNotIn(planned, rows["fault"])
        # Independent libc/config/handoff scenarios run once, in service.
        # Each native guest still creates its OWN real identities and enrolls
        # both accounts; it cannot borrow state or proof from another guest.
        for proof in fixture.MARKERS[split:enrollment]:
            self.assertIn(proof, rows["service"])
            self.assertNotIn(proof, rows["native"])
            self.assertNotIn(proof, rows["lifecycle"])
            self.assertNotIn(proof, rows["data"])
        self.assertEqual(fixture.check_campaigns(*good),
                         ((104, 12000000, 123456789),) * 9)
        for index, phase in enumerate(rows):
            self.assertEqual(fixture.check_campaign(good[index], phase),
                             (104, 12000000, 123456789))
            for row_index in range(len(rows[phase])):
                changed = list(good)
                changed[index] = "\n".join(
                    rows[phase][:row_index] + rows[phase][row_index + 1:])
                with self.assertRaises(ValueError):
                    fixture.check_campaigns(*changed)
            for altered in (good[index] + "\n" + rows[phase][0],
                            good[(index + 1) % len(fixture.CAMPAIGNS)],
                            good[index].replace("files=104", "files=105")):
                changed = list(good)
                changed[index] = altered
                with self.assertRaises(ValueError):
                    fixture.check_campaigns(*changed)

        for index in range(1, len(fixture.CAMPAIGNS)):
            for field in ("readonly", "complete_census", "hashes", "aliases"):
                changed = list(good)
                changed[index] = good[index].replace(
                    CENSUS, CENSUS.replace(field + "=true", field + "=false"))
                with self.assertRaises(ValueError):
                    fixture.check_campaigns(*changed)
            for field in ("negative_controls", "retained_control"):
                changed = list(good)
                changed[index] = good[index].replace(
                    CENSUS, CENSUS.replace(field + "=false", field + "=true"))
                with self.assertRaises(ValueError):
                    fixture.check_campaigns(*changed)

    def test_native_identity_fault_requires_review_and_settlement(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_IDENTITY_FAULT_READY "
                    "state_drift=true before_worker=true "
                    "pending_retained=true groups_stopped=true "
                    "capture_settled=true authority_busy=true "
                    "inputs_retained=true restoration_refused=true "
                    "close_no_retry=true subprocess_disposal=true "
                    "no_fd_leak=true service_owner=false scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("state_drift", "before_worker", "pending_retained",
                      "groups_stopped", "capture_settled", "authority_busy",
                      "inputs_retained", "restoration_refused",
                      "close_no_retry",
                      "subprocess_disposal", "no_fd_leak"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                altered = expected.replace(field + "=true",
                                           field + "=false", 1)
                fixture.check_guest(good.replace(expected, altered, 1))
        for bad in (good.replace(expected + "\n", "", 1),
                    good.replace(expected, expected + "\n" + expected, 1),
                    good.replace(expected, expected.replace(
                        "service_owner=false", "service_owner=true"), 1),
                    good.replace(expected, expected.replace(
                        "scope=qemu-only", "scope=product"), 1)):
            with self.assertRaises(ValueError):
                fixture.check_guest(bad)

    def test_native_identity_startup_requires_complete_retention(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_IDENTITY_STARTUP_READY "
                    "startup_bound=true exact_backend=true "
                    "before_start_busy=true after_start_busy=true "
                    "duplicate_refused=true canceled_start_refused=true "
                    "complete_observation=true serialized_scans=true "
                    "accepted_cancellation=true stopped_reaped=true "
                    "close_before_release=true no_fd_leak=true "
                    "coordinator_disable=true qualified_pair=true "
                    "same_peer_session=true target_denied=true "
                    "stale_revision_refused=true "
                    "canceled_disable_refused=true "
                    "serialized_disable=true "
                    "prepared_disable_refused=true "
                    "stopped_disable_refused=true "
                    "service_owner=false scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("startup_bound", "exact_backend", "before_start_busy",
                      "after_start_busy", "duplicate_refused",
                      "canceled_start_refused", "complete_observation",
                      "serialized_scans", "accepted_cancellation",
                      "stopped_reaped", "close_before_release", "no_fd_leak",
                      "coordinator_disable", "qualified_pair",
                      "same_peer_session", "target_denied",
                      "stale_revision_refused", "canceled_disable_refused",
                      "serialized_disable", "prepared_disable_refused",
                      "stopped_disable_refused"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                altered = expected.replace(field + "=true",
                                           field + "=false", 1)
                fixture.check_guest(good.replace(expected, altered, 1))
        for bad in (good.replace(expected + "\n", "", 1),
                    good.replace(expected, expected + "\n" + expected, 1),
                    good.replace(expected, expected.replace(
                        "service_owner=false", "service_owner=true"), 1),
                    good.replace(expected, expected.replace(
                        "scope=qemu-only", "scope=product"), 1)):
            with self.assertRaises(ValueError):
                fixture.check_guest(bad)

    def test_native_disable_handoff_requires_retention_until_stop(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_DISABLE_HANDOFF_READY "
                    "owner_bound=true backend_bound=true "
                    "atomic_successor=true "
                    "old_review=true new_verified=true close_busy=true "
                    "same_peer_session=true retained_until_stop=true "
                    "stopped_reaped=true no_fd_leak=true "
                    "startup_bound=false service_owner=false scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("owner_bound", "backend_bound", "atomic_successor",
                      "old_review", "new_verified", "close_busy",
                      "same_peer_session", "retained_until_stop",
                      "stopped_reaped", "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("startup_bound=false",
                                             "startup_bound=true"),
                            expected.replace("service_owner=false",
                                             "service_owner=true"),
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_native_backend_binding_requires_complete_readonly_probe(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_BACKEND_BINDING_READY "
                    "owner_bound=true backend_bound=true "
                    "unchanged_verified=true foreign_refused=true "
                    "close_busy=true released_before_start=true "
                    "release_no_mutation=true stopped_reaped=true "
                    "no_fd_leak=true service_owner=false scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("owner_bound", "backend_bound", "unchanged_verified",
                      "foreign_refused", "close_busy", "released_before_start",
                      "release_no_mutation", "stopped_reaped", "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("service_owner=false",
                                             "service_owner=true"),
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_native_live_revoke_requires_real_pair_and_peer_continuity(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_LIVE_REVOKE_READY "
                    "accounts=2 qualified_pair=true "
                    "original_pair_rechecked=true revoked_pair_refused=true "
                    "owner_bound=true "
                    "same_sid=true target_absent=true same_peer_session=true "
                    "new_login_denied=true other_login_allowed=true "
                    "same_daemon=true no_new_privileges=true "
                    "stopped_reaped=true no_fd_leak=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("qualified_pair", "original_pair_rechecked",
                      "revoked_pair_refused", "owner_bound", "same_sid",
                      "target_absent", "same_peer_session", "new_login_denied",
                      "other_login_allowed", "same_daemon",
                      "no_new_privileges",
                      "stopped_reaped", "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("accounts=2", "accounts=1"),
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_native_idle_disable_requires_owner_and_live_worker_proof(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_IDLE_DISABLE_READY "
                    "owner_bound=true same_sid=true stable_absence=true "
                    "new_login_denied=true other_login_allowed=true "
                    "same_daemon=true no_new_privileges=true "
                    "stopped_reaped=true no_fd_leak=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("owner_bound", "same_sid", "stable_absence",
                      "new_login_denied", "other_login_allowed",
                      "same_daemon", "no_new_privileges", "stopped_reaped",
                      "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_native_daemon_requires_same_state_authentication(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_DAEMON_READY accounts=2 "
                    "same_code=true same_config=true same_state=true "
                    "authenticated=true wrong_password_denied=true "
                    "owned_group=true stopped_reaped=true no_fd_leak=true "
                    "scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("same_code", "same_config", "same_state",
                      "authenticated", "wrong_password_denied",
                      "owned_group", "stopped_reaped", "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("accounts=2", "accounts=1"),
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_campaigns_cannot_substitute_two_for_three_proofs(self):
        split = next(i for i, row in enumerate(fixture.MARKERS)
                     if row.startswith(
                         "PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY"))
        service = [*fixture.MARKERS[:split],
                   "PHANTOWD_SAMBA_ROOT_SERVICE_DONE", SCAN_COST]
        native = [*fixture.MARKERS[:5], *fixture.MARKERS[split:], SCAN_COST]
        good_service, good_native = "\r\n".join(service), "\r\n".join(native)
        for first, second in ((good_native, good_service),
                              (good_service, good_service),
                              (good_native, good_native),
                              (good_service, good_native + "\n" + native[0]),
                              (good_service, good_native.replace(
                                  "files=104", "files=105"))):
            with self.assertRaises(TypeError):
                fixture.check_campaigns(first, second)

    def test_native_enrollment_requires_real_disabled_first_cycle(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY accounts=2 "
                    "owner_bound=true original_config=true "
                    "original_state=true "
                    "disabled_first=true stdin_only=true same_sid=true "
                    "explicit_enable=true stopped_reaped=true "
                    "no_fd_leak=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("owner_bound", "original_config", "original_state",
                      "disabled_first", "stdin_only", "same_sid",
                      "explicit_enable", "stopped_reaped", "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("accounts=2", "accounts=1"),
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_complete_manifest_contains_session_control_tools(self):
        manifest = merge(reports())
        for path in ("usr/bin/smbstatus", "usr/bin/smbcontrol"):
            self.assertIn(" /" + path + "\n", manifest)

    def test_native_handoff_requires_originals_and_refusals(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_HANDOFF_READY inputs=4 "
                    "refusals=7 source_path_masked=true same_objects=true "
                    "caller_close=true readonly_noexec=true "
                    "closed_before_exec=true late_drift_refused=true "
                    "review_sticky=true partial_cleanup=true "
                    "stopped_reaped=true no_fd_leak=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("source_path_masked", "same_objects", "caller_close",
                      "readonly_noexec", "closed_before_exec",
                      "late_drift_refused", "review_sticky", "partial_cleanup",
                      "stopped_reaped", "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("inputs=4", "inputs=3"),
                            expected.replace("refusals=7", "refusals=6"),
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_native_configuration_requires_retained_real_lookup(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_CONFIG_READY "
                    "owner_derived=true "
                    "exact_census=true readonly_noexec=true caller_close=true "
                    "libc=true drift_refused=true restoration_mismatch=true "
                    "stopped_reaped=true released=true no_fd_leak=true "
                    "scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("owner_derived", "exact_census", "readonly_noexec",
                      "caller_close", "libc", "drift_refused",
                      "restoration_mismatch", "stopped_reaped", "released",
                      "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_native_lookup_requires_real_corrupt_document_refusals(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_NSS_REFUSAL_READY "
                    "changed_uid=true supplementary_group=true "
                    "foreign_user=true restored_lookup=true "
                    "unchanged_owner=true stopped_reaped=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("changed_uid", "supplementary_group", "foreign_user",
                      "restored_lookup", "unchanged_owner", "stopped_reaped"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_native_lookup_requires_libc_and_isolated_owner_evidence(self):
        expected = ("PHANTOWD_SAMBA_OWNER_NATIVE_NSS_READY accounts=2 "
                    "owner_derived=true libc=true private_groups=true "
                    "foreign_omitted=true readonly_root=true caps_zero=true "
                    "no_state=true unchanged_owner=true stopped_reaped=true "
                    "daemon_installed=false scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("owner_derived", "libc", "private_groups",
                      "foreign_omitted", "readonly_root", "caps_zero",
                      "no_state", "unchanged_owner", "stopped_reaped"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("accounts=2", "accounts=1"),
                            expected.replace("daemon_installed=false",
                                             "daemon_installed=true"),
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_state_observer_requires_prelaunch_refusal_and_sticky_review(self):
        expected = ("PHANTOWD_SAMBA_OWNER_STATE_OBSERVER_REFUSAL_READY "
                    "late_mode_drift=true before_launch=true "
                    "cancellation_before_admission=true review_pins=true "
                    "restoration_refused=true stopped_reaped=true "
                    "released=true no_fd_leak=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("late_mode_drift", "before_launch",
                      "cancellation_before_admission", "review_pins",
                      "restoration_refused", "stopped_reaped", "released",
                      "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_state_observer_requires_actual_retained_worker_evidence(self):
        expected = ("PHANTOWD_SAMBA_OWNER_STATE_OBSERVER_READY inputs=7 "
                    "refusals=1 caller_inputs_closed=true "
                    "source_path_masked=true same_objects=true "
                    "closed_before_exec=true listing_redacted=true "
                    "single_use=true stopped_reaped=true released=true "
                    "no_fd_leak=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("caller_inputs_closed", "source_path_masked",
                      "same_objects", "closed_before_exec",
                      "listing_redacted", "single_use", "stopped_reaped",
                      "released", "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("inputs=7", "inputs=6"),
                            expected.replace("refusals=1", "refusals=0"),
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    @unittest.skipUnless(os.name == "posix", "Linux owned group contract")
    def test_owned_group_requires_leader_and_anonymous_writable_pipes(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as scratch:
            executable = Path(scratch, "owned-context-host")
            compiled = subprocess.run(
                ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 str(root / "support/tests/"
                     "samba-root-owned-context-fixture.c"),
                 "-o", str(executable)], timeout=30, check=False,
                capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run(
                [str(executable)], timeout=5, check=False,
                capture_output=True, text=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(result.stdout,
                             "PHANTOWD_SAMBA_OWNED_CONTEXT_NATIVE_READY "
                             "accepted=1 denied=6 scope=host-process-only\n")
            for operation in ("put /run/upload owned-created",
                              "get owned-created /run/download",
                              "put /run/upload owned-readonly-denied"):
                checked = subprocess.run(
                    [str(executable), operation], timeout=5, check=False,
                    capture_output=True, text=True)
                self.assertEqual(checked.returncode, 0, operation)
            for operation in ("put /run/upload unapproved", "ls; reboot",
                              "get ../escape /tmp/escape", "", "LS"):
                checked = subprocess.run(
                    [str(executable), operation], timeout=5, check=False,
                    capture_output=True, text=True)
                self.assertEqual(checked.returncode, 1, operation)

    @unittest.skipUnless(os.name == "posix", "Linux process context contract")
    def test_actual_context_check_denies_each_leak_and_restores(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as scratch:
            executable = Path(scratch, "context-host")
            compile_result = subprocess.run(
                ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 str(root / "support/tests/samba-root-context-fixture.c"),
                 "-o", str(executable)], timeout=30, check=False,
                capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0,
                             compile_result.stderr)
            result = subprocess.run(
                [str(executable)], timeout=5, check=False,
                capture_output=True, text=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(result.stdout,
                             "PHANTOWD_SAMBA_CONTEXT_NATIVE_READY "
                             "denied=8 restored=true "
                             "scope=host-process-only\n")

    @unittest.skipUnless(os.name == "posix", "POSIX shell contract")
    def test_fixed_mkdir_error_evidence_and_absence(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "support/tests/samba-root-init.sh").read_text()
        start = source.index("denied_mkdir() {")
        end = source.index("run_fixture() {", start)
        helper = source[start:end]
        prefix = "/run/phantowd-samba-source/approved/inherited/"
        self.assertEqual(helper.count(prefix), 1)
        with tempfile.TemporaryDirectory() as scratch:
            helper = helper.replace(prefix, scratch + "/")
            script = (helper + '\nclient_status=$3; evidence=$4\n'
                      'client() { return "$client_status"; }\n'
                      'grep() { printf "%s\\n" "$evidence"; }\n'
                      'denied_mkdir "$1" "$2"\n')
            expected = ("NT_STATUS_ACCESS_DENIED making remote directory "
                        "\\inherited\\reader-denied")

            def run(status, evidence, user="qpreader", folder="reader-denied"):
                return subprocess.run(
                    ["/bin/sh", "-c", script, "fixture", user, folder,
                     str(status), evidence], timeout=5, check=False,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
                ).returncode

            for status in (0, 1):
                self.assertEqual(run(status, expected), 0)
            for status in (2, 124, 143):
                self.assertNotEqual(run(status, expected), 0)
            for evidence in ("", "NT_STATUS_LOGON_FAILURE", "success",
                             expected + "\n" + expected,
                             expected.replace("reader-denied", "other"),
                             expected + "\nNT_STATUS_UNSUCCESSFUL"):
                self.assertNotEqual(run(0, evidence), 0)
            self.assertNotEqual(run(0, expected, user="qpwriter"), 0)
            self.assertNotEqual(run(0, expected, folder="other"), 0)
            Path(scratch, "reader-denied").mkdir()
            self.assertNotEqual(run(0, expected), 0)

    def test_deduplicated_fixed_roster(self):
        manifest = merge(reports())
        self.assertEqual(len(manifest.splitlines()), 10)
        self.assertEqual(manifest.count("b" * 64), 1)
        self.assertIn(hashlib.sha256(CATALOG.encode()).hexdigest(), manifest)
        self.assertNotEqual(
            manifest, fixture.merge(reports(), CATALOG + "# x\n"))

    def test_partial_reordered_or_authorized_inputs_refused(self):
        values = [reports()[:2], reports()[:3], reports()[:4], reports()[::-1]]
        for field, value in (("execution_authorized", True),
                             ("runtime_qualified", True),
                             ("static_dependencies_resolved", False),
                             ("entry", "usr/bin/untrusted")):
            changed = reports()
            changed[1][field] = value
            values.append(changed)
        for value in values:
            with self.assertRaises(ValueError):
                merge(value)

    def test_only_fixed_stream_module_entry_admitted(self):
        changed = reports()
        # A DSO has no PT_INTERP; require it only for the fixed programs.
        changed[3]["objects"][1]["path"] = "usr/lib/libc.so.6"
        changed[3]["objects"][1]["bindings"] = ["usr/lib/libc.so.6"]
        self.assertIn("/usr/lib/samba/vfs/streams_xattr.so",
                      merge(changed))
        for entry in ("usr/lib/samba/vfs/acl_xattr.so",
                      "usr/lib/untrusted.so"):
            value = copy.deepcopy(changed)
            value[3]["entry"] = entry
            with self.assertRaises(ValueError):
                merge(value)
        changed[0]["objects"][1]["path"] = "usr/lib/libc.so.6"
        changed[0]["objects"][1]["bindings"] = ["usr/lib/libc.so.6"]
        with self.assertRaises(ValueError):
            merge(changed)

    def test_only_fixed_gconv_module_and_catalog_admitted(self):
        changed = reports()
        changed[4]["objects"][1]["path"] = "usr/lib/libc.so.6"
        changed[4]["objects"][1]["bindings"] = ["usr/lib/libc.so.6"]
        self.assertIn("/usr/lib/gconv/IBM850.so", merge(changed))
        for entry in ("usr/lib/gconv/IBM437.so", "usr/lib/gconv/../IBM850.so"):
            value = copy.deepcopy(changed)
            value[4]["entry"] = entry
            with self.assertRaises(ValueError):
                merge(value)
        catalogs = ["", "x" * 4097, CATALOG + "\x00", CATALOG + "\u00e9",
                    CATALOG + "alias CP850// IBM850//\n",
                    CATALOG.replace("IBM850 1", "../../untrusted 1"),
                    CATALOG.replace("CP850//", "untrusted//"),
                    CATALOG.replace("module INTERNAL IBM850// IBM850 1", ""),
                    CATALOG + "module UTF-8// INTERNAL UTF8 1\n"]
        for catalog in catalogs:
            with self.assertRaises(ValueError):
                fixture.merge(reports(), catalog)
        changed = reports()
        changed[4]["objects"][0]["bindings"].append(fixture.CATALOG_PATH)
        with self.assertRaises(ValueError):
            merge(changed)

    def test_cross_candidate_byte_alias_conflict_refused(self):
        changed = reports()
        changed[1]["objects"][1]["sha256"] = "c" * 64
        with self.assertRaises(ValueError):
            merge(changed)
        changed = reports()
        changed[1]["objects"][0]["bindings"].append("usr/sbin/smbd")
        with self.assertRaises(ValueError):
            merge(changed)

    def test_shell_and_path_injection_refused(self):
        for alias in ("../state", "etc/passwd", "lib/x;reboot", "lib/$x"):
            # etc/passwd must not overlap generated non-ELF configuration.
            changed = reports()
            changed[0]["objects"][0]["bindings"].append(alias)
            with self.assertRaises(ValueError):
                merge(changed)

    def test_copy_does_not_mutate_candidates(self):
        values = reports()
        saved = copy.deepcopy(values)
        merge(values)
        self.assertEqual(values, saved)

    def test_merged_budget_and_guest_log_size_refused(self):
        values = reports()
        for report in values:
            report["objects"][0]["size"] = 24 * 1024 * 1024
            report["total_bytes"] = 24 * 1024 * 1024 + 100
        with self.assertRaises(ValueError):
            merge(values)
        with self.assertRaises(ValueError):
            fixture.check_guest("x" * (512 * 1024 + 1))

    def test_guest_crlf_and_strict_complete_markers(self):
        lines = [
            "PHANTOWD_SAMBA_ROOT_ENTROPY_READY provider=virtio-rng "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true "
            "hashes_during_copy=true "
            "no_overwrite=true refusals=5 scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CODE_ACL_READY baseline=true root=true "
            "directories=true files=true refusals=5 scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_BUNDLE_READY readonly=true "
            "complete_census=true hashes=true aliases=true refusals=5 "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_RETAINED_CODE_READY complete_code_pins=true "
            "caller_close=true dynamic_elf=true generic_dynamic_refused=true "
            "generic_root_refused=true canceled_refused=true "
            "released=true no_fd_leak=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CODE_VIEWS_READY code_only=true "
            "config_separate=true "
            "same_inodes=true readonly_views=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CODE_VIEWS_REFUSAL_READY "
            "same_bytes_copy=true "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CHARSET_READY charset=CP850 bytes=true "
            "roundtrip=true isolated_root=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CONTEXT_READY original_fds_closed=true "
            "signal_mask_empty=true dispositions_default=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_BOUNDARY_READY caps=00000000000000db "
            "nnp=true original_denied=true kernel_ro=true",
            "PHANTOWD_SAMBA_ROOT_STREAMS_READY module=streams_xattr "
            "xattr_bytes=true reader_write_denied=true kernel_ro=true "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_POSIX_ACL_READY fs=ext4 bytes=true "
            "named_reader=true outsider_denied=true mask_revocation=true "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_INHERITANCE_READY fs=ext4 directory_acl=true "
            "file_acl=true setgid=true reader_write_denied=true "
            "outsider_denied=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_POLICY_READY writer_uid=1801 "
            "reader_uid=1802 outsider_denied=true kernel_ro=true "
            "original_denied=true unix_ownership=true unix_denial=true "
            "utf8_roundtrip=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_STOPPED",
            "PHANTOWD_SAMBA_OWNER_GROUP_READY nonleader_refused=true "
            "pinned_helper=true caller_close=true canceled_refused=true "
            "same_group=true caps=db distinct_accounts=true "
            "writer_bytes=true unix_ownership=true kernel_ro=true "
            "duplicate_refused=true "
            "live_close_refused=true "
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
            "live_directory_pins=true same_child_objects=true "
            "writable_noexec=true mutable_passdb=true normal_stop=true "
            "drift_stopped=true review_retained=true "
            "restoration_refused=true released=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_STATE_HANDOFF_READY inputs=7 "
            "source_path_masked=true same_child_objects=true "
            "closed_before_exec=true no_fd_leak=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_STATE_ADMISSION_READY refusals=5 "
            "before_launch=true caller_inputs_closed=true copied_spec=true "
            "partial_cleanup=true forced_stop_review=true review_pins=true "
            "explicit_release=true no_fd_leak=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_STATE_OBSERVER_READY inputs=7 refusals=1 "
            "caller_inputs_closed=true source_path_masked=true "
            "same_objects=true closed_before_exec=true listing_redacted=true "
            "single_use=true stopped_reaped=true released=true "
            "no_fd_leak=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_STATE_OBSERVER_REFUSAL_READY "
            "late_mode_drift=true before_launch=true "
            "cancellation_before_admission=true review_pins=true "
            "restoration_refused=true stopped_reaped=true released=true "
            "no_fd_leak=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_NSS_READY accounts=2 "
            "owner_derived=true libc=true private_groups=true "
            "foreign_omitted=true readonly_root=true caps_zero=true "
            "no_state=true unchanged_owner=true stopped_reaped=true "
            "daemon_installed=false scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_NSS_REFUSAL_READY changed_uid=true "
            "supplementary_group=true foreign_user=true restored_lookup=true "
            "unchanged_owner=true stopped_reaped=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_CONFIG_READY owner_derived=true "
            "exact_census=true readonly_noexec=true caller_close=true "
            "libc=true drift_refused=true restoration_mismatch=true "
            "stopped_reaped=true released=true no_fd_leak=true "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_HANDOFF_READY inputs=4 refusals=7 "
            "source_path_masked=true same_objects=true caller_close=true "
            "readonly_noexec=true closed_before_exec=true "
            "late_drift_refused=true review_sticky=true partial_cleanup=true "
            "stopped_reaped=true no_fd_leak=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY accounts=2 "
            "owner_bound=true original_config=true original_state=true "
            "disabled_first=true stdin_only=true same_sid=true "
            "explicit_enable=true stopped_reaped=true "
            "no_fd_leak=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_DAEMON_READY accounts=2 "
            "same_code=true same_config=true same_state=true "
            "authenticated=true wrong_password_denied=true owned_group=true "
            "stopped_reaped=true no_fd_leak=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_IDLE_DISABLE_READY owner_bound=true "
            "same_sid=true stable_absence=true new_login_denied=true "
            "other_login_allowed=true same_daemon=true no_new_privileges=true "
            "stopped_reaped=true no_fd_leak=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_LIVE_REVOKE_READY accounts=2 "
            "qualified_pair=true original_pair_rechecked=true "
            "revoked_pair_refused=true owner_bound=true same_sid=true "
            "target_absent=true same_peer_session=true new_login_denied=true "
            "other_login_allowed=true same_daemon=true "
            "no_new_privileges=true stopped_reaped=true no_fd_leak=true "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_BACKEND_BINDING_READY "
            "owner_bound=true backend_bound=true unchanged_verified=true "
            "foreign_refused=true close_busy=true released_before_start=true "
            "release_no_mutation=true stopped_reaped=true no_fd_leak=true "
            "service_owner=false scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_DISABLE_HANDOFF_READY "
            "owner_bound=true backend_bound=true atomic_successor=true "
            "old_review=true new_verified=true close_busy=true "
            "same_peer_session=true retained_until_stop=true "
            "stopped_reaped=true no_fd_leak=true "
            "startup_bound=false service_owner=false scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_DATA_READY original_objects=true "
            "individual_clones=true readonly_EROFS=true "
            "smb_read=true smb_write=true unix_owner=true "
            "symlink_denied=true private_namespace=true "
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
            "smb_read=true smb_write=true unix_owner=true "
            "readonly_EROFS=true readonly_denied=true symlink_denied=true "
            "fresh_observation=true stopped_before_release=true "
            "no_fd_leak=true activation=false scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_PLANNED_SUPERVISION_READY "
            "same_authorities=true complete_scan=true serialized=true "
            "cancellation_stopped=true originals_retained=true "
            "restart_refused=true close_before_release=true "
            "stopped_reaped=true no_fd_leak=true "
            "activation=false scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_PLANNED_STOP_READY "
            "same_daemon=true private_inputs=15 runtime_inputs_retained=true "
            "live_not_stopped=true stopped_reaped=true "
            "legacy_clients_guard=true repeated_readonly=true "
            "closed_refused=true no_fd_leak=true activation=false "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_PLANNED_CANDIDATE_READY "
            "owner=actual_native_backend storage=mounted_roster "
            "locked_plan=true exact_declaration=true original_objects=true "
            "caller_close=true fresh_recompiled=true rendered=true "
            "granted_only=true paired_lookup=true management_complete=true "
            "shared_globals=true management_bound=true protected_role=true "
            "management_unchanged=true prepared_inputs=true "
            "service_config_bound=true share_inputs_bound=true "
            "coordinator_bound=true same_roster=true policy_copy=true "
            "startup_blocked=true identity_retained=true "
            "handoff_close_gated=true desired_roundtrip=true "
            "journals_unchanged=true stale_refused=true "
            "runtime_close_before_release=true released=true "
            "samba_data=false activation=false scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_IDENTITY_STARTUP_READY "
            "startup_bound=true exact_backend=true before_start_busy=true "
            "after_start_busy=true duplicate_refused=true "
            "canceled_start_refused=true complete_observation=true "
            "serialized_scans=true accepted_cancellation=true "
            "stopped_reaped=true close_before_release=true no_fd_leak=true "
            "coordinator_disable=true qualified_pair=true "
            "same_peer_session=true target_denied=true "
            "stale_revision_refused=true canceled_disable_refused=true "
            "serialized_disable=true prepared_disable_refused=true "
            "stopped_disable_refused=true "
            "service_owner=false scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_NATIVE_IDENTITY_FAULT_READY "
            "state_drift=true before_worker=true pending_retained=true "
            "groups_stopped=true capture_settled=true "
            "authority_busy=true "
            "inputs_retained=true restoration_refused=true "
            "close_no_retry=true "
            "subprocess_disposal=true no_fd_leak=true "
            "service_owner=false scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_PLANNED_SOURCE_FAULT_READY "
            "same_authorities=true same_daemon=true data_verified=true "
            "original_session=true held_client_stopped=true "
            "held_client_retained=true old_observers_refused=true "
            "source_covered=true exclusive_supervision=true "
            "review_sticky=true stopped_reaped=true private_inputs=15 "
            "runtime_inputs_retained=true originals_busy=true "
            "cover_removed=true restoration_refused=true close_refused=true "
            "private_mount_namespace=true subprocess_disposal=true "
            "parent_fd_equal=true activation=false scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_DONE",
        ]
        # The new independent exit proof is additional; all older literal
        # golden proofs remain required, in their original relative order.
        index = next(i for i, row in enumerate(lines) if row.startswith(
            "PHANTOWD_SAMBA_OWNER_NATIVE_IDENTITY_STARTUP_READY"))
        lines.insert(index, fixture.PLANNED_EXIT_FAULT_MARKER)
        fixture.check_guest("\r\n".join(lines + [SCAN_COST]))
        self.assertEqual(fixture.scan_cost("\r\n".join(lines + [SCAN_COST])),
                         (104, 12000000, 123456789))
        invalid_logs = [lines[:i] + lines[i + 1:] for i in range(len(lines))]
        invalid_logs += [lines + [lines[0]], lines[::-1],
                         lines + ["PHANTOWD_SAMBA_ROOT_FAILED"],
                         lines + ["PHANTOWD_SAMBA_ROOT_LAUNCH_REFUSED"]]
        for invalid in invalid_logs:
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(invalid + [SCAN_COST]))

    def test_guest_refuses_missing_or_predictable_entropy_evidence(self):
        expected = ("PHANTOWD_SAMBA_ROOT_ENTROPY_READY provider=virtio-rng "
                    "scope=qemu-only")
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for replacement in ("", expected.replace("virtio-rng", "none"),
                            expected.replace("virtio-rng", "fixed-seed"),
                            expected.replace("qemu-only", "product"),
                            expected + "\n" + expected):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_code_lifetime_requires_verified_stop_drift_and_retention(self):
        fields = ("caller_close", "live_code_pins", "normal_stop",
                  "drift_stopped", "review_retained", "restoration_refused",
                  "released", "no_fd_leak")
        for field in fields:
            changed = [row.replace(field + "=true", field + "=false")
                       if "CODE_LIFETIME_READY" in row else row
                       for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_configuration_lifetime_requires_protected_child_and_stop(self):
        for field in ("exact_contents", "caller_close", "live_pins",
                      "same_child_objects", "readonly_noexec", "normal_stop",
                      "drift_stopped", "review_retained",
                      "restoration_refused", "released"):
            changed = [row.replace(field + "=true", field + "=false")
                       if "CONFIG_LIFETIME_READY" in row else row
                       for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_code_lifetime_refuses_missing_or_false_forced_stop_review(self):
        for value in ("", " forced_stop_review=false"):
            changed = [row.replace(" forced_stop_review=true", value)
                       if "CODE_LIFETIME_READY" in row else row
                       for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_state_requires_mutable_same_objects_and_verified_stop(self):
        expected = ("PHANTOWD_SAMBA_OWNER_STATE_LIFETIME_READY "
                    "caller_close=true live_directory_pins=true "
                    "same_child_objects=true writable_noexec=true "
                    "mutable_passdb=true normal_stop=true drift_stopped=true "
                    "review_retained=true restoration_refused=true "
                    "released=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("caller_close", "live_directory_pins",
                      "same_child_objects", "writable_noexec",
                      "mutable_passdb",
                      "normal_stop", "drift_stopped", "review_retained",
                      "restoration_refused", "released"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_state_handoff_requires_masked_path_objects_and_cleanup(self):
        expected = ("PHANTOWD_SAMBA_OWNER_STATE_HANDOFF_READY inputs=7 "
                    "source_path_masked=true same_child_objects=true "
                    "closed_before_exec=true no_fd_leak=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("source_path_masked", "same_child_objects",
                      "closed_before_exec", "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("inputs=7", "inputs=6"),
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_state_admission_requires_refusal_copy_and_forced_cleanup(self):
        expected = ("PHANTOWD_SAMBA_OWNER_STATE_ADMISSION_READY refusals=5 "
                    "before_launch=true caller_inputs_closed=true "
                    "copied_spec=true partial_cleanup=true "
                    "forced_stop_review=true review_pins=true "
                    "explicit_release=true no_fd_leak=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("before_launch", "caller_inputs_closed", "copied_spec",
                      "partial_cleanup", "forced_stop_review", "review_pins",
                      "explicit_release", "no_fd_leak"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("refusals=5", "refusals=4"),
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_inherited_context_requires_exact_positive_evidence(self):
        evidence = ("PHANTOWD_SAMBA_ROOT_CONTEXT_READY "
                    "original_fds_closed=true signal_mask_empty=true "
                    "dispositions_default=true scope=qemu-only")
        lines = list(fixture.MARKERS)
        self.assertEqual(lines.count(evidence), 1)
        fixture.check_guest("\n".join(lines + [SCAN_COST]))
        for field in ("original_fds_closed", "signal_mask_empty",
                      "dispositions_default"):
            changed = [row.replace(field + "=true", field + "=false")
                       for row in lines]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

        for replacement in ("", evidence + "\n" + evidence,
                            evidence.replace("qemu-only", "physical-ex4")):
            changed = [replacement if row == evidence else row
                       for row in lines]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_owned_group_requires_executed_write_and_canceled_admission(self):
        expected = ("PHANTOWD_SAMBA_OWNER_GROUP_READY nonleader_refused=true "
                    "pinned_helper=true caller_close=true "
                    "canceled_refused=true "
                    "same_group=true caps=db distinct_accounts=true "
                    "writer_bytes=true unix_ownership=true kernel_ro=true "
                    "duplicate_refused=true live_close_refused=true "
                    "stopped_reaped=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        for field in ("canceled_refused", "writer_bytes", "unix_ownership",
                      "kernel_ro", "same_group", "stopped_reaped"):
            changed = [row.replace(field + "=true", field + "=false")
                       if row == expected else row for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))
        for extra in (expected, "PHANTOWD_SAMBA_OWNER_FAILED writer access"):
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(
                    list(fixture.MARKERS) + [SCAN_COST, extra]))

    def test_retained_code_requires_complete_roster_and_verified_release(self):
        evidence = ("PHANTOWD_SAMBA_ROOT_RETAINED_CODE_READY "
                    "complete_code_pins=true caller_close=true "
                    "dynamic_elf=true generic_dynamic_refused=true "
                    "generic_root_refused=true canceled_refused=true "
                    "released=true "
                    "no_fd_leak=true scope=qemu-only")
        self.assertIn(evidence, fixture.MARKERS)
        for field in ("complete_code_pins", "caller_close", "dynamic_elf",
                      "generic_dynamic_refused", "generic_root_refused",
                      "canceled_refused", "released", "no_fd_leak"):
            changed = [row.replace(field + "=true", field + "=false")
                       if row == evidence else row for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))
        for replacement in (evidence + "\n" + evidence,
                            evidence.replace("qemu-only", "physical-ex4"),
                            "PHANTOWD_SAMBA_ROOT_RETAINED_CODE_FAILED"):
            changed = [replacement if row == evidence else row
                       for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_code_views_require_identity_and_separation(self):
        fields = ("code_only", "config_separate", "same_inodes",
                  "readonly_views", "same_bytes_copy")
        for field in fields:
            changed = [row.replace(field + "=true", field + "=false")
                       for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_inspection_cost_is_single_bounded_emulation_evidence(self):
        good = "\n".join(fixture.MARKERS)
        with self.assertRaises(ValueError):
            fixture.check_guest(good)
        invalid = [SCAN_COST + "\n" + SCAN_COST]
        for old, new in (("files=104", "files=0"),
                         ("files=104", "files=257"),
                         ("bytes=12000000", "bytes=0"),
                         ("bytes=12000000", "bytes=67108865"),
                         ("elapsed_ns=123456789", "elapsed_ns=0"),
                         ("elapsed_ns=123456789", "elapsed_ns=-1"),
                         ("elapsed_ns=123456789", "elapsed_ns=01"),
                         ("elapsed_ns=123456789", "elapsed_ns=" + "9" * 1000),
                         ("qemu-emulation-only", "physical-ex4")):
            invalid.append(SCAN_COST.replace(old, new))
        for cost in invalid:
            with self.assertRaises(ValueError):
                fixture.check_guest(good + "\n" + cost)

    def test_fixed_experiment_scope_and_runtime_assertions(self):
        root = Path(__file__).resolve().parents[2]
        wrapper = (root / "support/test-samba-root.ps1").read_text()
        driver = (root / "support/tests/test-qemu-samba-root.sh").read_text()
        native = (root / "support/tests/samba-root-launcher-fixture.c"
                  ).read_text()
        init = (root / "support/tests/samba-root-init.sh").read_text()
        self.assertIn("--pull never --network none --read-only", wrapper)
        self.assertNotIn("docker volume create", wrapper)
        self.assertIn("timeout --signal=TERM --kill-after=5 180", driver)
        self.assertIn("-nic none", driver)
        self.assertIn("rootwait ro", driver)
        self.assertIn("if=scsi,snapshot=on", driver)
        self.assertIn("ARM Versatile PB", native)
        self.assertIn("unshare(CLONE_NEWNS)", native)
        self.assertIn("SYS_close_range", native)
        self.assertIn("--user 1000:1000 --cap-drop ALL", wrapper)
        self.assertIn("--memory 2g --pids-limit 256", wrapper)
        self.assertIn("server && poison_inherited_context()", native)
        self.assertIn("dup2(directory, 63)", native)
        self.assertIn("dup2(file, 64)", native)
        self.assertIn("sigaction(SIGINT, &ignored, NULL)", native)
        self.assertIn("sigismember(&observed, SIGTERM) != 1", native)
        self.assertIn("sigismember(&current_mask, number) != 0", native)
        self.assertIn("action.sa_handler != SIG_DFL", native)
        self.assertIn("fcntl(63, F_GETFD) != -1 || errno != EBADF", native)
        self.assertIn("fcntl(64, F_GETFD) != -1 || errno != EBADF", native)
        self.assertLess(
            native.index("if (server && verify_restored_context())"),
            native.index('execve("/usr/sbin/smbd"'))
        self.assertIn("^Cap(Inh|Amb):", init)
        self.assertIn("PR_SET_NO_NEW_PRIVS", native)
        self.assertIn("errno != EROFS", native)
        self.assertIn("NT_STATUS_BAD_NETWORK_NAME", init)
        self.assertIn("created.st_uid != 1801", native)
        self.assertIn("PHANTOWD_SAMBA_ROOT_STOPPED", init)
        self.assertIn("now.tv_sec - start.tv_sec >= 10", native)
        self.assertIn('return 124;', native)
        self.assertIn('[ "$status" -eq 1 ]', init)
        self.assertNotIn("timeout -s", init)
        self.assertIn('/bin/busybox kill -TERM "-$daemon_pid"', init)
        self.assertIn('[ "$stop_status" -ne 143 ]', init)
        self.assertIn('[ "$stop_attempted" -eq 0 ]', init)
        self.assertIn("usr/lib/samba/vfs/streams_xattr.so", driver)
        self.assertIn("usr/lib/gconv/IBM850.so", driver)
        self.assertIn('./cmd/qemu-runtime-bundle', driver)
        self.assertIn('"bundle phantowd-runtime-bundle-probe"', driver)
        self.assertIn('inspect_runtime_bundle()', native)
        self.assertIn('PR_CAPBSET_DROP, cap, 0, 0, 0', native)
        bundle_call = init.index('phantowd-samba-root-launcher runtime-bundle')
        self.assertLess(init.index('phantowd-runtime-bundle-probe stage'),
                        bundle_call)
        acl_call = init.index('phantowd-runtime-bundle-probe inspect-acl')
        self.assertLess(init.index('phantowd-runtime-bundle-probe stage'),
                        acl_call)
        self.assertLess(acl_call, bundle_call)
        acl = (root / 'src/phantowd-api/cmd/qemu-runtime-bundle/acl.go'
               ).read_text()
        self.assertTrue(acl.startswith('//go:build qemu && linux'))
        self.assertIn('unix.Unshare(unix.CLONE_NEWNS)', acl)
        self.assertIn('unix.MS_REC|unix.MS_PRIVATE', acl)
        self.assertIn('runtime.LockOSThread()', acl)
        self.assertIn('unix.Getxattr', acl)
        self.assertIn('plan.Inspect(context.Background(), root)', acl)
        self.assertNotIn('UnlockOSThread', acl)
        self.assertNotIn('RemoveAll(', acl)
        self.assertNotIn('cp "$canonical"', init)
        stage = (root / "src/phantowd-api/internal/runtimebundle/"
                 "stage_qemu_linux.go").read_text()
        self.assertTrue(stage.startswith('//go:build qemu && linux'))
        self.assertIn('unix.O_EXCL', stage)
        self.assertIn('ErrStageIncomplete', stage)
        self.assertIn('unix.TMPFS_MAGIC', stage)
        self.assertNotIn('RemoveAll(', stage)
        self.assertLess(bundle_call, init.index('mkdir -p "$root/etc/samba"'))
        charset_copy = init.index('cp /usr/sbin/phantowd-samba-charset-probe')
        self.assertLess(bundle_call, charset_copy)
        self.assertIn("gconv-modules", driver)
        self.assertIn("dos charset = CP850", init)
        self.assertIn("phantowd-samba-root-launcher charset", init)
        probe = (root / "support/tests/samba-charset-fixture.c").read_text()
        self.assertIn('convert("UTF-8", aliases[i]', probe)
        self.assertIn('convert(aliases[i], "UTF-8"', probe)
        self.assertIn('EILSEQ, EILSEQ, EINVAL', probe)
        self.assertIn('"LC_ALL=C"', native)
        self.assertNotIn("GCONV_PATH=", native)
        config = (root / "configs/phantowd_qemu_armv5_defconfig").read_text()
        self.assertIn('BR2_TOOLCHAIN_GLIBC_GCONV_LIBS_COPY=y', config)
        self.assertIn('BR2_TOOLCHAIN_GLIBC_GCONV_LIBS_LIST="IBM850"', config)
        self.assertIn("vfs objects = streams_xattr", init)
        self.assertIn("user.DosStream.fixture:$DATA", native)
        self.assertIn("lgetxattr", native)
        self.assertNotIn("CAP_SYS_ADMIN)", native)
        self.assertIn('"system.posix_acl_access"', native)
        self.assertIn('"system.posix_acl_default"', native)
        self.assertIn('directory ? 02750 : 0640', native)
        self.assertIn('inheritance-verify', init)
        self.assertIn('map archive = no', init)
        self.assertIn('store dos attributes = yes', init)
        self.assertIn('put /run/upload-stream inherited/child/data', init)
        self.assertIn('denied_mkdir qpreader reader-denied', init)
        self.assertIn('mount -t ext4 -o acl,nosuid,nodev,noexec', init)
        self.assertIn('file=$scratch/acl.ext4,format=raw,if=scsi,snapshot=on',
                      driver)


if __name__ == "__main__":
    unittest.main()
