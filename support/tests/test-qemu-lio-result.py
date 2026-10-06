#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Consumer-contract tests, not a target/initiator test."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "support/container/qemu_lio_result.py"
SPEC = importlib.util.spec_from_file_location("lio_result", SCRIPT)
result = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(result)


class LIOResult(unittest.TestCase):
    def valid(self, strict=False, idle=False):
        markers = result.STRICT_MARKERS if strict else result.MARKERS
        if idle:
            markers += result.IDLE_MARKERS
        return ("ordinary boot log\n" + "\n".join(markers) + "\n").encode()

    def test_idle_mode_matrix_refuses_missing_duplicate_weakened_or_wrong_profile(self):
        for strict in (False, True):
            good = self.valid(strict, idle=True)
            result.validate(good, strict, True)
            result.validate(good.replace(b"\n", b"\r\n"), strict, True)
            for selected_strict, selected_idle in ((strict, False), (not strict, True)):
                with self.assertRaises(ValueError):
                    result.validate(good, selected_strict, selected_idle)
            with self.assertRaises(ValueError):
                result.validate(self.valid(strict), strict, True)
            for marker in result.IDLE_MARKERS:
                replacements = ("", marker + "\n" + marker, "prefix " + marker)
                if "true" in marker:
                    replacements += (marker.replace("true", "false"),)
                for replacement in replacements:
                    with self.subTest(strict=strict, marker=marker, replacement=replacement), self.assertRaises(ValueError):
                        result.validate(good.replace(marker.encode(), replacement.encode()), strict, True)
            for marker in (result.MARKERS if not strict else result.STRICT_MARKERS):
                with self.subTest(strict=strict, omitted=marker), self.assertRaises(ValueError):
                    result.validate(good.replace(marker.encode(), b""), strict, True)
            for token in result.DENIED:
                with self.assertRaises(ValueError):
                    result.validate(good + token.encode(), strict, True)

    def test_owned_target_marker_cannot_claim_partial_or_product_authority(self):
        marker = next(item for item in result.IDLE_MARKERS if item.startswith("PHANTOWD_LIO_TARGET_READY "))
        good = self.valid(idle=True)
        for old, new in (("complete_roster=true", "complete_roster=false"),
                         ("luns=0,7", "luns=0"), ("actual_mount_owner=true", "actual_mount_owner=false"),
                         ("uncertain_retains_all=true", "uncertain_retains_all=false"),
                         ("idle_teardown_before_release=true", "idle_teardown_before_release=false"),
                         ("disposable-qemu-only", "product")):
            with self.subTest(old=old), self.assertRaises(ValueError):
                result.validate(good.replace(marker.encode(), marker.replace(old, new).encode()), idle_guard=True)

    def test_complete(self):
        result.validate(self.valid())
        result.validate(self.valid().replace(b"\n", b"\r\n"))

    def test_owned_fault_proof_cannot_omit_retention_or_foreign_preservation(self):
        marker = "PHANTOWD_LIO_TARGET_FAULTS_READY existing_target_preserved=true later_storage_preserved=true partial_setup_cleaned=true " \
                 "partial_teardown_retained=true no_retry=true independent_disposal=true scope=disposable-qemu-only"
        self.assertIn(marker, result.IDLE_MARKERS)
        good = self.valid(idle=True)
        for replacement in ("", marker + "\n" + marker, marker.replace("later_storage_preserved=true", "later_storage_preserved=false"),
                            marker.replace("partial_teardown_retained=true", "partial_teardown_retained=false"),
                            marker.replace("no_retry=true", "no_retry=false"), marker.replace("disposable-qemu-only", "product")):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                result.validate(good.replace(marker.encode(), replacement.encode()), idle_guard=True)

    def test_owned_topology_requires_foreign_object_refusal_and_retention(self):
        marker = "PHANTOWD_LIO_TOPOLOGY_READY bounded_census=true foreign_acl_refused=true foreign_lun_refused=true foreign_grant_refused=true " \
                 "foreign_preserved=true sources_retained=true no_retry=true writer_exclusion=false scope=disposable-qemu-only"
        self.assertIn(marker, result.IDLE_MARKERS)
        good = self.valid(idle=True)
        for replacement in ("", marker + "\n" + marker, marker.replace("foreign_acl_refused=true", "foreign_acl_refused=false"),
                            marker.replace("sources_retained=true", "sources_retained=false"), marker.replace("writer_exclusion=false", "writer_exclusion=true"),
                            marker.replace("no_retry=true", "no_retry=false"), marker.replace("disposable-qemu-only", "product")):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                result.validate(good.replace(marker.encode(), replacement.encode()), idle_guard=True)

    def test_foreign_endpoints_require_retention_and_no_product_claim(self):
        marker = "PHANTOWD_LIO_ENDPOINTS_READY foreign_portal_refused=true extra_tpg_refused=true foreign_preserved=true " \
                 "sources_retained=true no_retry=true independent_disposal=true writer_exclusion=false scope=disposable-qemu-only"
        self.assertIn(marker, result.IDLE_MARKERS)
        good = self.valid(idle=True)
        for replacement in ("", marker + "\n" + marker, marker.replace("foreign_portal_refused=true", "foreign_portal_refused=false"),
                            marker.replace("extra_tpg_refused=true", "extra_tpg_refused=false"),
                            marker.replace("sources_retained=true", "sources_retained=false"),
                            marker.replace("no_retry=true", "no_retry=false"), marker.replace("writer_exclusion=false", "writer_exclusion=true"),
                            marker.replace("disposable-qemu-only", "product")):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                result.validate(good.replace(marker.encode(), replacement.encode()), idle_guard=True)

    def test_owned_session_proof_requires_same_client_io_and_no_owner_retry(self):
        marker = "PHANTOWD_LIO_TARGET_SESSION_READY active_stop_refused=true same_client_readwrite=true complete_resources_retained=true " \
                 "owner_review=true no_retry=true logout_not_recovery=true independent_fixture_disposal=true scope=disposable-qemu-only"
        self.assertIn(marker, result.IDLE_MARKERS)
        good = self.valid(idle=True)
        for replacement in ("", marker + "\n" + marker, marker.replace("same_client_readwrite=true", "same_client_readwrite=false"),
                            marker.replace("complete_resources_retained=true", "complete_resources_retained=false"),
                            marker.replace("no_retry=true", "no_retry=false"), marker.replace("disposable-qemu-only", "product")):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                result.validate(good.replace(marker.encode(), replacement.encode()), idle_guard=True)

    def test_owned_access_proof_is_mandatory_and_cannot_be_weakened(self):
        marker = "PHANTOWD_LIO_TARGET_ACCESS_READY peers=2 separate_credentials=true primary_readwrite=true peer_readonly=true " \
                 "ungranted_refused=true cross_credentials_refused=true foreign_refused=true original_data_preserved=true scope=disposable-qemu-only"
        self.assertIn(marker, result.IDLE_MARKERS)
        good = self.valid(idle=True)
        for replacement in ("", marker + "\n" + marker, marker.replace("peers=2", "peers=1"),
                            marker.replace("peer_readonly=true", "peer_readonly=false"),
                            marker.replace("ungranted_refused=true", "ungranted_refused=false"),
                            marker.replace("disposable-qemu-only", "product")):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                result.validate(good.replace(marker.encode(), replacement.encode()), idle_guard=True)

    def test_strict_mode_refuses_default_cross_mode_and_mixed_evidence(self):
        strict = self.valid(strict=True)
        result.validate(strict, required_mutual=True)
        result.validate(strict.replace(b"\n", b"\r\n"), required_mutual=True)
        with self.assertRaises(ValueError):
            result.validate(self.valid(), required_mutual=True)
        with self.assertRaises(ValueError):
            result.validate(strict)
        for marker in result.STRICT_MARKERS:
            for replacement in ("", marker + "\n" + marker, "prefix " + marker):
                with self.subTest(marker=marker, replacement=replacement), self.assertRaises(ValueError):
                    result.validate(strict.replace(marker.encode(), replacement.encode()), required_mutual=True)
        for old in set(result.MARKERS) - set(result.STRICT_MARKERS):
            with self.assertRaises(ValueError):
                result.validate(strict + old.encode() + b"\n", required_mutual=True)
        for token in result.DENIED:
            with self.assertRaises(ValueError):
                result.validate(strict + token.encode(), required_mutual=True)

    def test_every_marker_missing_duplicate_or_substring_refused(self):
        for marker in result.MARKERS:
            for replacement in ("", marker + "\n" + marker, "prefix " + marker):
                with self.subTest(marker=marker, replacement=replacement):
                    with self.assertRaises(ValueError):
                        result.validate(self.valid().replace(marker.encode(),
                                                            replacement.encode()))

    def test_multiple_lun_evidence_cannot_be_omitted_or_weakened(self):
        marker = "PHANTOWD_LIO_LUNS_READY count=2 block_sizes=512,4096 primary_luns=0,1 peer_luns=0,3 " \
                 "opposite_access=true ungranted_refused=true data_isolated=true teardown=true scope=disposable-qemu-only"
        self.assertIn(marker, result.MARKERS)
        self.assertIn(marker, result.STRICT_MARKERS)
        for strict in (False, True):
            good = self.valid(strict=strict)
            for old, new in (("count=2", "count=1"), ("4096", "512"),
                             ("peer_luns=0,3", "peer_luns=0,1"),
                             ("ungranted_refused=true", "ungranted_refused=false"),
                             ("data_isolated=true", "data_isolated=false"),
                             ("teardown=true", "teardown=false")):
                with self.subTest(strict=strict, old=old), self.assertRaises(ValueError):
                    result.validate(good.replace(marker.encode(), marker.replace(old, new).encode()),
                                    required_mutual=strict)

    def test_errors_secrets_and_wrong_scope_refused(self):
        for token in result.DENIED:
            with self.subTest(token=token), self.assertRaises(ValueError):
                result.validate(self.valid() + token.encode())
        with self.assertRaises(ValueError):
            result.validate(self.valid().replace(b"disposable-qemu-only", b"product"))

    def test_size_and_encoding(self):
        for data in (self.valid() + b"\xff", b"x" * (result.MAX_BYTES + 1)):
            with self.assertRaises(ValueError):
                result.validate(data)

    def test_additional_unknown_or_contradictory_results_refused(self):
        for marker in (
            "PHANTOWD_LIO_CLIENT_READY case=unexpected",
            "PHANTOWD_LIO_MUTUAL_READY enforcement=true scope=product",
            "PHANTOWD_LIO_PEERS_READY concurrent=1",
            "PHANTOWD_LIO_READY scope=product",
            "prefix PHANTOWD_LIO_READY scope=product",
        ):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                result.validate(self.valid() + marker.encode() + b"\n")

    def test_cli_regular_missing_directory_and_redacted_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            log = directory / "log"
            log.write_bytes(self.valid())
            good = subprocess.run([sys.executable, "-B", str(SCRIPT), str(log)],
                                  capture_output=True, check=False)
            self.assertEqual(good.returncode, 0)
            for path in (directory, directory / "private-missing-log"):
                bad = subprocess.run([sys.executable, "-B", str(SCRIPT), str(path)],
                                     capture_output=True, check=False)
                self.assertEqual(bad.returncode, 1)
                self.assertEqual(bad.stderr.replace(b"\r\n", b"\n"),
                                 b"LIO guest qualification refused\n")
            log.write_bytes(self.valid() + b"synthetic-chap-only-2026")
            bad = subprocess.run([sys.executable, "-B", str(SCRIPT), str(log)],
                                 capture_output=True, check=False)
            self.assertEqual(bad.returncode, 1)
            self.assertNotIn(b"synthetic-chap", bad.stderr)


if __name__ == "__main__":
    unittest.main()
