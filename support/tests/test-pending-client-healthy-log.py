#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Synthetic parser controls, not guest execution."""
import unittest

import pending_client_healthy_log as fixture


class HealthyLog(unittest.TestCase):
    def test_exact_order_and_crlf(self):
        cost = ("PHANTOWD_RUNTIME_SCAN_COST files=114 bytes=27384058 "
                "elapsed_ns=123456789 scope=qemu-emulation-only")
        rows = (*fixture.EXPECTED, cost)
        for separator in ("\n", "\r\n"):
            self.assertEqual(fixture.verify(separator.join(rows)),
                             (114, 27384058, 123456789))
        for index in range(len(rows)):
            with self.assertRaises(ValueError):
                fixture.verify("\n".join(rows[:index] + rows[index + 1:]))
            with self.assertRaises(ValueError):
                fixture.verify("\n".join((*rows, rows[index])))
        with self.assertRaises(ValueError):
            fixture.verify("\n".join(reversed(rows)))
        for bad in ("PHANTOWD_PENDING_UNKNOWN",
                    "PHANTOWD_PENDING_MEASUREMENT_ONLY original5s=false "
                    "qualifying=false scope=qemu-only",
                    "PHANTOWD_DIAG_PENDING_OPEN_MEASURED elapsed_ms=5557 "
                    "qualifying=false scope=qemu-only",
                    "PHANTOWD_RUNTIME_BUNDLE_FAILED",
                    "PHANTOWD_SAMBA_ROOT_FAILED",
                    "PHANTOWD_SMB_WRITE_CLIENT_OPEN_NOTICE "
                    "scope=qemu-only proof=false"):
            with self.assertRaises(ValueError):
                fixture.verify("\n".join((*rows, bad)))
        good = "\n".join(rows)
        for field in ("complete_inputs=true", "client_exit0=true",
                      "client_group_absent=true",
                      "local_object_unchanged=true",
                      "server_open_observed=true",
                      "server_open_continuity=true",
                      "local_object_matched=true",
                      "no_fd_leak=true", "smb_object_bound=false",
                      "pending_io=false", "activation=false"):
            with self.assertRaises(ValueError):
                fixture.verify(good.replace(field, field + "-altered"))


if __name__ == "__main__":
    unittest.main()
