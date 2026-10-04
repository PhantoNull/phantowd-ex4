#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Bounded profile refusal tests; no compiler, guest or configfs access."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "lio_inputs", ROOT / "support/container/qemu_lio_inputs.py")
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


class LIOInputs(unittest.TestCase):
    def valid(self):
        return "\n".join([*(f"CONFIG_{s}=y" for s in inputs.ENABLED),
                          *(f"# CONFIG_{s} is not set" for s in inputs.DISABLED)])

    def check(self, data, required_mutual=False, idle_guard=False):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config"
            path.write_bytes(data)
            inputs.audit(path, required_mutual, idle_guard)

    def test_idle_mode_exact_builtin_and_mutual_mode_matrix(self):
        idle = "CONFIG_ISCSI_TARGET_IDLE_DISABLE=y"
        strict = "CONFIG_ISCSI_TARGET_STRICT_MUTUAL_CHAP=y"
        for mutual in (False, True):
            base = self.valid() + ("\n" + strict if mutual else "")
            self.check((base + "\n" + idle).encode(), mutual, True)
            self.check(base.encode(), mutual, False)
            self.check((base + "\n# CONFIG_ISCSI_TARGET_IDLE_DISABLE is not set").encode(), mutual, False)
            with self.assertRaises(ValueError):
                self.check((base + "\n" + idle).encode(), mutual, False)
            for substitute in ("", "# CONFIG_ISCSI_TARGET_IDLE_DISABLE is not set",
                               "CONFIG_ISCSI_TARGET_IDLE_DISABLE=m", idle + "\n" + idle):
                with self.subTest(mutual=mutual, substitute=substitute), self.assertRaises(ValueError):
                    self.check((base + "\n" + substitute).encode(), mutual, True)

    def test_valid_profile(self):
        self.check(self.valid().encode())

    def test_strict_mode_requires_exact_builtin_opt_in(self):
        line = "CONFIG_ISCSI_TARGET_STRICT_MUTUAL_CHAP=y"
        strict = self.valid() + "\n" + line
        self.check(strict.encode(), required_mutual=True)
        with self.assertRaises(ValueError):
            self.check(strict.encode())
        for substitute in ("", "# CONFIG_ISCSI_TARGET_STRICT_MUTUAL_CHAP is not set",
                           "CONFIG_ISCSI_TARGET_STRICT_MUTUAL_CHAP=m", line + "\n" + line):
            with self.subTest(substitute=substitute), self.assertRaises(ValueError):
                self.check(strict.replace(line, substitute).encode(), required_mutual=True)
        self.check((self.valid() + "\n# CONFIG_ISCSI_TARGET_STRICT_MUTUAL_CHAP is not set").encode())

    def test_every_required_symbol_missing_module_or_duplicate_refused(self):
        for symbol in inputs.ENABLED:
            line = f"CONFIG_{symbol}=y"
            for substitute in ("", f"CONFIG_{symbol}=m", line + "\n" + line):
                with self.subTest(symbol=symbol, substitute=substitute):
                    with self.assertRaises(ValueError):
                        self.check(self.valid().replace(line, substitute).encode())

    def test_every_excluded_backend_or_initiator_refused(self):
        for symbol in inputs.DISABLED:
            line = f"# CONFIG_{symbol} is not set"
            for substitute in (f"CONFIG_{symbol}=m", f"CONFIG_{symbol}=y",
                               line + "\n" + line):
                with self.subTest(symbol=symbol, substitute=substitute):
                    with self.assertRaises(ValueError):
                        self.check(self.valid().replace(line, substitute).encode())

    def test_disabled_symbols_hidden_by_kconfig_dependencies(self):
        data = self.valid()
        for symbol in inputs.DISABLED:
            data = data.replace(f"# CONFIG_{symbol} is not set", "")
        self.check(data.encode())

    def test_size_and_non_ascii_refused(self):
        for data in (b"#" * (1024 * 1024 + 1), b"\xff"):
            with self.assertRaises(ValueError):
                self.check(data)

    def test_nonregular_missing_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for path in (directory, directory / "missing"):
                with self.assertRaises(ValueError):
                    inputs.audit(path)
            source = directory / "config"
            source.write_text(self.valid())
            link = directory / "link"
            try:
                link.symlink_to(source)
            except OSError:
                return  # Windows symlinks may require privileges; Linux covers it.
            with self.assertRaises(ValueError):
                inputs.audit(link)


if __name__ == "__main__":
    unittest.main()
