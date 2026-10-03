#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Regressions for cached fragment changes and storage ACL requirements."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "kernel_inputs", ROOT / "support/container/qemu_kernel_inputs.py")
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


class KernelInputs(unittest.TestCase):
    def populate(self, root):
        external, buildroot = root / "external", root / "buildroot"
        for base, name in [*(
                (external, name) for name in inputs.EXTERNAL_FILES),
                (buildroot, inputs.BUILDROOT_FILE)]:
            file = base / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(name)
        (external / inputs.EXTERNAL_FILES[0]).write_text(
            inputs.FRAGMENT_DECLARATION + "\n")
        return external, buildroot

    def test_every_fragment_invalidates_cached_fingerprint(self):
        with tempfile.TemporaryDirectory() as temp:
            external, buildroot = self.populate(Path(temp))
            before = inputs.fingerprint(external, buildroot)
            for base, name in [*(
                    (external, name) for name in inputs.EXTERNAL_FILES),
                    (buildroot, inputs.BUILDROOT_FILE)]:
                file = base / name
                original = file.read_text()
                file.write_text(original + "\nCONFIG_CHANGED=y\n")
                self.assertNotEqual(inputs.fingerprint(external, buildroot),
                                    before)
                file.write_text(original)
            self.assertEqual(inputs.fingerprint(external, buildroot), before)

    def test_unknown_missing_or_duplicate_fragment_roster_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            external, buildroot = self.populate(Path(temp))
            file = external / inputs.EXTERNAL_FILES[0]
            invalid = ("", inputs.FRAGMENT_DECLARATION + "\n" +
                       inputs.FRAGMENT_DECLARATION,
                       inputs.FRAGMENT_DECLARATION[:-1] + ' extra.fragment"')
            for text in invalid:
                file.write_text(text)
                with self.assertRaises(ValueError):
                    inputs.fingerprint(external, buildroot)

    def test_checkout_and_workspace_paths_do_not_change_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            first = self.populate(Path(temp) / "first")
            second = self.populate(Path(temp) / "second")
            self.assertEqual(inputs.fingerprint(*first),
                             inputs.fingerprint(*second))

    def test_missing_input_or_oversized_config_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            external, buildroot = self.populate(Path(temp))
            file = external / inputs.EXTERNAL_FILES[0]
            file.unlink()
            with self.assertRaises(ValueError):
                inputs.fingerprint(external, buildroot)
            file.write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                inputs.fingerprint(external, buildroot)

    def test_absent_disabled_duplicate_or_conflicting_acl_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "config"
            good = "\n".join(inputs.REQUIRED) + "\n"
            config.write_text(good)
            inputs.audit(config)
            acl = "CONFIG_EXT4_FS_POSIX_ACL=y"
            for text in (good.replace(acl, ""),
                         good.replace(acl, acl[:-1] + "n"),
                         good + acl + "\n", good + "CONFIG_MD_AUTODETECT=y\n"):
                config.write_text(text)
                with self.assertRaises(ValueError):
                    inputs.audit(config)

    def test_build_refreshes_cached_kernel_and_audits_before_checkpoint(self):
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        self.assertIn('"$linux_inputs_previous" != "$linux_inputs_digest"',
                      script)
        refresh = script.index("linux-reconfigure")
        audit = script.index('"$kernel_inputs_helper" audit')
        checkpoint = script.index("printf 'complete\\n'")
        stamp = script.index('mv "$linux_inputs_stamp.part"')
        self.assertLess(refresh, audit)
        self.assertLess(audit, stamp)
        self.assertLess(stamp, checkpoint)

    def test_policy_routing_support_cannot_be_silently_absent(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "config"
            good = "\n".join(inputs.REQUIRED) + "\n"
            for key in ("CONFIG_IP_ADVANCED_ROUTER",
                        "CONFIG_IP_MULTIPLE_TABLES",
                        "CONFIG_IPV6_MULTIPLE_TABLES", "CONFIG_FIB_RULES"):
                self.assertIn(key + "=y", inputs.REQUIRED)
                for replacement in ("", key + "=n", key + "=m",
                                    "# " + key + " is not set"):
                    config.write_text(
                        good.replace(key + "=y", replacement))
                    with self.assertRaises(ValueError):
                        inputs.audit(config)


if __name__ == "__main__":
    unittest.main()
