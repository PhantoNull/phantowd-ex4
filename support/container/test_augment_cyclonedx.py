#!/usr/bin/env python3
"""Unit tests for the pinned Go-module SBOM augmentation."""

import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("augment-cyclonedx.py")
SPEC = importlib.util.spec_from_file_location("augment_cyclonedx", SCRIPT)
augment_cyclonedx = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(augment_cyclonedx)


class AugmentCycloneDXTests(unittest.TestCase):
    def setUp(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        go_mod = repo_root / "src" / "phantowd-api" / "go.mod"
        self.modules = augment_cyclonedx.modules_from_go_mod(
            go_mod.read_text(encoding="utf-8")
        )
        self.bom = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "type": "library",
                    "bom-ref": "phantowd-api",
                    "name": "phantowd-api",
                }
            ],
            "dependencies": [{"ref": "phantowd-api", "dependsOn": []}],
        }

    def test_adds_pinned_go_components_licenses_and_dependency_edges(self):
        result = augment_cyclonedx.augment(self.bom, self.modules)
        components = {item["name"]: item for item in result["components"]}
        dependencies = {
            item["ref"]: item["dependsOn"] for item in result["dependencies"]
        }

        self.assertEqual(
            components["golang.org/x/crypto"]["version"], "v0.57.0"
        )
        self.assertEqual(components["golang.org/x/sys"]["version"], "v0.48.0")
        for name in ("golang.org/x/crypto", "golang.org/x/sys"):
            self.assertEqual(
                components[name]["licenses"][0]["license"]["id"],
                "BSD-3-Clause",
            )
        self.assertEqual(
            dependencies["phantowd-api"],
            [self.modules[0]["purl"]],
        )
        self.assertEqual(
            dependencies[self.modules[0]["purl"]],
            self.modules[0]["depends_on"],
        )

    def test_rejects_duplicate_or_ambiguous_input(self):
        duplicate = {
            "type": "library",
            "bom-ref": "another-api",
            "name": "phantowd-api",
        }
        self.bom["components"].append(duplicate)
        with self.assertRaises(ValueError):
            augment_cyclonedx.augment(self.bom, self.modules)

    def test_rejects_repeated_augmentation(self):
        augmented = augment_cyclonedx.augment(self.bom, self.modules)
        with self.assertRaises(ValueError):
            augment_cyclonedx.augment(augmented, self.modules)

    def test_versions_follow_go_mod_and_missing_modules_fail_closed(self):
        fixture = """
module test.invalid/fixture
go 1.26.0
require (
    golang.org/x/crypto v9.8.7
    golang.org/x/sys v6.5.4 // indirect
)
"""
        modules = augment_cyclonedx.modules_from_go_mod(fixture)
        self.assertEqual(modules[0]["version"], "v9.8.7")
        self.assertEqual(modules[1]["version"], "v6.5.4")
        with self.assertRaises(ValueError):
            incomplete_go_mod = (
                "module test.invalid/fixture\n"
                "require golang.org/x/crypto v9.8.7\n"
            )
            augment_cyclonedx.modules_from_go_mod(
                incomplete_go_mod
            )


if __name__ == "__main__":
    unittest.main()
