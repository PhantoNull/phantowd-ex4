#!/usr/bin/env python3
"""Add pinned Go modules to Buildroot's package-level CycloneDX output."""

import json
import sys
from pathlib import Path


MODULE_SOURCES = {
    "golang.org/x/crypto": "https://go.googlesource.com/crypto",
    "golang.org/x/sys": "https://go.googlesource.com/sys",
}


def modules_from_go_mod(contents):
    versions = {}
    in_require_block = False
    for raw_line in contents.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if line == "require (":
            in_require_block = True
            continue
        if line == ")" and in_require_block:
            in_require_block = False
            continue
        if in_require_block:
            fields = line.split()
        elif line.startswith("require "):
            fields = line.split()[1:]
        else:
            continue
        if len(fields) >= 2 and fields[0] in MODULE_SOURCES:
            if fields[0] in versions or not fields[1].startswith("v"):
                raise ValueError(
                    f"invalid or repeated Go module requirement: {fields[0]}"
                )
            versions[fields[0]] = fields[1]

    missing = set(MODULE_SOURCES) - set(versions)
    if missing:
        raise ValueError(
            f"Go module requirements missing from go.mod: {sorted(missing)}"
        )

    modules = []
    for name, vcs_url in MODULE_SOURCES.items():
        version = versions[name]
        purl = f"pkg:golang/{name}@{version}"
        modules.append(
            {
                "name": name,
                "version": version,
                "purl": purl,
                "vcs_url": vcs_url,
                "depends_on": [],
            }
        )
    modules[0]["depends_on"].append(modules[1]["purl"])
    return modules


def _set_dependency(dependencies, ref, required):
    records = [entry for entry in dependencies if entry.get("ref") == ref]
    if len(records) > 1:
        raise ValueError(f"duplicate CycloneDX dependency ref: {ref}")
    if not records:
        records.append({"ref": ref, "dependsOn": []})
        dependencies.append(records[0])
    edges = records[0].setdefault("dependsOn", [])
    if not isinstance(edges, list):
        raise ValueError(f"invalid CycloneDX dependency edges for: {ref}")
    for dependency in required:
        if dependency not in edges:
            edges.append(dependency)


def augment(document, modules):
    components = document.get("components")
    dependencies = document.get("dependencies")
    if not isinstance(components, list) or not isinstance(dependencies, list):
        raise ValueError(
            "expected CycloneDX components and dependencies arrays"
        )
    api = [item for item in components if item.get("name") == "phantowd-api"]
    if len(api) != 1:
        raise ValueError("expected exactly one phantowd-api SBOM component")

    module_names = {module.get("name") for module in modules}
    module_count = len(MODULE_SOURCES)
    if module_names != set(MODULE_SOURCES) or len(modules) != module_count:
        raise ValueError(
            "Go module metadata does not match expected dependencies"
        )
    by_name = {module["name"]: module for module in modules}
    ordered_modules = [by_name[name] for name in MODULE_SOURCES]

    for module in ordered_modules:
        ref = module["purl"]
        already_present = any(
            item.get("bom-ref") == ref or item.get("name") == module["name"]
            for item in components
        )
        if already_present:
            module_name = module["name"]
            raise ValueError(
                f"Go module already present in CycloneDX input: {module_name}"
            )
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": module["name"],
                "version": module["version"],
                "purl": ref,
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "externalReferences": [
                    {"type": "vcs", "url": module["vcs_url"]}
                ],
            }
        )

    api_ref = api[0].get("bom-ref")
    if not isinstance(api_ref, str) or not api_ref:
        raise ValueError("phantowd-api SBOM component has no bom-ref")
    _set_dependency(dependencies, api_ref, [ordered_modules[0]["purl"]])
    for module in ordered_modules:
        _set_dependency(dependencies, module["purl"], module["depends_on"])
    return document


def main():
    try:
        repo_root = Path(__file__).resolve().parents[2]
        go_mod = repo_root / "src" / "phantowd-api" / "go.mod"
        modules = modules_from_go_mod(go_mod.read_text(encoding="utf-8"))
        document = json.load(sys.stdin)
        result = augment(document, modules)
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        message = f"CycloneDX Go-module augmentation failed: {error}"
        print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
