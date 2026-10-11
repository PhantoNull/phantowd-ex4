#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Fixed disposable client-root build inputs, never a release manifest."""
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
import sys

from runtime_loader_fixture import validate


DOCUMENTS = frozenset({"sys/firmware/devicetree/base/model", "etc/passwd",
                       "etc/group", "etc/nsswitch.conf", "etc/hosts",
                       "etc/samba/smb.conf", "usr/lib/gconv/gconv-modules"})
OBSERVER = "usr/lib/libphantowd-pending-handle-qemu.so"


def merge_charset(report, charset):
    """Add the fixed dynamic conversion closure, not an arbitrary module."""
    extra, _, _ = validate(charset, fixed_entry="usr/lib/gconv/IBM850.so")
    if (not isinstance(report, dict)
            or not isinstance(report.get("objects"), list)):
        raise ValueError("invalid client candidate")
    objects = report["objects"]
    if (any(not isinstance(item, dict) or type(item.get("size")) is not int
            or item["size"] <= 0 or not canonical(item.get("path"))
            for item in objects)
            or type(report.get("total_bytes")) is not int
            or report["total_bytes"] != sum(item["size"] for item in objects)):
        raise ValueError("invalid original client byte evidence")
    known = {item["path"]: item for item in objects}
    if len(known) != len(objects):
        raise ValueError("duplicate original client object")
    merged = list(objects)
    for item in extra:
        prior = known.get(item["path"])
        if prior is not None:
            if prior != item:
                raise ValueError("shared conversion dependency changed")
        else:
            merged.append(item)
    return {**report, "objects": merged,
            "total_bytes": sum(item["size"] for item in merged)}


def read_bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                 | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError("regular bounded build input required")
        source = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with source:
        data = source.read(limit + 1)
        after = os.fstat(source.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_uid",
                  "st_gid", "st_nlink", "st_mtime_ns", "st_ctime_ns")
        if (len(data) != before.st_size
                or any(getattr(before, key) != getattr(after, key)
                       for key in fields)):
            raise ValueError("original build input changed")
        return data


def merge_observer(report, observer):
    """Independent fixed module closure; shared evidence must match exactly."""
    manifest(report, {name: "scope-validation" for name in DOCUMENTS},
             b"client-scope", b"helper-scope")
    extra, _, _ = validate(observer, fixed_entry=OBSERVER)
    known = {item["path"]: item for item in report["objects"]}
    if OBSERVER in known:
        raise ValueError("observer already present in base candidate")
    merged = list(report["objects"])
    for item in extra:
        prior = known.get(item["path"])
        if prior is not None:
            if prior != item:
                raise ValueError("shared observer dependency changed")
        elif item["path"] == OBSERVER:
            if item["size"] > 1024 * 1024 or item["bindings"] != [OBSERVER]:
                raise ValueError("fixed bounded observer required")
            merged.append(item)
        else:
            raise ValueError("unqualified additional observer dependency")
    result = {**report, "objects": merged,
              "total_bytes": sum(item["size"] for item in merged)}
    manifest(result, {name: "scope-validation" for name in DOCUMENTS},
             b"client-scope", b"helper-scope")
    return result


def observer_tree(report_path, charset_path, target_path, module_path,
                  root_path):
    """Minimal disposable inspection tree, not a retained execution root."""
    combined = merge_charset(
        json.loads(read_bounded(report_path, 1024 * 1024)),
        json.loads(read_bounded(charset_path, 1024 * 1024)))
    plan = manifest(combined, {name: "scope-validation" for name in DOCUMENTS},
                    b"client-scope", b"helper-scope")
    if any(item["Path"] == OBSERVER for item in plan["RootFiles"]):
        raise ValueError("observer already in original closure")
    if any(item["Path"] == OBSERVER for item in plan["RootAliases"]):
        raise ValueError("observer binding collision")
    module = read_bounded(module_path, 1024 * 1024)
    root = Path(root_path)
    root.mkdir(mode=0o700)  # Refuse existing/caller-replaced destinations.
    for item in combined["objects"]:
        data = read_bounded(Path(target_path) / item["path"],
                            64 * 1024 * 1024)
        if (len(data) != item["size"]
                or hashlib.sha256(data).hexdigest() != item["sha256"]):
            raise ValueError("inspection source changed")
        actual = root / item["path"]
        actual.parent.mkdir(parents=True, exist_ok=True)
        actual.write_bytes(data)
    for item in plan["RootAliases"]:
        alias = root / item["Path"]
        alias.parent.mkdir(parents=True, exist_ok=True)
        alias.symlink_to(os.path.relpath(root / item["Target"], alias.parent))
    actual = root / OBSERVER
    actual.parent.mkdir(parents=True, exist_ok=True)
    actual.write_bytes(module)


def canonical(value):
    return (isinstance(value, str) and len(value) <= 4096
            and re.fullmatch(r"[a-zA-Z0-9_./+-]+", value)
            and not value.startswith("/")
            and all(part not in ("", ".", "..") for part in value.split("/"))
            and str(PurePosixPath(value)) == value)


def metadata(path, data, mode):
    if not canonical(path) or not data or len(data) > 64 * 1024 * 1024:
        raise ValueError("invalid fixed file")
    return {"Path": path, "SHA256": hashlib.sha256(data).hexdigest(),
            "Size": len(data), "Mode": mode}


def manifest(report, documents, client, helper):
    if (not isinstance(report, dict)
            or report.get("format") != "phantowd-elf-runtime-candidate"
            or type(report.get("schema_version")) is not int
            or report["schema_version"] != 1
            or report.get("entry") != "usr/lib/libsmbclient.so.0"
            or report.get("static_dependencies_resolved") is not True
            or report.get("runtime_qualified") is not False
            or report.get("execution_authorized") is not False):
        raise ValueError("invalid offline candidate")
    objects = report.get("objects")
    if not isinstance(objects, list) or not 2 <= len(objects) <= 248:
        raise ValueError("object budget")
    files, paths, bindings = [], set(), {}
    total = 0
    for item in objects:
        if not isinstance(item, dict):
            raise ValueError("invalid object")
        path = item.get("path")
        digest, size = item.get("sha256"), item.get("size")
        names = item.get("bindings")
        if (not canonical(path) or path in paths or path in DOCUMENTS
                or path.startswith("fixture/")
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or type(size) is not int or size <= 0
                or not isinstance(names, list) or not names):
            raise ValueError("invalid original object")
        paths.add(path)
        total += size
        files.append({"Path": path, "SHA256": digest,
                      "Size": size, "Mode": 0o555})
        for name in names:
            if (not canonical(name) or name in bindings or name in DOCUMENTS
                    or name.startswith("fixture/")):
                raise ValueError("invalid binding")
            bindings[name] = path
    for path in paths:
        if path in bindings and bindings[path] != path:
            raise ValueError("canonical binding conflict")
        bindings[path] = path
    if (type(report.get("total_bytes")) is not int
            or report["total_bytes"] != total
            or total > 64 * 1024 * 1024 or len(bindings) > 1024
            or "lib/ld-linux.so.3" not in bindings
            or "usr/lib/libsmbclient.so.0" not in bindings
            or "usr/lib/gconv/IBM850.so" not in bindings):
        raise ValueError("closure budget or missing fixed binding")
    if (not isinstance(documents, dict) or set(documents) != DOCUMENTS
            or any(not isinstance(value, str) or not value
                   or len(value.encode()) > 4096
                   for value in documents.values())):
        raise ValueError("fixed documents required")
    if (not client or len(client) > 1024 * 1024
            or not helper or len(helper) > 1024 * 1024):
        raise ValueError("program budget")
    files.append(metadata("fixture/pending-write", client, 0o555))
    files.extend(metadata(name, value.encode(), 0o444)
                 for name, value in documents.items())
    if sum(item["Size"] for item in files) > 64 * 1024 * 1024:
        raise ValueError("complete root budget")
    return {"Format": "phantowd-qemu-pending-client-inputs-v1",
            "RootFiles": sorted(files, key=lambda item: item["Path"]),
            "RootAliases": [{"Path": name, "Target": target}
                            for name, target in sorted(bindings.items())
                            if name != target],
            "BootstrapFiles": [metadata("fixture/launcher", helper, 0o555)]}


def produce(report_path, charset_path, documents_path, client_path,
            helper_path, target_path, scratch_path, observer_report=None,
            observer_path=None):
    # All outputs belong to the wrapper's newly-created disposable tmpfs tree.
    scratch = Path(scratch_path)
    report_data = read_bounded(report_path, 1024 * 1024)
    charset_data = read_bounded(charset_path, 1024 * 1024)
    documents_data = read_bounded(documents_path, 64 * 1024)
    documents = json.loads(documents_data)
    client = read_bounded(client_path, 1024 * 1024)
    helper = read_bounded(helper_path, 1024 * 1024)
    combined = merge_charset(json.loads(report_data), json.loads(charset_data))
    if (observer_report is None) != (observer_path is None):
        raise ValueError("both fixed observer inputs required")
    if observer_report is not None:
        combined = merge_observer(combined, json.loads(
            read_bounded(observer_report, 1024 * 1024)))
    value = manifest(combined, documents, client, helper)
    docs = scratch / "documents"
    docs.mkdir(mode=0o700)
    source = "/usr/lib/phantowd/pending-source"
    directories = {source, "/usr/lib/phantowd"}
    mappings = {}
    for index, item in enumerate(value["RootFiles"] + value["BootstrapFiles"]):
        path = item["Path"]
        if path in DOCUMENTS:
            actual = docs / f"{index}.data"
            actual.write_bytes(documents[path].encode())
        elif path == "fixture/pending-write":
            actual = Path(client_path)
        elif path == "fixture/launcher":
            actual = Path(helper_path)
        elif path == OBSERVER and observer_path is not None:
            actual = Path(observer_path)
        else:
            actual = Path(target_path) / path
        if actual.is_symlink() or not actual.is_file():
            raise ValueError("regular original build input required")
        data = read_bounded(actual, 64 * 1024 * 1024)
        if (len(data) != item["Size"]
                or hashlib.sha256(data).hexdigest() != item["SHA256"]):
            raise ValueError("build input changed")
        mappings[path] = str(actual)
        parent = PurePosixPath(source + "/" + path).parent
        while str(parent).startswith(source):
            directories.add(str(parent))
            parent = parent.parent
    commands = [f"mkdir {directory}\n" for directory in
                sorted(directories, key=lambda d: (d.count('/'), d))]
    for path, actual in sorted(mappings.items()):
        if not re.fullmatch(r"[a-zA-Z0-9_./+-]+", actual):
            raise ValueError("fixed build path alphabet")
        commands.append(f"write {actual} {source}/{path}\n")
    (scratch / "stage.commands").write_text("".join(commands),
                                            encoding="ascii")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    (scratch / "inputs.json").write_text(encoded, encoding="ascii")
    print(json.dumps({"format": "phantowd-pending-inputs-build-diagnostic",
                      "qualifying": False, "client_executed": False,
                      "manifest": value}, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) == 7 and sys.argv[1] == "observer-tree":
        observer_tree(*sys.argv[2:])
    elif len(sys.argv) in (8, 10):
        produce(*sys.argv[1:])
    else:
        raise SystemExit("fixed fixture build inputs required")
