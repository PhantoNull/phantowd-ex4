#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Compile real pinned watched-reader bodies; replace only the raw DB backend.

This is a host source regression, not full CLI/serializer or ARM
qualification.
Usage: this-file.py CACHED_SAMBA_SOURCE; cached input is never modified.
"""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct { uint8_t *dptr; size_t dsize; } TDB_DATA;
struct db_record { TDB_DATA value; bool value_valid; };
struct db_context { void *private_data;
 int (*traverse_read)(struct db_context *,
                      int (*)(struct db_record *, void *), void *); };
struct db_watched_ctx { struct db_context *backend; };
typedef int NTSTATUS;
#define NT_STATUS_OK 0
#define NT_STATUS_INTERNAL_DB_CORRUPTION 1
#define NT_STATUS_REQUEST_ABORTED 20
#define NT_STATUS_FILE_CORRUPT_ERROR 23
#define NT_STATUS_IS_OK(s) ((s) == NT_STATUS_OK)
#define talloc_get_type_abort(p, t) ((t *)(p))
#define DBWRAP_WATCHER_BUF_LENGTH 32
#define IVAL(p,i) ((uint32_t)(p)[i] | ((uint32_t)(p)[(i)+1]<<8) | \
 ((uint32_t)(p)[(i)+2]<<16) | ((uint32_t)(p)[(i)+3]<<24))
'''
BACKEND = r'''
static struct db_record input;
static int records, callbacks, result;
static int backend(struct db_context *db,
 int (*fn)(struct db_record *, void *), void *data) {
 (void)db;
 if (records > 0) { (void)fn(&input, data); }
 return records; /* TDB returns a count even after callback refusal. */
}
static int consume(struct db_record *rec, void *data) {
 (void)data;
 if (!rec->value_valid || rec->value.dsize != 1) { abort(); }
 callbacks++; return result;
}
int main(int argc, char **argv) {
 uint8_t healthy[] = {0,0,0,0,42}, bad[] = {1};
 uint8_t short_watchers[] = {1,0,0,0,42};
 struct db_context raw = {.traverse_read=backend};
 struct db_watched_ctx watched = {.backend=&raw};
 struct db_context db = {.private_data=&watched};
 if (argc != 2) { return 99; }
 records=1; input.value=(TDB_DATA){healthy,sizeof(healthy)};
 switch (atoi(argv[1])) {
 case 0: records=0; break;
 case 1: break;
 case 2: input.value=(TDB_DATA){bad,sizeof(bad)}; break;
 case 3: input.value=(TDB_DATA){short_watchers,sizeof(short_watchers)}; break;
 case 4: result=-1; break;
 case 5: input.value.dsize=0; break;
 case 6: result=1; break;
 case 7: records=-1; break;
 default: return 99;
 }
 NTSTATUS status = dbwrap_watched_traverse_read_complete(&db,consume,NULL);
 printf("%d %d\n", status, callbacks);
 return 0;
}
'''


def function(source, name):
    matches = list(re.finditer(
        rf"(?m)^(?:static )?(?:bool|int|NTSTATUS) {name}\([^;]*?\)\s*\{{",
        source))
    if len(matches) != 1:
        raise ValueError(f"nonunique function: {name}")
    start, end, depth = matches[0].start(), matches[0].end(), 1
    while depth and end < len(source):
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if depth:
        raise ValueError(f"unterminated function: {name}")
    return source[start:end]


HASHES = (
    "57a10407fa3b7c11a9dca95a21f201544d3073f30ba82e42a5100734d12151a5",
    "c7627d57e9f0e8c7e25e3acb4646f085152e0b8be6e9bec777a033487eb0ea84",
    "960814783c7d00d1258925e850e882fcb14288b189d2e075b6d34ad4aa3679f4")
PATCH = (Path(__file__).resolve().parents[2] /
         "board/qemu/armv5/patches/samba4/4.22.11" /
         "0003-smbstatus-complete-session-inventory.patch")


class CompleteReader(unittest.TestCase):
    def test_errors_survive_positive_backend_count(self):
        root = Path(sys.argv[1])
        with tempfile.TemporaryDirectory(prefix="samba-complete-") as tmp:
            scratch = Path(tmp)
            watch = (root / "source3/lib/dbwrap/dbwrap_watch.c").read_bytes()
            digest = hashlib.sha256(watch).hexdigest()
            if digest == HASHES[0]:
                paths = re.findall(
                    r"(?m)^--- a/(source3/[a-zA-Z_/.]+)$", PATCH.read_text())
                self.assertEqual(len(paths), 7)
                for name in paths:
                    target = scratch / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(root / name, target)
                subprocess.run(
                    ["patch", "-d", tmp, "-p1", "--fuzz=0", "--batch",
                     "-i", str(PATCH)], check=True, timeout=10)
                path = scratch / "source3/lib/dbwrap/dbwrap_watch.c"
                watch = path.read_bytes()
            self.assertEqual(hashlib.sha256(watch).hexdigest(), HASHES[1])
            common = (root / "lib/dbwrap/dbwrap.c").read_bytes()
            self.assertEqual(hashlib.sha256(common).hexdigest(), HASHES[2])
            watch = watch.decode()
            state, = re.findall(
                r"struct dbwrap_complete_read_state \{[^}]*\};", watch)
            parts = [function(common.decode(), "dbwrap_traverse_read"),
                     function(watch, "dbwrap_watch_rec_parse"), state,
                     function(watch, "dbwrap_complete_read_fn"),
                     function(watch, "dbwrap_watched_traverse_read_complete")]
            code = PRELUDE + "\n".join(parts) + BACKEND
            (scratch / "test.c").write_text(code)
            subprocess.run(
                ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 str(scratch / "test.c"), "-o", str(scratch / "test")],
                check=True, timeout=20)
            for case, expected in enumerate(
                    ["0 0", "0 1", "23 0", "23 0",
                     "20 1", "0 0", "20 1", "1 0"]):
                with self.subTest(case=case):
                    result = subprocess.run(
                        [str(scratch / "test"), str(case)],
                        capture_output=True,
                        text=True, check=True, timeout=2)
                    self.assertEqual(result.stdout.strip(), expected)
                    self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("provide cached pinned Samba source")
    unittest.main(argv=[sys.argv[0]])
