#!/usr/bin/env python3
"""Host-only RED regression at Samba's public read-traversal boundary.

Reads exact, already-cached GPL source; compiles unchanged function bodies in
temporary storage, with only the underlying database replaced by synthetic data.
Not a full smbstatus/serializer test, an upstream patch, or product qualification.
Usage: python3 -B this-file.py /path/to/samba4-4.22.11
"""

import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest


def pinned_source(root, name, expected):
    data = (root / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"source identity mismatch: {name}")
    return data.decode("utf-8")


def function(source, name):
    matches = list(re.finditer(
        rf"(?m)^(?:static )?(?:bool|int|NTSTATUS) {name}\([^;]*?\)\s*\{{",
        source))
    if len(matches) != 1:
        raise ValueError(f"function boundary is not unique: {name}")
    match = matches[0]
    depth = 1
    end = match.end()
    while depth and end < len(source):
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if depth:
        raise ValueError(f"unterminated function: {name}")
    return source[match.start():end]


PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct { uint8_t *dptr; size_t dsize; } TDB_DATA;
struct db_record { TDB_DATA value; bool value_valid; };
struct db_context {
    void *private_data;
    int (*traverse_read)(struct db_context *,
                         int (*)(struct db_record *, void *), void *);
};
struct db_watched_ctx { struct db_context *backend; void *msg; };
typedef int NTSTATUS;
#define NT_STATUS_OK 0
#define NT_STATUS_INTERNAL_DB_CORRUPTION 1
#define NT_STATUS_IS_OK(s) ((s) == NT_STATUS_OK)
#define talloc_get_type_abort(p, t) ((t *)(p))
#define DBWRAP_WATCHER_BUF_LENGTH 32
#define IVAL(p, i) ((uint32_t)(p)[i] | ((uint32_t)(p)[(i)+1] << 8) | \
    ((uint32_t)(p)[(i)+2] << 16) | ((uint32_t)(p)[(i)+3] << 24))
'''

BACKEND = r'''
static struct db_record input;
static int records, callbacks, callback_result;
/* Match tdb_traverse_read: the result is a visited-record count, not the
 * callback's stop value. A callback stop must not be confused with -1 here. */
static int backend(struct db_context *db,
                   int (*fn)(struct db_record *, void *), void *private_data)
{
    (void)db;
    if (records != 0) { (void)fn(&input, private_data); }
    return records;
}
static int consume(struct db_record *record, void *private_data)
{
    (void)private_data;
    if (!record->value_valid || record->value.dsize != 1) { abort(); }
    callbacks++;
    return callback_result;
}
int main(int argc, char **argv)
{
    uint8_t healthy[] = {0, 0, 0, 0, 42};
    uint8_t malformed[] = {1};
    uint8_t partial[] = {1, 0, 0, 0, 42};
    struct db_context raw = {.traverse_read = backend};
    struct db_watched_ctx watched = {.backend = &raw};
    struct db_context db = {
        .private_data = &watched, .traverse_read = dbwrap_watched_traverse_read};
    int count = -1;
    NTSTATUS status;
    if (argc != 2) { return 99; }
    records = 1;
    input.value = (TDB_DATA){healthy, sizeof(healthy)};
    switch (atoi(argv[1])) {
    case 0: records = 0; break;
    case 1: break;
    case 2: input.value = (TDB_DATA){malformed, sizeof(malformed)}; break;
    case 3: input.value = (TDB_DATA){partial, sizeof(partial)}; break;
    case 4: callback_result = -1; break;
    case 5: input.value.dsize = 0; break; /* Valid deleted/tombstone record. */
    default: return 99;
    }
    status = dbwrap_traverse_read(&db, consume, NULL, &count);
    printf("status=%d count=%d callbacks=%d\n", status, count, callbacks);
    return 0;
}
'''


class WatchedTraversal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(sys.argv[1])
        watch = pinned_source(
            root, "source3/lib/dbwrap/dbwrap_watch.c",
            "57a10407fa3b7c11a9dca95a21f201544d3073f30ba82e42a5100734d12151a5")
        common = pinned_source(
            root, "lib/dbwrap/dbwrap.c",
            "960814783c7d00d1258925e850e882fcb14288b189d2e075b6d34ad4aa3679f4")
        state = re.findall(
            r"struct dbwrap_watched_traverse_state \{[^}]*\};", watch)
        if len(state) != 1:
            raise ValueError("traversal state is not unique")
        fragments = [function(common, "dbwrap_traverse_read"),
                     function(watch, "dbwrap_watch_rec_parse"), state[0],
                     function(watch, "dbwrap_watched_traverse_fn"),
                     function(watch, "dbwrap_watched_traverse_read")]
        cls.temporary = tempfile.TemporaryDirectory(prefix="samba-watch-host-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = pathlib.Path(cls.temporary.name)
        source = directory / "test.c"
        source.write_text(PRELUDE + "\n".join(fragments) + BACKEND)
        cls.binary = directory / "test"
        subprocess.run(["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(cls.binary)],
                       check=True, timeout=20)

    def observe(self, case):
        result = subprocess.run([str(self.binary), str(case)], check=True,
                                capture_output=True, text=True, timeout=2)
        self.assertEqual(result.stderr, "")
        return dict(field.split("=") for field in result.stdout.split())

    def test_empty_database_is_success(self):
        self.assertEqual(self.observe(0),
                         {"status": "0", "count": "0", "callbacks": "0"})

    def test_healthy_record_reaches_callback(self):
        self.assertEqual(self.observe(1),
                         {"status": "0", "count": "1", "callbacks": "1"})

    def test_deleted_record_is_not_malformed(self):
        self.assertEqual(self.observe(5),
                         {"status": "0", "count": "1", "callbacks": "0"})

    def test_malformed_watched_record_is_not_clean_inventory(self):
        observed = self.observe(2)
        self.assertNotEqual(observed["status"], "0", observed)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("provide the existing pinned Samba source directory")
    unittest.main(argv=[sys.argv[0]], verbosity=2)
