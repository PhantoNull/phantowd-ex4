/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#define _GNU_SOURCE
#include <blkid/blkid.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

/* No path arguments, device enumeration, cache API, mount or repair operation.
 * The trusted caller supplies exactly one O_RDONLY regular/block object on
 * stdin. Results are observations, never an authorization to mount/import. */
static int fail(void)
{
    fputs("volume metadata probe failed\n", stderr);
    return 1;
}

static int token_is(blkid_probe probe, const char *key, const char *wanted)
{
    const char *value = NULL;
    size_t length = 0, wanted_length = strlen(wanted);
    if (blkid_probe_lookup_value(probe, key, &value, &length) != 0 || !value)
        return 0;
    if (length && value[length - 1] == '\0')
        --length;
    return length == wanted_length && memcmp(value, wanted, length) == 0;
}

static int read_uuid(blkid_probe probe, char out[37])
{
    const char *value = NULL;
    size_t length = 0;
    int nonzero = 0;
    if (blkid_probe_lookup_value(probe, "UUID", &value, &length) != 0 || !value)
        return -1;
    if (length && value[length - 1] == '\0')
        --length;
    if (length != 36)
        return -1;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return -1;
        } else {
            if (c >= 'A' && c <= 'F')
                c = (unsigned char)(c + ('a' - 'A'));
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return -1;
            nonzero |= c != '0';
        }
        out[i] = (char)c;
    }
    out[36] = '\0';
    return nonzero ? 0 : -1;
}

static int emit(const char *status, const char *kind, const char *filesystem,
                const char *uuid)
{
    /* Every substituted value is a fixed literal or validated UUID. No labels,
     * serial numbers, source paths or arbitrary library tokens are emitted. */
    int written = printf("{\"schema_version\":1,\"status\":\"%s\","
                         "\"source_kind\":\"%s\",\"filesystem\":\"%s\","
                         "\"filesystem_uuid\":\"%s\",\"mount_performed\":false,"
                         "\"compatibility_qualified\":false,\"activation_allowed\":false}\n",
                         status, kind, filesystem, uuid);
    return written < 0 || fflush(stdout) == EOF ? 1 : 0;
}

int main(int argc, char **argv)
{
    (void)argv;
    struct stat before, after;
    struct rlimit memory = {64U * 1024U * 1024U, 64U * 1024U * 1024U};
    struct rlimit cpu = {2, 2}, core = {0, 0};
    int flags = fcntl(STDIN_FILENO, F_GETFL);
    if (argc != 1 || flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        (flags & O_PATH) || fstat(STDIN_FILENO, &before) != 0 ||
        (!S_ISREG(before.st_mode) && !S_ISBLK(before.st_mode)))
        return fail();
    if (setrlimit(RLIMIT_AS, &memory) != 0 || setrlimit(RLIMIT_CPU, &cpu) != 0 ||
        setrlimit(RLIMIT_CORE, &core) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        signal(SIGALRM, SIG_DFL) == SIG_ERR)
        return fail();
    alarm(5); /* Not a guarantee against kernel uninterruptible device I/O. */
    const char *kind = S_ISREG(before.st_mode) ? "regular-image" : "block-device";
    blkid_probe probe = blkid_new_probe();
    if (!probe)
        return fail();
    if (blkid_probe_set_device(probe, STDIN_FILENO, 0, 0) != 0 ||
        blkid_probe_enable_superblocks(probe, 1) != 0 ||
        blkid_probe_set_superblocks_flags(probe, BLKID_SUBLKS_UUID | BLKID_SUBLKS_TYPE | BLKID_SUBLKS_USAGE) != 0 ||
        blkid_probe_enable_partitions(probe, 1) != 0 ||
        blkid_probe_set_partitions_flags(probe, 0) != 0 ||
        blkid_probe_enable_topology(probe, 0) != 0) {
        blkid_free_probe(probe);
        return fail();
    }
    /* Do not filter signatures by type/usage: colliding RAID/filesystem
     * signatures must not disappear just because ext is our first profile. */
    int result = blkid_do_safeprobe(probe);
    if (fstat(STDIN_FILENO, &after) != 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_rdev != after.st_rdev ||
        before.st_size != after.st_size || before.st_mode != after.st_mode ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        blkid_free_probe(probe);
        return fail();
    }
    const char *status = "unidentified", *filesystem = "";
    char uuid[37] = "";
    if (result == -2) {
        status = "ambiguous";
    } else if (result == 0) {
        const char *partition = NULL;
        size_t length = 0;
        status = "other-signature";
        if (blkid_probe_lookup_value(probe, "PTTYPE", &partition, &length) != 0 &&
            token_is(probe, "USAGE", "filesystem")) {
            if (token_is(probe, "TYPE", "ext2")) filesystem = "ext2";
            if (token_is(probe, "TYPE", "ext3")) filesystem = "ext3";
            if (token_is(probe, "TYPE", "ext4")) filesystem = "ext4";
            if (*filesystem) {
                status = "ext-metadata";
                if (read_uuid(probe, uuid) != 0) {
                    status = "unusable-signature";
                    filesystem = "";
                    uuid[0] = '\0';
                }
            }
        }
    } else if (result != 1) {
        blkid_free_probe(probe);
        return fail();
    }
    blkid_free_probe(probe);
    return emit(status, kind, filesystem, uuid);
}
