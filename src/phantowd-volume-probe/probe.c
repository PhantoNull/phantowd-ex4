/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#define _GNU_SOURCE
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include <blkid/blkid.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include "partition_table.h"
#include <linux/fs.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
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
                const char *uuid, const phantowd_partition_table_t *table)
{
    /* Table/partition values are validated by the strict table reader. No
     * labels, serials, paths or arbitrary library tokens are emitted. */
    int written = printf("{\"schema_version\":2,\"status\":\"%s\","
                         "\"source_kind\":\"%s\",\"filesystem\":\"%s\","
                         "\"filesystem_uuid\":\"%s\",\"partition_table\":\"%s\","
                         "\"partition_table_id\":\"%s\",\"partitions\":[",
                         status, kind, filesystem, uuid,
                         table->scheme, table->id);
    if (written < 0)
        return 1;
    for (size_t i = 0; i < table->count; ++i) {
        const phantowd_partition_t *part = &table->partitions[i];
        if (printf("%s{\"number\":%u,\"start_512b_sectors\":%llu,"
                   "\"size_512b_sectors\":%llu,\"uuid\":\"%s\","
                   "\"type_id\":\"%s\",\"extended\":%s}",
                   i ? "," : "", part->number,
                   (unsigned long long)part->start_512b_sectors,
                   (unsigned long long)part->size_512b_sectors,
                   part->uuid, part->type_id, part->extended ? "true" : "false") < 0)
            return 1;
    }
    return printf("],\"mount_performed\":false,\"compatibility_qualified\":false,"
                  "\"activation_allowed\":false}\n") < 0 || fflush(stdout) == EOF ? 1 : 0;
}

static int protective_gpt_mbr_state(int fd, uint64_t disk_bytes, uint32_t sector_size)
{
    unsigned char mbr[512];
    if (sector_size < 512 || disk_bytes < sizeof(mbr) || disk_bytes % sector_size != 0)
        return -1;
    size_t read_bytes = 0;
    while (read_bytes < sizeof(mbr)) {
        ssize_t count = pread(fd, mbr + read_bytes, sizeof(mbr) - read_bytes, (off_t)read_bytes);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        read_bytes += (size_t)count;
    }
    if (mbr[510] != 0x55 || mbr[511] != 0xaa)
        return 0;

    uint64_t last_lba = disk_bytes / sector_size - 1;
    unsigned int protective_count = 0;
    for (unsigned int i = 0; i < 4; ++i) {
        const unsigned char *entry = mbr + 446 + i * 16;
        uint8_t type = entry[4];
        uint32_t start = (uint32_t)entry[8] | ((uint32_t)entry[9] << 8) |
            ((uint32_t)entry[10] << 16) | ((uint32_t)entry[11] << 24);
        uint32_t size = (uint32_t)entry[12] | ((uint32_t)entry[13] << 8) |
            ((uint32_t)entry[14] << 16) | ((uint32_t)entry[15] << 24);
        if (type == 0) {
            for (unsigned int j = 0; j < 16; ++j) {
                if (entry[j] != 0)
                    return 0;
            }
            continue;
        }
        if (type != 0xee || entry[0] != 0 || start != 1 || size == 0 ||
            size != (last_lba > UINT32_MAX ? UINT32_MAX : (uint32_t)last_lba))
            return 0;
        ++protective_count;
    }
    return protective_count == 1 ? 1 : 0;
}

static int descriptor_unchanged(int fd, const struct stat *before)
{
    struct stat after;
    return fstat(fd, &after) == 0 && before->st_dev == after.st_dev &&
        before->st_ino == after.st_ino && before->st_rdev == after.st_rdev &&
        before->st_size == after.st_size && before->st_mode == after.st_mode &&
        before->st_mtim.tv_sec == after.st_mtim.tv_sec && before->st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before->st_ctim.tv_sec == after.st_ctim.tv_sec && before->st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

static int observe_gpt_only(int fd, const struct stat *before, const char *kind)
{
    uint64_t disk_bytes = 0;
    uint32_t sector_size = 512;
    if (S_ISBLK(before->st_mode)) {
        unsigned int logical_sector_size = 0;
        if (ioctl(fd, BLKGETSIZE64, &disk_bytes) != 0 ||
            ioctl(fd, BLKSSZGET, &logical_sector_size) != 0)
            return fail();
        sector_size = logical_sector_size;
    } else if (S_ISREG(before->st_mode) && before->st_size > 0) {
        disk_bytes = (uint64_t)before->st_size;
    } else {
        return fail();
    }

    phantowd_partition_table_t table = {0};
    int mbr_state = protective_gpt_mbr_state(fd, disk_bytes, sector_size);
    if (mbr_state < 0)
        return fail();
    if (mbr_state == 0) {
        if (!descriptor_unchanged(fd, before))
            return fail();
        return emit("unsupported-table", kind, "", "", &table);
    }
    if (phantowd_partition_table_read(fd, disk_bytes, sector_size, "gpt", &table) != 0)
        return fail();
    if (!descriptor_unchanged(fd, before))
        return fail();
    return emit("other-signature", kind, "", "", &table);
}

int main(int argc, char **argv)
{
    struct stat before, after;
    struct rlimit memory = {64U * 1024U * 1024U, 64U * 1024U * 1024U};
    struct rlimit cpu = {2, 2}, core = {0, 0};
    int flags = fcntl(STDIN_FILENO, F_GETFL);
    int gpt_only = argc == 2 && strcmp(argv[1], "--gpt-only") == 0;
    if ((!gpt_only && argc != 1) || flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
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
    if (gpt_only)
        return observe_gpt_only(STDIN_FILENO, &before, kind);
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
    const char *status = "unidentified", *filesystem = "";
    phantowd_partition_table_t table = {0};
    char uuid[37] = "";
    if (result == -2) {
        status = "ambiguous";
    } else if (result == 0) {
        status = "other-signature";
        if (token_is(probe, "PTTYPE", "gpt") || token_is(probe, "PTTYPE", "dos")) {
            const char *scheme = token_is(probe, "PTTYPE", "gpt") ? "gpt" : "dos";
            blkid_loff_t size = blkid_probe_get_size(probe);
            unsigned long sector_size = blkid_probe_get_sectorsize(probe);
            if (size <= 0 || sector_size > UINT32_MAX ||
                phantowd_partition_table_read(STDIN_FILENO, (uint64_t)size,
                                              (uint32_t)sector_size, scheme, &table) != 0) {
                blkid_free_probe(probe);
                return fail();
            }
        } else if (token_is(probe, "USAGE", "filesystem")) {
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
    if (fstat(STDIN_FILENO, &after) != 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_rdev != after.st_rdev ||
        before.st_size != after.st_size || before.st_mode != after.st_mode ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        blkid_free_probe(probe);
        return fail();
    }
    blkid_free_probe(probe);
    return emit(status, kind, filesystem, uuid, &table);
}
