/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#define _GNU_SOURCE
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include "partition_table.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define GPT_HEADER_MIN_SIZE 92U
#define GPT_ENTRY_SIZE 128U
#define GPT_MAX_ENTRY_SLOTS 4096U
#define DOS_MAX_EBR 256U

typedef struct {
    uint32_t revision;
    uint32_t header_size;
    uint64_t first_usable;
    uint64_t last_usable;
    unsigned char disk_guid[16];
    uint64_t entries_lba;
    uint32_t entry_count;
    uint32_t entry_size;
    uint32_t entries_crc;
    unsigned char *entries;
    size_t entries_bytes;
    uint64_t entries_sectors;
} gpt_copy_t;

typedef struct {
    uint8_t boot;
    uint8_t type;
    uint32_t start;
    uint32_t size;
} mbr_entry_t;

static uint32_t get_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get_le64(const unsigned char *p)
{
    return (uint64_t)get_le32(p) | ((uint64_t)get_le32(p + 4) << 32);
}

static uint32_t crc32_ieee(const unsigned char *data, size_t length)
{
    uint32_t crc = UINT32_C(0xffffffff);
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (unsigned int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (uint32_t)-(int32_t)(crc & 1U));
    }
    return crc ^ UINT32_C(0xffffffff);
}

static int read_exact(int fd, uint64_t disk_bytes, uint64_t offset,
                      void *buffer, size_t length)
{
    size_t done = 0;
    if (offset > disk_bytes || (uint64_t)length > disk_bytes - offset ||
        offset > (uint64_t)INT64_MAX || (uint64_t)length > (uint64_t)INT64_MAX - offset)
        return -1;
    while (done < length) {
        ssize_t got = pread(fd, (unsigned char *)buffer + done, length - done,
                            (off_t)(offset + (uint64_t)done));
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return -1;
        done += (size_t)got;
    }
    return 0;
}

static int lba_offset(uint64_t lba, uint32_t sector_size, uint64_t *offset)
{
    if (lba > UINT64_MAX / sector_size)
        return -1;
    *offset = lba * sector_size;
    return 0;
}

static int multiply_u64(uint64_t left, uint64_t right, uint64_t *product)
{
    if (right && left > UINT64_MAX / right)
        return -1;
    *product = left * right;
    return 0;
}

static int uuid_is_zero(const unsigned char *uuid, size_t length)
{
    unsigned char combined = 0;
    for (size_t i = 0; i < length; ++i)
        combined |= uuid[i];
    return combined == 0;
}

static int entry_is_empty(const unsigned char *raw);

static int format_gpt_guid(const unsigned char raw[16], char out[37])
{
    int written;
    if (uuid_is_zero(raw, 16))
        return -1;
    written = snprintf(out, 37,
                       "%08" PRIx32 "-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                       get_le32(raw), (unsigned int)raw[4] | ((unsigned int)raw[5] << 8),
                       (unsigned int)raw[6] | ((unsigned int)raw[7] << 8),
                       raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
    return written == 36 ? 0 : -1;
}

static int format_dos_uuid(const char disk_id[9], uint32_t number, char out[37])
{
    int written = snprintf(out, 37, "%s-%02" PRIx32, disk_id, number);
    return written > 0 && written < 37 ? 0 : -1;
}

static int ranges_overlap(uint64_t first_start, uint64_t first_end,
                          uint64_t second_start, uint64_t second_end)
{
    return first_start < second_end && second_start < first_end;
}

static int add_partition(phantowd_partition_table_t *result, uint32_t number,
                         uint64_t start, uint64_t size, const char *uuid,
                         const char *type_id, int extended)
{
    if (result->count >= PHANTOWD_PT_MAX_PARTITIONS || number == 0 || size == 0 ||
        start > UINT64_MAX - size ||
        !uuid || !*uuid || !type_id || !*type_id)
        return -1;
    for (size_t i = 0; i < result->count; ++i) {
        const phantowd_partition_t *existing = &result->partitions[i];
        if (existing->number == number || strcmp(existing->uuid, uuid) == 0)
            return -1;
        if (!extended && !existing->extended &&
            ranges_overlap(start, start + size,
                           existing->start_512b_sectors,
                           existing->start_512b_sectors + existing->size_512b_sectors))
            return -1;
    }
    phantowd_partition_t *part = &result->partitions[result->count++];
    part->number = number;
    part->start_512b_sectors = start;
    part->size_512b_sectors = size;
    part->extended = extended;
    if (snprintf(part->uuid, sizeof(part->uuid), "%s", uuid) < 0 ||
        snprintf(part->type_id, sizeof(part->type_id), "%s", type_id) < 0)
        return -1;
    return 0;
}

static void free_gpt_copy(gpt_copy_t *copy)
{
    free(copy->entries);
    memset(copy, 0, sizeof(*copy));
}

static int read_gpt_copy(int fd, uint64_t disk_bytes, uint32_t sector_size,
                         uint64_t disk_lbas, uint64_t header_lba,
                         uint64_t expected_alternate,
                         gpt_copy_t *copy)
{
    unsigned char sector[4096], crc_sector[4096];
    unsigned char signature[8] = {'E','F','I',' ','P','A','R','T'};
    uint64_t offset, entries_bytes64, entries_end, entries_sectors;
    uint32_t stored_header_crc;

    memset(copy, 0, sizeof(*copy));
    if (sector_size > sizeof(sector) || lba_offset(header_lba, sector_size, &offset) != 0 ||
        read_exact(fd, disk_bytes, offset, sector, sector_size) != 0 ||
        memcmp(sector, signature, sizeof(signature)) != 0)
        return -1;

    copy->revision = get_le32(sector + 8);
    copy->header_size = get_le32(sector + 12);
    stored_header_crc = get_le32(sector + 16);
    if (copy->revision != UINT32_C(0x00010000) ||
        copy->header_size < GPT_HEADER_MIN_SIZE || copy->header_size > sector_size ||
        get_le32(sector + 20) != 0 || get_le64(sector + 24) != header_lba ||
        get_le64(sector + 32) != expected_alternate)
        return -1;

    memcpy(crc_sector, sector, copy->header_size);
    memset(crc_sector + 16, 0, 4);
    if (crc32_ieee(crc_sector, copy->header_size) != stored_header_crc)
        return -1;

    copy->first_usable = get_le64(sector + 40);
    copy->last_usable = get_le64(sector + 48);
    memcpy(copy->disk_guid, sector + 56, sizeof(copy->disk_guid));
    copy->entries_lba = get_le64(sector + 72);
    copy->entry_count = get_le32(sector + 80);
    copy->entry_size = get_le32(sector + 84);
    copy->entries_crc = get_le32(sector + 88);
    if (uuid_is_zero(copy->disk_guid, sizeof(copy->disk_guid)) ||
        copy->first_usable < 2 || copy->first_usable > copy->last_usable ||
        copy->last_usable >= disk_lbas - 1 ||
        (header_lba >= copy->first_usable && header_lba <= copy->last_usable) ||
        copy->entry_count == 0 || copy->entry_count > GPT_MAX_ENTRY_SLOTS ||
        copy->entry_size != GPT_ENTRY_SIZE)
        return -1;

    entries_bytes64 = (uint64_t)copy->entry_count * copy->entry_size;
    if (entries_bytes64 == 0 || entries_bytes64 > SIZE_MAX ||
        entries_bytes64 > UINT32_C(524288))
        return -1;
    copy->entries_bytes = (size_t)entries_bytes64;
    entries_sectors = (entries_bytes64 + sector_size - 1) / sector_size;
    if (entries_sectors == 0 || copy->entries_lba >= disk_lbas ||
        entries_sectors > disk_lbas - copy->entries_lba)
        return -1;
    entries_end = copy->entries_lba + entries_sectors;
    if (header_lba == 1) {
        if (copy->entries_lba < 2 || entries_end > copy->first_usable)
            return -1;
    } else {
        if (copy->entries_lba <= copy->last_usable || entries_end > header_lba)
            return -1;
    }
    copy->entries_sectors = entries_sectors;
    copy->entries = malloc(copy->entries_bytes);
    if (!copy->entries)
        return -1;
    if (lba_offset(copy->entries_lba, sector_size, &offset) != 0 ||
        read_exact(fd, disk_bytes, offset, copy->entries, copy->entries_bytes) != 0 ||
        crc32_ieee(copy->entries, copy->entries_bytes) != copy->entries_crc) {
        free_gpt_copy(copy);
        return -1;
    }
    return 0;
}

static int parse_gpt(int fd, uint64_t disk_bytes, uint32_t sector_size,
                     phantowd_partition_table_t *result)
{
    unsigned char mbr[512];
    uint64_t disk_lbas, last_lba, multiplier;
    gpt_copy_t primary = {0}, backup = {0};
    int ok = -1;

    if (sector_size < 512 || sector_size > 4096 || sector_size % 512 != 0 ||
        disk_bytes % sector_size != 0)
        return -1;
    disk_lbas = disk_bytes / sector_size;
    if (disk_lbas < 68)
        return -1;
    last_lba = disk_lbas - 1;
    if (read_exact(fd, disk_bytes, 0, mbr, sizeof(mbr)) != 0 ||
        mbr[510] != 0x55 || mbr[511] != 0xaa)
        return -1;

    /* A hybrid MBR is ambiguous; accept only one protective entry. */
    unsigned int protective_count = 0;
    for (unsigned int i = 0; i < 4; ++i) {
        const unsigned char *entry = mbr + 446 + i * 16;
        uint8_t type = entry[4];
        uint32_t start = get_le32(entry + 8), size = get_le32(entry + 12);
        if (type == 0) {
            if (!entry_is_empty(entry))
                return -1;
            continue;
        }
        if (type != 0xee || entry[0] != 0 || start != 1 || size == 0 ||
            size != (last_lba > UINT32_MAX ? UINT32_MAX : (uint32_t)last_lba))
            return -1;
        ++protective_count;
    }
    if (protective_count != 1)
        return -1;

    if (read_gpt_copy(fd, disk_bytes, sector_size, disk_lbas, 1, last_lba,
                      &primary) != 0 ||
        read_gpt_copy(fd, disk_bytes, sector_size, disk_lbas, last_lba, 1,
                      &backup) != 0)
        goto done;
    if (primary.first_usable != backup.first_usable ||
        primary.last_usable != backup.last_usable ||
        primary.header_size != backup.header_size || primary.revision != backup.revision ||
        primary.entry_count != backup.entry_count || primary.entry_size != backup.entry_size ||
        primary.entries_crc != backup.entries_crc ||
        memcmp(primary.disk_guid, backup.disk_guid, sizeof(primary.disk_guid)) != 0 ||
        primary.entries_bytes != backup.entries_bytes ||
        memcmp(primary.entries, backup.entries, primary.entries_bytes) != 0 ||
        ranges_overlap(primary.entries_lba, primary.entries_lba + primary.entries_sectors,
                       backup.entries_lba, backup.entries_lba + backup.entries_sectors))
        goto done;

    multiplier = sector_size / 512;
    if (format_gpt_guid(primary.disk_guid, result->id) != 0)
        goto done;
    for (uint32_t i = 0; i < primary.entry_count; ++i) {
        const unsigned char *entry = primary.entries + (size_t)i * primary.entry_size;
        const unsigned char *type_guid = entry;
        const unsigned char *part_guid = entry + 16;
        uint64_t first = get_le64(entry + 32), last = get_le64(entry + 40);
        uint64_t size, start_512, size_512;
        char uuid[37], type_id[37];
        if (uuid_is_zero(type_guid, 16)) {
            if (!uuid_is_zero(entry, primary.entry_size))
                goto done;
            continue;
        }
        if (uuid_is_zero(part_guid, 16) || last < first ||
            first < primary.first_usable || last > primary.last_usable)
            goto done;
        size = last - first + 1;
        if (size == 0 || multiply_u64(first, multiplier, &start_512) != 0 ||
            multiply_u64(size, multiplier, &size_512) != 0 ||
            format_gpt_guid(part_guid, uuid) != 0 ||
            format_gpt_guid(type_guid, type_id) != 0 ||
            add_partition(result, i + 1, start_512, size_512, uuid, type_id, 0) != 0)
            goto done;
    }
    memcpy(result->scheme, "gpt", 4);
    ok = 0;
done:
    free_gpt_copy(&primary);
    free_gpt_copy(&backup);
    return ok;
}

static int entry_is_empty(const unsigned char *raw)
{
    unsigned char combined = 0;
    for (size_t i = 0; i < 16; ++i)
        combined |= raw[i];
    return combined == 0;
}

static int valid_boot_indicator(uint8_t boot)
{
    return boot == 0 || boot == 0x80;
}

static int is_extended_type(uint8_t type)
{
    return type == 0x05 || type == 0x0f || type == 0x85;
}

static mbr_entry_t decode_mbr_entry(const unsigned char *raw)
{
    mbr_entry_t entry;
    entry.boot = raw[0];
    entry.type = raw[4];
    entry.start = get_le32(raw + 8);
    entry.size = get_le32(raw + 12);
    return entry;
}

static int add_dos_partition(phantowd_partition_table_t *result,
                             const char disk_id[9], uint32_t number,
                             const mbr_entry_t *entry, uint64_t start_lba,
                             uint64_t multiplier, int extended)
{
    uint64_t start_512, size_512;
    char uuid[37], type_id[37];
    if (multiply_u64(start_lba, multiplier, &start_512) != 0 ||
        multiply_u64(entry->size, multiplier, &size_512) != 0 ||
        format_dos_uuid(disk_id, number, uuid) != 0 ||
        snprintf(type_id, sizeof(type_id), "0x%02x", entry->type) <= 0)
        return -1;
    return add_partition(result, number, start_512, size_512, uuid, type_id, extended);
}

static int parse_dos(int fd, uint64_t disk_bytes, uint32_t sector_size,
                     phantowd_partition_table_t *result)
{
    unsigned char sector[4096];
    uint64_t disk_lbas, multiplier, extended_start = 0, extended_end = 0;
    uint64_t visited[DOS_MAX_EBR];
    size_t visited_count = 0;
    char disk_id[9];
    int has_extended = 0, terminated = 0;
    if (sector_size < 512 || sector_size > sizeof(sector) || sector_size % 512 != 0 ||
        disk_bytes % sector_size != 0 ||
        (disk_lbas = disk_bytes / sector_size) == 0 ||
        read_exact(fd, disk_bytes, 0, sector, sector_size) != 0 ||
        sector[510] != 0x55 || sector[511] != 0xaa)
        return -1;

    uint32_t raw_id = get_le32(sector + 440);
    if (raw_id == 0)
        return -1;
    if (snprintf(disk_id, sizeof(disk_id), "%08" PRIx32, raw_id) != 8)
        return -1;
    multiplier = sector_size / 512;

    for (uint32_t i = 0; i < 4; ++i) {
        const unsigned char *raw = sector + 446 + i * 16;
        mbr_entry_t entry = decode_mbr_entry(raw);
        uint64_t end;
        if (entry_is_empty(raw))
            continue;
        if (!valid_boot_indicator(entry.boot) || entry.type == 0 || entry.start == 0 ||
            entry.size == 0 || entry.type == 0xee)
            return -1;
        end = (uint64_t)entry.start + entry.size;
        if (end > disk_lbas)
            return -1;
        if (is_extended_type(entry.type)) {
            if (has_extended)
                return -1;
            extended_start = entry.start;
            extended_end = end;
            has_extended = 1;
        }
        if (add_dos_partition(result, disk_id, i + 1, &entry, entry.start,
                              multiplier, is_extended_type(entry.type)) != 0)
            return -1;
    }

    if (has_extended) {
        for (size_t i = 0; i < result->count; ++i) {
            const phantowd_partition_t *part = &result->partitions[i];
            if (part->extended)
                continue;
            uint64_t start = part->start_512b_sectors / multiplier;
            uint64_t size = part->size_512b_sectors / multiplier;
            if (ranges_overlap(start, start + size, extended_start, extended_end))
                return -1;
        }
        uint64_t current = extended_start;
        uint32_t logical_number = 5;
        for (size_t hop = 0; hop < DOS_MAX_EBR; ++hop) {
            unsigned char ebr[4096];
            uint64_t offset;
            if (current < extended_start || current >= extended_end ||
                current >= disk_lbas || visited_count >= DOS_MAX_EBR)
                return -1;
            for (size_t i = 0; i < visited_count; ++i)
                if (visited[i] == current)
                    return -1;
            for (size_t i = 0; i < result->count; ++i) {
                const phantowd_partition_t *part = &result->partitions[i];
                if (part->extended)
                    continue;
                uint64_t part_start = part->start_512b_sectors / multiplier;
                uint64_t part_size = part->size_512b_sectors / multiplier;
                if (current >= part_start && current < part_start + part_size)
                    return -1;
            }
            visited[visited_count++] = current;
            if (lba_offset(current, sector_size, &offset) != 0 ||
                read_exact(fd, disk_bytes, offset, ebr, sector_size) != 0 ||
                ebr[510] != 0x55 || ebr[511] != 0xaa)
                return -1;
            const unsigned char *data_raw = ebr + 446;
            const unsigned char *link_raw = ebr + 462;
            if (!entry_is_empty(ebr + 478) || !entry_is_empty(ebr + 494))
                return -1;
            mbr_entry_t data = decode_mbr_entry(data_raw);
            mbr_entry_t link = decode_mbr_entry(link_raw);
            if (entry_is_empty(data_raw) || !valid_boot_indicator(data.boot) ||
                data.type == 0 || is_extended_type(data.type) || data.type == 0xee ||
                data.start == 0 || data.size == 0 ||
                (uint64_t)current > UINT64_MAX - data.start)
                return -1;
            uint64_t data_start = current + data.start;
            uint64_t data_end = data_start + data.size;
            if (data_end < data_start || data_start < extended_start || data_end > extended_end ||
                add_dos_partition(result, disk_id, logical_number, &data, data_start,
                                  multiplier, 0) != 0)
                return -1;
            if (logical_number == UINT32_MAX)
                return -1;
            ++logical_number;
            if (entry_is_empty(link_raw)) {
                terminated = 1;
                break;
            }
            if (!valid_boot_indicator(link.boot) || !is_extended_type(link.type) ||
                link.start == 0 || link.size == 0 ||
                (uint64_t)extended_start > UINT64_MAX - link.start)
                return -1;
            uint64_t next = extended_start + link.start;
            uint64_t link_end = next + link.size;
            if (link_end < next || next >= extended_end || link_end > extended_end ||
                next == current)
                return -1;
            current = next;
        }
        if (!terminated)
            return -1;
    }

    memcpy(result->scheme, "dos", 4);
    memcpy(result->id, disk_id, sizeof(disk_id));
    return 0;
}

int phantowd_partition_table_read(int fd, uint64_t disk_bytes,
                                  uint32_t sector_size, const char *scheme,
                                  phantowd_partition_table_t *result)
{
    if (fd < 0 || disk_bytes == 0 || !scheme || !result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (strcmp(scheme, "gpt") == 0)
        return parse_gpt(fd, disk_bytes, sector_size, result);
    if (strcmp(scheme, "dos") == 0)
        return parse_dos(fd, disk_bytes, sector_size, result);
    return -1;
}
