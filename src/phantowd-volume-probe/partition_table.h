/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#ifndef PHANTOWD_PARTITION_TABLE_H
#define PHANTOWD_PARTITION_TABLE_H

#include <stddef.h>
#include <stdint.h>

#define PHANTOWD_PT_MAX_PARTITIONS 256U

typedef struct {
    uint32_t number;
    uint64_t start_512b_sectors;
    uint64_t size_512b_sectors;
    char uuid[37];
    char type_id[37];
    int extended;
} phantowd_partition_t;

typedef struct {
    char scheme[5];
    char id[37];
    size_t count;
    phantowd_partition_t partitions[PHANTOWD_PT_MAX_PARTITIONS];
} phantowd_partition_table_t;

/* Return zero only for a complete, supported, internally consistent table. */
int phantowd_partition_table_read(int fd, uint64_t disk_bytes,
                                  uint32_t sector_size, const char *scheme,
                                  phantowd_partition_table_t *result);

#endif
