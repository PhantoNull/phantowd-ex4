/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#ifndef PHANTOWD_SERVER_OPEN_OBSERVER_FIXTURE_H
#define PHANTOWD_SERVER_OPEN_OBSERVER_FIXTURE_H
#include <stdint.h>

/* Copied local metadata only. Not a lease, execution token or WRITE authority.
 * Raw IDs stay private to a future containing QEMU-only composition. */
struct phantowd_server_open_observation_v1 {
    uint64_t session_id, persistent_id, volatile_id, share_file_id;
    uint64_t device, inode, worker_unique_id;
    uint32_t tree_id, worker_pid, worker_task_id, worker_vnn;
};
_Static_assert(sizeof(struct phantowd_server_open_observation_v1) == 72,
    "Fixed copied observation ABI");

struct connection_struct;
struct files_struct;
int phantowd_qemu_observe_server_open_v1(const struct connection_struct *,
    const struct files_struct *, struct phantowd_server_open_observation_v1 *);
#endif
