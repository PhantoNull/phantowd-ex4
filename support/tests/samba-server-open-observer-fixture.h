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

/* Private test-only framing, not an authenticated producer/channel contract.
 * Eight magic bytes, LE version/payload length, LE sequence (1 or 2), followed
 * by seven LE64 and four LE32 values. Never memcpy native struct padding. */
static inline void phantowd_qemu_server_open_put_le(unsigned char *output,
    uint64_t value, unsigned width)
{
    for (unsigned index = 0; index < width; ++index)
        output[index] = (unsigned char)(value >> (index * 8));
}

static inline int phantowd_qemu_encode_server_open_v1(unsigned char *output,
    const struct phantowd_server_open_observation_v1 *input, uint32_t sequence)
{
    if (!output) return -1;
    for (unsigned index = 0; index < 88; ++index) output[index] = 0;
    if (!input || (sequence != 1 && sequence != 2)) return -1;
    const unsigned char magic[8] = {'P', 'W', 'D', 'O', 'P', 'E', 'N', 0};
    for (unsigned index = 0; index < 8; ++index) output[index] = magic[index];
    phantowd_qemu_server_open_put_le(output + 8, 1, 2);
    phantowd_qemu_server_open_put_le(output + 10, 72, 2);
    phantowd_qemu_server_open_put_le(output + 12, sequence, 4);
    const uint64_t wide[7] = {input->session_id, input->persistent_id,
        input->volatile_id, input->share_file_id, input->device, input->inode,
        input->worker_unique_id};
    const uint32_t narrow[4] = {input->tree_id, input->worker_pid,
        input->worker_task_id, input->worker_vnn};
    for (unsigned index = 0; index < 7; ++index)
        phantowd_qemu_server_open_put_le(output + 16 + index * 8, wide[index], 8);
    for (unsigned index = 0; index < 4; ++index)
        phantowd_qemu_server_open_put_le(output + 72 + index * 4, narrow[index], 4);
    return 0;
}
#endif
