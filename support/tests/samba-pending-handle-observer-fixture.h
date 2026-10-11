/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#ifndef PHANTOWD_PENDING_HANDLE_OBSERVER_FIXTURE_H
#define PHANTOWD_PENDING_HANDLE_OBSERVER_FIXTURE_H

/* Internal disposable fixture ABI, never product authority or a Samba API.
 * The caller is serialized and owns the original context/file throughout.
 * No pointers, credentials, keys, paths or server-local generation IDs leave.
 * The caller must independently bind these copied observations to the server
 * and retained process/TCP witnesses. Success alone never authorizes WRITE. */
#include <stdint.h>
#include <sys/time.h>
#include <libsmbclient.h>

struct phantowd_pending_handle_observation_v1 {
    uint64_t session_id;
    uint64_t persistent_id;
    uint64_t volatile_id;
    uint32_t tree_id;
};

int phantowd_qemu_observe_smb_handle_v1(SMBCCTX *context, SMBCFILE *file,
    struct phantowd_pending_handle_observation_v1 *output);

#endif
