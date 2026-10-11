/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* This original adapter is compiled WITH the exact pinned GPL-3.0-or-later
 * Samba translation unit below. The combined artifact retains upstream GPL
 * terms/notices; it is not an Apache relicensing of Samba or a product library.
 * Never install it or replace the cached/installed libsmbclient. */
#ifndef PHANTOWD_SAMBA_SOURCE_OBSERVER_FIXTURE
#error "Only the dedicated pinned-source fixture may compile this adapter"
#endif

/* Use the actual definition and static mapping in the SAME translation unit.
 * No copied structure, guessed offset, dlsym of a private function or process
 * memory inspection. The test linker discards unrelated hidden Samba code. */
#include "source3/libsmb/cli_smb2_fnum.c"
#include "libsmb_internal.h"
#include "samba-pending-handle-observer-fixture.h"

__attribute__((visibility("default")))
int phantowd_qemu_observe_smb_handle_v1(SMBCCTX *context, SMBCFILE *file,
    struct phantowd_pending_handle_observation_v1 *output)
{
    if (!output) return -1;
    memset(output, 0, sizeof(*output));
    /* This fixed client has one opening only. Membership precedes any file
     * dereference; an arbitrary handle, extra opening or directory refuses. */
    if (!context || !context->internal || !context->internal->initialized ||
        !file || context->internal->files != file || file->next || file->prev ||
        !file->file || file->dir_list || file->dirplus_list || file->offset != 0 ||
        file->cli_fd <= 0 || file->cli_fd > 0xfffe || !file->targetcli) return -1;
    struct cli_state *cli = file->targetcli; /* Never cached srv->cli (DFS). */
    if (!cli->conn || !cli->smb2.session || !cli->smb2.tcon ||
        smbXcli_conn_protocol(cli->conn) != PROTOCOL_SMB3_11 ||
        !smbXcli_conn_is_connected(cli->conn)) return -1;
    struct smb2_hnd *handle = NULL;
    NTSTATUS status = map_fnum_to_smb2_handle(cli, (uint16_t)file->cli_fd, &handle);
    if (!NT_STATUS_IS_OK(status) || !handle || handle->posix) return -1;
    struct phantowd_pending_handle_observation_v1 observed = {
        .session_id = smb2cli_session_current_id(cli->smb2.session),
        .tree_id = smb2cli_tcon_current_id(cli->smb2.tcon),
        .persistent_id = handle->fid_persistent,
        .volatile_id = handle->fid_volatile,
    };
    if (!observed.session_id || observed.session_id == UINT64_MAX ||
        !observed.tree_id || observed.tree_id == UINT32_MAX ||
        !observed.persistent_id || observed.persistent_id == UINT64_MAX ||
        !observed.volatile_id || observed.volatile_id == UINT64_MAX) return -1;
    /* All getters are local reads in the pinned source; no new wire request,
     * map allocation/removal, close, reconnect or authentication is attempted.
     * This copied tuple is point-in-time, NOT a lifetime or server-side lease. */
    *output = observed;
    return 0;
}
