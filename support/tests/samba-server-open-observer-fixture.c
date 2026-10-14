/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Built against actual pinned GPL Samba definitions; the combined artifact
 * retains upstream terms. Never install into the product or replace Samba. */
#ifndef PHANTOWD_SAMBA_SERVER_OBSERVER_FIXTURE
#error "Dedicated pinned-source fixture only"
#endif
#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "librpc/gen_ndr/smbXsrv.h"
#include "samba-server-open-observer-fixture.h"

__attribute__((visibility("default")))
int phantowd_qemu_observe_server_open_v1(const connection_struct *connection,
    const files_struct *file, struct phantowd_server_open_observation_v1 *output)
{
    if (!output) return -1;
    memset(output, 0, sizeof(*output));
    if (!connection || !connection->sconn || !file || !connection->tcon ||
        !connection->tcon->global || connection->tcon->compat != connection ||
        !NT_STATUS_IS_OK(connection->tcon->status)) return -1;

    /* Validate membership before dereferencing the supplied file. This bounded
     * complete internal list is not an external inventory or lifetime lease. */
    size_t count = 0, found = 0;
    const files_struct *entry;
    for (entry = connection->sconn->files; entry; entry = entry->next) {
        if (++count > 128) return -1;
        if (entry == file) found++;
    }
    /* FSA distinguishes completed backend data opens from internal/pre-FSA
     * structures. It is NOT proof that the SMB CREATE response succeeded. */
    if (!count || count != connection->sconn->num_files || found != 1 ||
        file->conn != connection || !file->fh || fh_get_refcount(file->fh) != 1 ||
        !file->fsp_flags.is_fsa || file->fsp_flags.is_pathref || file->fsp_flags.is_directory ||
        file->fsp_flags.is_dirfsp || file->fsp_flags.closing ||
        file->fsp_flags.modified || file->fsp_flags.posix_open ||
        file->fsp_flags.delete_on_close || file->fsp_flags.initial_delete_on_close ||
        file->base_fsp || !file->op || file->op->compat != file ||
        !file->op->global || !NT_STATUS_IS_OK(file->op->status)) return -1;

    const struct smbXsrv_open_global0 *open = file->op->global;
    const struct smbXsrv_tcon_global0 *tree = connection->tcon->global;
    uint64_t generation = fh_get_gen_id(file->fh);
    if (!file->vuid || file->vuid == UINT64_MAX ||
        file->vuid != tree->session_global_id || !tree->tcon_wire_id ||
        tree->tcon_wire_id == UINT32_MAX || connection->cnum != tree->tcon_wire_id ||
        connection->tcon->local_id != tree->tcon_wire_id ||
        !open->open_persistent_id || open->open_persistent_id == UINT64_MAX ||
        open->open_persistent_id != open->open_global_id ||
        !open->open_volatile_id || open->open_volatile_id == UINT64_MAX ||
        open->open_volatile_id != file->op->local_id ||
        file->fnum != open->open_volatile_id || !generation ||
        generation == UINT64_MAX || open->durable || open->disconnect_time ||
        open->server_id.pid <= 1 || open->server_id.pid != getpid() ||
        open->server_id.task_id != 0 || open->server_id.vnn != UINT32_MAX ||
        !open->server_id.unique_id || open->server_id.unique_id == UINT64_MAX ||
        tree->server_id.pid != open->server_id.pid ||
        tree->server_id.task_id != open->server_id.task_id ||
        tree->server_id.vnn != open->server_id.vnn ||
        tree->server_id.unique_id != open->server_id.unique_id) return -1;

    /* This upstream accessor simply reads the existing fd. The pathref flag
     * was refused above; no pathname open, VFS operation or wire request. */
    int fd = fsp_get_pathref_fd(file);
    struct stat actual;
    if (fd < 0 || fstat(fd, &actual) || !S_ISREG(actual.st_mode) ||
        actual.st_nlink != 1 || actual.st_size <= 0 || !actual.st_dev ||
        !actual.st_ino || file->file_id.extid != 0 ||
        file->file_id.devid != (uint64_t)actual.st_dev ||
        file->file_id.inode != (uint64_t)actual.st_ino) return -1;

    *output = (struct phantowd_server_open_observation_v1){
        .session_id = file->vuid, .tree_id = tree->tcon_wire_id,
        .persistent_id = open->open_persistent_id,
        .volatile_id = open->open_volatile_id, .share_file_id = generation,
        .device = actual.st_dev, .inode = actual.st_ino,
        .worker_pid = open->server_id.pid,
        .worker_task_id = open->server_id.task_id,
        .worker_vnn = open->server_id.vnn,
        .worker_unique_id = open->server_id.unique_id,
    };
    return 0;
}
