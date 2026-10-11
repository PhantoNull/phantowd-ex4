/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* S1 loader prerequisite only. Admission intentionally remains unavailable. */
#ifndef PHANTOWD_SAMBA_SERVER_VFS_FIXTURE
#error "Fixture-only build required"
#endif
#include "includes.h"
#include "smbd/smbd.h"
#include "lib/util/samba_modules.h"

_Static_assert(SMB_VFS_INTERFACE_VERSION == 50, "Pinned Samba VFS ABI");

static int refuse_unqualified_connection(struct vfs_handle_struct *handle,
    const char *service, const char *user)
{
    (void)handle;
    (void)service;
    (void)user;
    /* S2/S3 endpoint handoff and still-open sampling are not implemented.
     * Never silently enable an observer-less share or widen the bootstrap. */
    errno = ENOTSUP;
    return -1;
}

static const struct vfs_fn_pointers fixture_functions = {
    .connect_fn = refuse_unqualified_connection,
};

__attribute__((visibility("default")))
NTSTATUS samba_init_module(TALLOC_CTX *ctx)
{
    (void)ctx;
    return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "phantowd_open_qemu",
        &fixture_functions);
}
