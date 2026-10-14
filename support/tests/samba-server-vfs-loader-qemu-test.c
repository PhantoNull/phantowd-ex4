/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Real Samba loader/registry only. No daemon, worker, data or channel. */
#ifndef PHANTOWD_SAMBA_SERVER_VFS_FIXTURE
#error "Fixture-only build required"
#endif
#include "includes.h"
#include "smbd/smbd.h"
#include "lib/util/samba_modules.h"
#include <sys/prctl.h>
#include <linux/capability.h>
#include <sys/syscall.h>

static void require(bool condition)
{
    if (!condition) {
        puts("PHANTOWD_SERVER_VFS_LOADER_ASSERT_FAILED");
        exit(1);
    }
}

int main(void)
{
    alarm(5);
    require(getuid() == 0 && geteuid() == 0);
    require(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    require(setresgid(65534, 65534, 65534) == 0);
    require(setresuid(65534, 65534, 65534) == 0);
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0,
    };
    struct __user_cap_data_struct caps[2] = {{0}};
    require(syscall(SYS_capget, &header, caps) == 0);
    for (unsigned index = 0; index < 2; ++index)
        require(!caps[index].effective && !caps[index].permitted &&
            !caps[index].inheritable);
    require(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);

    const char *name = "phantowd_open_qemu";
    require(NT_STATUS_EQUAL(smb_load_module(NULL, name),
        NT_STATUS_INVALID_PARAMETER));
    require(NT_STATUS_EQUAL(smb_load_module("vfs", NULL),
        NT_STATUS_INVALID_PARAMETER));
    require(NT_STATUS_EQUAL(smb_load_module("vfs", "/phantowd_open_qemu"),
        NT_STATUS_INVALID_PARAMETER));
    require(!NT_STATUS_IS_OK(smb_load_module("vfs", "phantowd_missing_qemu")));
    static const struct vfs_fn_pointers foreign = {0};
    require(NT_STATUS_EQUAL(smb_register_vfs(SMB_VFS_INTERFACE_VERSION + 1,
        "phantowd_wrong_abi_qemu", &foreign), NT_STATUS_OBJECT_TYPE_MISMATCH));
    /* Exercise the actual canonical subsystem loader, not a fake registry. */
    require(NT_STATUS_IS_OK(smb_load_module("vfs", name)));
    TALLOC_CTX *ctx = talloc_new(NULL);
    require(ctx != NULL);
    connection_struct *conn = talloc_zero(ctx, connection_struct);
    require(conn != NULL && vfs_init_custom(conn, name));
    vfs_handle_struct *handle = conn->vfs_handles;
    require(handle != NULL && handle->conn == conn && handle->fns != NULL);
    require(handle->fns->connect_fn != NULL);
    errno = 0;
    require(handle->fns->connect_fn(handle, "fixture", "fixture") == -1);
    require(errno == ENOTSUP);
    errno = 0;
    require(handle->fns->connect_fn(NULL, NULL, NULL) == -1 && errno == ENOTSUP);
    require(NT_STATUS_EQUAL(smb_load_module("vfs", name),
        NT_STATUS_OBJECT_NAME_COLLISION));
    talloc_free(ctx);
    puts("PHANTOWD_SERVER_VFS_LOADER_READY canonical=true registry=true connect_refused=true loader_refusals=6 uid=65534 caps=0 nnp=true active_worker=false producer=false authority=false scope=qemu-only");
    return 0;
}
