/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Actual pinned Samba VFS/tevent/reader and kernel sockets. Connection/open
 * records and the thin system-pread backend are synthetic, NOT an SMB worker.
 * The combined artifact includes upstream GPL Samba code and retains its
 * terms/notices. These original-file SPDX headers do not relicense Samba. */
#ifndef PHANTOWD_SAMBA_SERVER_CAPTURE_FIXTURE
#error "Dedicated disposable capture test only"
#endif
#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "librpc/gen_ndr/smbXsrv.h"
#include "lib/util/samba_modules.h"
#include "source3/smbd/fd_handle.c"
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <dirent.h>

static void require_at(bool value, int line)
{
    if (!value) {
        fprintf(stderr, "PHANTOWD_SERVER_CAPTURE_ASSERT_FAILED line=%d errno=%d\n", line, errno);
        _Exit(1);
    }
}
#define require(value) require_at((value), __LINE__)
static unsigned fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    require(directory != NULL);
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
    require(!closedir(directory));
    return count;
}
static bool backend_fail;
static int backend_connect(vfs_handle_struct *handle, const char *service,
    const char *user)
{
    (void)handle; (void)service; (void)user; return 0;
}
static void backend_disconnect(vfs_handle_struct *handle) { (void)handle; }
static ssize_t backend_pread(vfs_handle_struct *handle, files_struct *file,
    void *data, size_t count, off_t offset)
{
    (void)handle;
    if (backend_fail) { errno = EIO; return -1; }
    return pread(fsp_get_pathref_fd(file), data, count, offset);
}
struct backend_read_state { ssize_t result; struct vfs_aio_state aio; };
static struct tevent_req *backend_send(vfs_handle_struct *handle,
    TALLOC_CTX *mem_ctx, struct tevent_context *ev, files_struct *file,
    void *data, size_t count, off_t offset)
{
    struct backend_read_state *state;
    struct tevent_req *req = tevent_req_create(mem_ctx, &state, struct backend_read_state);
    if (!req) return NULL;
    state->result = backend_pread(handle, file, data, count, offset);
    state->aio.error = state->result < 0 ? errno : 0;
    tevent_req_done(req);
    return tevent_req_post(req, ev);
}
static ssize_t backend_recv(struct tevent_req *req, struct vfs_aio_state *aio)
{
    struct backend_read_state *state = tevent_req_data(req, struct backend_read_state);
    *aio = state->aio; return state->result;
}
static ssize_t async_read(vfs_handle_struct *handle, files_struct *file,
    TALLOC_CTX *ctx, struct tevent_context *ev, unsigned char *data)
{
    struct tevent_req *req = handle->fns->pread_send_fn(handle, ctx, ev, file, data, 1, 0);
    require(req != NULL && tevent_req_poll(req, ev));
    struct vfs_aio_state aio = {0};
    ssize_t result = handle->fns->pread_recv_fn(req, &aio);
    TALLOC_FREE(req);
    errno = aio.error;
    return result;
}
enum { SYNC, ASYNC, COPIED, CLOSING, PRE_FSA, REMOTE_DRIFT, CLOSE_DRIFT,
    SENDER_DRIFT, PEER_CLOSED, QUEUE_FULL, BOUNDS, BAD_USER, RECONNECT,
    BACKEND_ERROR, CANCELED, OVERLAP, WRONG_ROLE, MISSING_FILE, SHARE_DRIFT,
    DISCONNECTED, CASES };

static void child_case(unsigned which, int receiver)
{
    alarm(5);
    unsigned before = fd_count();
    require(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    require(!setgroups(0, NULL) && !setresgid(65534, 65534, 65534) &&
        !setresuid(65534, 65534, 65534));
    require(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    struct __user_cap_header_struct cap_header = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0,
    };
    struct __user_cap_data_struct caps[2] = {{0}};
    require(!syscall(SYS_capget, &cap_header, caps));
    for (unsigned i = 0; i < 2; ++i)
        require(!caps[i].effective && !caps[i].permitted && !caps[i].inheritable);
    static const struct vfs_fn_pointers backend = {
        .connect_fn = backend_connect, .disconnect_fn = backend_disconnect,
        .pread_fn = backend_pread, .pread_send_fn = backend_send,
        .pread_recv_fn = backend_recv,
    };
    require(NT_STATUS_IS_OK(smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
        "phantowd_capture_backend_qemu", &backend)));
    require(NT_STATUS_IS_OK(smb_load_module("vfs", "phantowd_open_qemu")));
    TALLOC_CTX *ctx = talloc_new(NULL);
    connection_struct *conn = talloc_zero(ctx, connection_struct);
    require(conn != NULL);
    conn->read_only = true;
    require(vfs_init_custom(conn, "phantowd_capture_backend_qemu"));
    require(vfs_init_custom(conn, "phantowd_open_qemu"));
    vfs_handle_struct *handle = conn->vfs_handles;
    require(handle && handle->fns->connect_fn && handle->fns->pread_fn &&
        handle->fns->pread_send_fn && handle->fns->pread_recv_fn);
    if (which == BAD_USER || which == WRONG_ROLE) {
        int original = -1;
        if (which == WRONG_ROLE) {
            original = fcntl(3, F_DUPFD_CLOEXEC, 32);
            require(original >= 32 && dup2(receiver, 3) == 3);
        }
        require(handle->fns->connect_fn(handle, "readonly",
            which == BAD_USER ? "root" : "nobody") == -1 && errno == EIO);
        if (which == WRONG_ROLE)
            require(dup2(original, 3) == 3 && !close(original));
        require(handle->fns->connect_fn(handle, "readonly", "nobody") == -1 && errno == EIO);
        require(!close(3));
        if (receiver >= 0) require(!close(receiver));
        require(!talloc_free(ctx));
        require(fd_count() == before - 1 - (receiver >= 0 ? 1 : 0));
        return;
    }
    require(handle->fns->connect_fn(handle, "readonly", "nobody") == 0);
    if (receiver >= 0) require(!close(receiver));

    char name[] = "/tmp/phantowd-capture.XXXXXX";
    int fd = mkstemp(name);
    require(fd >= 0 && write(fd, "data", 4) == 4);
    struct stat initial, final;
    require(!fstat(fd, &initial));
    struct smbd_server_connection server = {0};
    struct smbXsrv_tcon_global0 tree_global = {
        .tcon_wire_id = 21, .session_global_id = 42,
        .server_id = {.pid = getpid(), .vnn = UINT32_MAX, .unique_id = 999},
    };
    struct smbXsrv_tcon tree = {.global = &tree_global, .local_id = 21,
        .status = NT_STATUS_OK, .compat = conn};
    conn->sconn = &server; conn->tcon = &tree; conn->cnum = 21;
    struct smbXsrv_open_global0 open_global = {
        .open_global_id = 123, .open_persistent_id = 123, .open_volatile_id = 456,
        .server_id = tree_global.server_id,
    };
    files_struct file = {.conn = conn, .vuid = 42, .fnum = 456,
        .file_id = {.devid = initial.st_dev, .inode = initial.st_ino}};
    struct smbXsrv_open opening = {.global = &open_global, .local_id = 456,
        .status = NT_STATUS_OK, .compat = &file};
    file.op = &opening; file.fsp_flags.is_fsa = true;
    file.fh = fd_handle_create(ctx);
    require(file.fh != NULL);
    fh_set_refcount(file.fh, 1); fsp_set_fd(&file, fd);
    fh_set_gen_id(file.fh, 7777);
    DLIST_ADD(server.files, &file); server.num_files = 1;
    struct tevent_context *ev = tevent_context_init(ctx);
    require(ev != NULL);
    unsigned char data = 0;
    if (which == SYNC || which == ASYNC) {
        for (unsigned i = 0; i < 2; ++i) {
            ssize_t result = which == ASYNC ? async_read(handle, &file, ctx, ev, &data) :
                handle->fns->pread_fn(handle, &file, &data, 1, 0);
            require(result == 1 && data == 'd');
        }
    } else {
        if (which == REMOTE_DRIFT || which == CLOSE_DRIFT) {
            require(handle->fns->pread_fn(handle, &file, &data, 1, 0) == 1 && data == 'd');
            if (which == REMOTE_DRIFT) open_global.open_global_id = open_global.open_persistent_id = 124;
            else file.fsp_flags.closing = true;
        }
        if (which == SENDER_DRIFT)
            require(!setsockopt(3, SOL_SOCKET, SO_PASSCRED, &(int){1}, sizeof(int)));
        if (which == QUEUE_FULL) {
            unsigned char filler[88] = {0};
            unsigned filled = 0;
            while (send(3, filler, sizeof(filler), MSG_DONTWAIT | MSG_NOSIGNAL) == 88)
                require(++filled <= 64);
            require(filled > 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        }
        files_struct copied = file;
        if (which == CLOSING) file.fsp_flags.closing = true;
        if (which == PRE_FSA) file.fsp_flags.is_fsa = false;
        if (which == SHARE_DRIFT) conn->read_only = false;
        if (which == RECONNECT)
            require(handle->fns->connect_fn(handle, "readonly", "nobody") == -1 && errno == EIO);
        if (which == DISCONNECTED) handle->fns->disconnect_fn(handle);
        backend_fail = which == BACKEND_ERROR;
        if (which == CANCELED || which == OVERLAP) {
            struct tevent_req *first = handle->fns->pread_send_fn(handle, ctx, ev, &file, &data, 1, 0);
            require(first != NULL);
            if (which == CANCELED) TALLOC_FREE(first);
            else {
                require(async_read(handle, &file, ctx, ev, &data) == -1 && errno == EIO);
                require(tevent_req_poll(first, ev));
                struct vfs_aio_state aio = {0};
                require(handle->fns->pread_recv_fn(first, &aio) == -1 && aio.error == EIO);
                TALLOC_FREE(first);
            }
        } else {
            require(handle->fns->pread_fn(handle,
                which == COPIED ? &copied : which == MISSING_FILE ? NULL : &file,
                &data, which == BOUNDS ? 2 : 1, 0) == -1 && errno == EIO);
        }
    }
    /* Repair fault inputs: sticky failure may never emit a replacement frame. */
    file.fsp_flags.is_fsa = true; file.fsp_flags.closing = false;
    conn->read_only = true; backend_fail = false;
    open_global.open_global_id = open_global.open_persistent_id = 123;
    require(!setsockopt(3, SOL_SOCKET, SO_PASSCRED, &(int){0}, sizeof(int)));
    for (unsigned i = 0; i < 2; ++i)
        require(handle->fns->pread_fn(handle, &file, &data, 1, 0) == -1 && errno == EIO);
    require(!fstat(fd, &final) && initial.st_dev == final.st_dev &&
        initial.st_ino == final.st_ino && initial.st_size == final.st_size &&
        initial.st_nlink == final.st_nlink &&
        initial.st_mode == final.st_mode && initial.st_uid == final.st_uid &&
        initial.st_gid == final.st_gid && initial.st_mtim.tv_sec == final.st_mtim.tv_sec &&
        initial.st_mtim.tv_nsec == final.st_mtim.tv_nsec && initial.st_ctim.tv_sec == final.st_ctim.tv_sec &&
        initial.st_ctim.tv_nsec == final.st_ctim.tv_nsec);
    char contents[4];
    require(pread(fd, contents, 4, 0) == 4 && !memcmp(contents, "data", 4));
    require(!close(fd) && !unlink(name) && !close(3));
    fsp_set_fd(&file, -1);
    require(!talloc_free(ctx));
    require(fd_count() == before - 1 - (receiver >= 0 ? 1 : 0));
}
static uint64_t le(const unsigned char *input, unsigned width)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i) value |= (uint64_t)input[i] << (i * 8);
    return value;
}
int main(void)
{
    alarm(15);
    require(getuid() == 0 && geteuid() == 0);
    int model_fd = open("/sys/firmware/devicetree/base/model", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char model[64] = {0};
    require(model_fd >= 0 && read(model_fd, model, sizeof(model)) == sizeof("ARM Versatile PB") &&
        !memcmp(model, "ARM Versatile PB", sizeof("ARM Versatile PB")) && !close(model_fd));
    int command_fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char command[512] = {0};
    require(command_fd >= 0 && read(command_fd, command, sizeof(command) - 1) > 0 &&
        strstr(command, " phantowd_capture_fixture=1 ") && !close(command_fd));
    unsigned before = fd_count();
    for (unsigned which = 0; which < CASES; ++which) {
        int pair[2];
        require(!socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
        require(!setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED, &(int){1}, sizeof(int)));
        require(!setsockopt(pair[1], SOL_SOCKET, SO_SNDBUF, &(int){2048}, sizeof(int)));
        int receiver = fcntl(pair[0], F_DUPFD_CLOEXEC, 16);
        int sender = fcntl(pair[1], F_DUPFD_CLOEXEC, 16);
        require(receiver >= 16 && sender >= 16 && !close(pair[0]) && !close(pair[1]));
        if (which == PEER_CLOSED) { require(!close(receiver)); receiver = -1; }
        pid_t child = fork();
        require(child >= 0);
        if (!child) {
            require(dup2(sender, 3) == 3 && !close(sender));
            child_case(which, receiver);
            _Exit(0);
        }
        require(!close(sender));
        int status;
        require(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
        unsigned records = 0, fillers = 0;
        unsigned char original[88] = {0};
        if (receiver >= 0) {
            for (;;) {
                unsigned char frame[89] = {0}, control[CMSG_SPACE(sizeof(struct ucred))];
                struct iovec io = {.iov_base = frame, .iov_len = sizeof(frame)};
                struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1,
                    .msg_control = control, .msg_controllen = sizeof(control)};
                ssize_t size = recvmsg(receiver, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
                if (size == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                if (size == 0) break;
                require(size == 88 && !(message.msg_flags & ~MSG_CMSG_CLOEXEC));
                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
                require(cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)) && !CMSG_NXTHDR(&message, cmsg));
                struct ucred cred;
                memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
                require(cred.pid == child && cred.uid == 65534 && cred.gid == 65534);
                if (which == QUEUE_FULL) {
                    for (unsigned i = 0; i < 88; ++i) require(!frame[i]);
                    require(++fillers <= 64); continue;
                }
                require(!memcmp(frame, "PWDOPEN\0", 8) && le(frame + 8, 2) == 1 &&
                    le(frame + 10, 2) == 72 && le(frame + 12, 4) == records + 1);
                require(le(frame + 16, 8) == 42 && le(frame + 24, 8) == 123 &&
                    le(frame + 32, 8) == 456 && le(frame + 40, 8) == 7777 &&
                    le(frame + 48, 8) && le(frame + 56, 8) && le(frame + 64, 8) == 999 &&
                    le(frame + 72, 4) == 21 && le(frame + 76, 4) == (uint32_t)child &&
                    !le(frame + 80, 4) && le(frame + 84, 4) == UINT32_MAX);
                if (!records) memcpy(original, frame, 88);
                else require(!memcmp(original + 16, frame + 16, 72));
                require(++records <= 2);
            }
            require(!close(receiver));
        }
        unsigned expected = which == SYNC || which == ASYNC ? 2 :
            which == REMOTE_DRIFT || which == CLOSE_DRIFT || which == BACKEND_ERROR ||
            which == CANCELED || which == OVERLAP ? 1 : 0;
        require(records == expected && (which != QUEUE_FULL || fillers > 0));
    }
    require(fd_count() == before);
    puts("PHANTOWD_SERVER_CAPTURE_READY sync=true async=true paired_frames=true credentials=true cases=20 sticky_refusal=true unchanged_data=true fd_equal=true uid=65534 caps=0 nnp=true synthetic_open=true active_worker=false authority=false scope=qemu-only");
    return 0;
}
