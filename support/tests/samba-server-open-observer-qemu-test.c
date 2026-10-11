/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Actual pinned types/list/fd_handle functions plus real temporary file/fstat.
 * Open/tree/connection objects are SYNTHETIC, never an active Samba worker. */
#include "samba-server-open-observer-fixture.c"
#include "source3/smbd/fd_handle.c"
#include <dlfcn.h>
#include <sys/socket.h>

static unsigned refusals;
static int (*loaded_reader)(const connection_struct *, const files_struct *,
    struct phantowd_server_open_observation_v1 *);
static void require_at(bool value, int line)
{
    if (!value) {
        fprintf(stderr, "PHANTOWD_SERVER_OPEN_SOURCE_ASSERT_FAILED line=%d\n", line);
        _Exit(1);
    }
}
#define require(value) require_at((value), __LINE__)
static void refused(const connection_struct *connection, const files_struct *file)
{
    struct phantowd_server_open_observation_v1 output;
    memset(&output, 0xa5, sizeof(output));
    require(phantowd_qemu_observe_server_open_v1(connection, file, &output) != 0);
    unsigned char *bytes = (unsigned char *)&output;
    for (size_t index = 0; index < sizeof(output); ++index) require(bytes[index] == 0);
    memset(&output, 0xa5, sizeof(output));
    require(loaded_reader(connection, file, &output) != 0);
    for (size_t index = 0; index < sizeof(output); ++index) require(bytes[index] == 0);
    refusals++;
}

int main(int argc, char **argv)
{
    alarm(5);
    bool emit_frames = argc == 2 && !strcmp(argv[1], "--frames");
    bool emit_packets = argc == 2 && !strcmp(argv[1], "--packets");
    require(argc == 1 || emit_frames || emit_packets);
    if (emit_packets) {
        /* Fixed inherited fixture endpoint only; no path/arbitrary FD selector.
         * SO_PEERCRED identifies our parent creator, not us as packet sender. */
        for (unsigned index = 0; index < 3; ++index) {
            const int options[] = {SO_DOMAIN, SO_TYPE, SO_PROTOCOL};
            const int expected[] = {AF_UNIX, SOCK_SEQPACKET, 0};
            int value = -1;
            socklen_t length = sizeof(value);
            require(!getsockopt(3, SOL_SOCKET, options[index], &value, &length) &&
                length == sizeof(value) && value == expected[index]);
        }
        struct ucred creator = {0};
        socklen_t length = sizeof(creator);
        require(!getsockopt(3, SOL_SOCKET, SO_PEERCRED, &creator, &length) &&
            length == sizeof(creator) && creator.pid == getppid() &&
            creator.uid == geteuid() && creator.gid == getegid());
    }
    char name[] = "/tmp/phantowd-server-open.XXXXXX";
    int fd = mkstemp(name);
    require(fd >= 0 && write(fd, "synthetic-data", 14) == 14);
    struct stat initial, final;
    require(!fstat(fd, &initial));
    struct smbd_server_connection server = {0};
    struct smbXsrv_tcon_global0 tree_global = {
        .tcon_wire_id = 21, .session_global_id = 42,
        .server_id = {.pid = getpid(), .vnn = UINT32_MAX, .unique_id = 999},
    };
    struct smbXsrv_tcon tree = {.global = &tree_global, .local_id = 21,
        .status = NT_STATUS_OK};
    connection_struct connection = {.sconn = &server, .tcon = &tree, .cnum = 21};
    tree.compat = &connection;
    struct smbXsrv_open_global0 open_global = {
        .open_global_id = 123, .open_persistent_id = 123, .open_volatile_id = 456,
        .server_id = tree_global.server_id,
    };
    struct smbXsrv_open opening = {.global = &open_global, .local_id = 456,
        .status = NT_STATUS_OK};
    files_struct file = {.conn = &connection, .op = &opening, .vuid = 42, .fnum = 456,
        .file_id = {.devid = initial.st_dev, .inode = initial.st_ino}};
    /* Real upstream allocation/getters/setters, not a copied fd_handle layout. */
    file.fh = fd_handle_create(NULL);
    require(file.fh != NULL);
    fh_set_refcount(file.fh, 1);
    fsp_set_fd(&file, fd);
    fh_set_gen_id(file.fh, 7777); /* Deliberately neither remote FileId half. */
    opening.compat = &file;
    DLIST_ADD(server.files, &file);
    server.num_files = 1;
    struct phantowd_server_open_observation_v1 observed, repeated;
    require(!phantowd_qemu_observe_server_open_v1(&connection, &file, &observed));
    require(observed.persistent_id == 123 && observed.volatile_id == 456 &&
        observed.share_file_id == 7777 && observed.session_id == 42 &&
        observed.tree_id == 21 && observed.device == (uint64_t)initial.st_dev &&
        observed.inode == (uint64_t)initial.st_ino && observed.worker_pid == (uint32_t)getpid());
    require(!phantowd_qemu_observe_server_open_v1(&connection, &file, &repeated) &&
        !memcmp(&observed, &repeated, sizeof(observed)));

    /* Actual DSO uses the installed pinned Samba getters, not our local copy.
     * The supplied open/tree objects are still synthetic, not server authority. */
    void *library = dlopen("/usr/lib/phantowd-server-open-fixture.so", RTLD_NOW | RTLD_LOCAL);
    require(library != NULL);
    void *symbol = dlsym(library, "phantowd_qemu_observe_server_open_v1");
    _Static_assert(sizeof(symbol) == sizeof(loaded_reader), "Fixed function pointer ABI");
    memcpy(&loaded_reader, &symbol, sizeof(symbol));
    require(loaded_reader != NULL &&
        !loaded_reader(&connection, &file, &repeated) &&
        !memcmp(&observed, &repeated, sizeof(observed)));

    require(phantowd_qemu_observe_server_open_v1(&connection, &file, NULL) != 0);
    refused(NULL, &file); refused(&connection, NULL);
    files_struct copied_file = file;
    refused(&connection, &copied_file); /* Equal fields, not the registered object. */
    refused(&connection, (const files_struct *)(uintptr_t)1); /* Before dereference. */
#define BAD(field, value) do { __typeof__(field) saved = field; field = value; \
    refused(&connection, &file); field = saved; } while (0)
    BAD(connection.sconn, NULL); BAD(connection.tcon, NULL);
    BAD(tree.global, NULL); BAD(tree.compat, NULL); BAD(tree.status, NT_STATUS_INVALID_HANDLE);
    BAD(server.files, NULL); BAD(server.num_files, 0); BAD(server.num_files, 2);
    BAD(file.next, &file); BAD(file.conn, NULL); BAD(file.fh, NULL);
    fh_set_refcount(file.fh, 2); refused(&connection, &file); fh_set_refcount(file.fh, 1);
    file.fsp_flags.is_pathref = true; refused(&connection, &file); file.fsp_flags.is_pathref = false;
    file.fsp_flags.is_directory = true; refused(&connection, &file); file.fsp_flags.is_directory = false;
    file.fsp_flags.is_dirfsp = true; refused(&connection, &file); file.fsp_flags.is_dirfsp = false;
    file.fsp_flags.closing = true; refused(&connection, &file); file.fsp_flags.closing = false;
    file.fsp_flags.modified = true; refused(&connection, &file); file.fsp_flags.modified = false;
    file.fsp_flags.posix_open = true; refused(&connection, &file); file.fsp_flags.posix_open = false;
    file.fsp_flags.delete_on_close = true; refused(&connection, &file); file.fsp_flags.delete_on_close = false;
    file.fsp_flags.initial_delete_on_close = true; refused(&connection, &file); file.fsp_flags.initial_delete_on_close = false;
    BAD(file.base_fsp, &file); BAD(file.op, NULL); BAD(opening.global, NULL);
    BAD(opening.compat, NULL); BAD(opening.status, NT_STATUS_INVALID_HANDLE);
    BAD(file.vuid, 0); BAD(file.vuid, UINT64_MAX); BAD(file.vuid, 43);
    BAD(tree_global.tcon_wire_id, 0); BAD(tree_global.tcon_wire_id, UINT32_MAX);
    BAD(connection.cnum, 22); BAD(tree.local_id, 22);
    BAD(open_global.open_persistent_id, 0); BAD(open_global.open_persistent_id, UINT64_MAX);
    BAD(open_global.open_global_id, 124); BAD(open_global.open_volatile_id, 0);
    BAD(open_global.open_volatile_id, UINT64_MAX); BAD(opening.local_id, 457); BAD(file.fnum, 457);
    fh_set_gen_id(file.fh, 0); refused(&connection, &file);
    fh_set_gen_id(file.fh, UINT64_MAX); refused(&connection, &file); fh_set_gen_id(file.fh, 7777);
    BAD(open_global.durable, 1); BAD(open_global.disconnect_time, 1);
    BAD(open_global.server_id.pid, 1); BAD(open_global.server_id.pid, getpid() + 1);
    BAD(open_global.server_id.task_id, 1); BAD(open_global.server_id.vnn, 0);
    BAD(open_global.server_id.unique_id, 0); BAD(open_global.server_id.unique_id, UINT64_MAX);
    BAD(tree_global.server_id.pid, 1); BAD(tree_global.server_id.task_id, 1);
    BAD(tree_global.server_id.vnn, 0); BAD(tree_global.server_id.unique_id, 998);
    BAD(file.file_id.extid, 1); BAD(file.file_id.devid, initial.st_dev + 1);
    BAD(file.file_id.inode, initial.st_ino + 1);
    fsp_set_fd(&file, -1); refused(&connection, &file); fsp_set_fd(&file, fd);
#undef BAD
    /* Same connection/remote IDs, a different real file: metadata must refuse. */
    char other_name[] = "/tmp/phantowd-server-other.XXXXXX";
    int other = mkstemp(other_name);
    require(other >= 0 && write(other, "synthetic-data", 14) == 14);
    fsp_set_fd(&file, -1); fsp_set_fd(&file, other);
    refused(&connection, &file);
    fsp_set_fd(&file, -1); fsp_set_fd(&file, fd);
    require(!close(other) && !unlink(other_name));
    int closed = dup(fd);
    require(closed >= 0 && !close(closed));
    fsp_set_fd(&file, -1); fsp_set_fd(&file, closed);
    refused(&connection, &file); /* Actual fstat EBADF, not just negative fd. */
    int directory = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(directory >= 0);
    fsp_set_fd(&file, -1); fsp_set_fd(&file, directory);
    refused(&connection, &file); /* Actual directory descriptor. */
    require(!close(directory));
    fsp_set_fd(&file, -1); fsp_set_fd(&file, fd);
    char alias[sizeof(name) + 8];
    require(snprintf(alias, sizeof(alias), "%s.alias", name) > 0 && !link(name, alias));
    refused(&connection, &file); /* Actual shared inode, not edited mock nlink. */
    require(!unlink(alias));
    require(!fstat(fd, &final) && initial.st_dev == final.st_dev &&
        initial.st_ino == final.st_ino && initial.st_size == final.st_size);
    char data[14];
    require(pread(fd, data, sizeof(data), 0) == 14 && !memcmp(data, "synthetic-data", 14));
    require(!phantowd_qemu_observe_server_open_v1(&connection, &file, &repeated) &&
        !memcmp(&observed, &repeated, sizeof(observed)));
    require(!loaded_reader(&connection, &file, &repeated) &&
        !memcmp(&observed, &repeated, sizeof(observed)) && !dlclose(library));
    require(!close(fd) && !unlink(name));
    fsp_set_fd(&file, -1);
    TALLOC_FREE(file.fh);
    unsigned char frames[176];
    memset(frames, 0xa5, sizeof(frames));
    require(phantowd_qemu_encode_server_open_v1(frames, &observed, 0) != 0);
    for (unsigned index = 0; index < 88; ++index) require(frames[index] == 0);
    require(phantowd_qemu_encode_server_open_v1(NULL, &observed, 1) != 0 &&
        phantowd_qemu_encode_server_open_v1(frames, NULL, 1) != 0);
    for (unsigned index = 0; index < 88; ++index) require(frames[index] == 0);
    require(!phantowd_qemu_encode_server_open_v1(frames, &observed, 1) &&
        !phantowd_qemu_encode_server_open_v1(frames + 88, &repeated, 2));
    if (emit_frames) {
        /* Private subprocess bytes only. The Go test captures them without
         * logging raw IDs; this is not the future retained worker channel. */
        require(write(STDOUT_FILENO, frames, sizeof(frames)) == sizeof(frames));
        return 0;
    }
    if (emit_packets) {
        /* Exactly two metadata packets, each sent once. The original synthetic
         * file has already closed; this does not claim active-worker lifetime. */
        require(send(3, frames, 88, MSG_DONTWAIT | MSG_NOSIGNAL) == 88 &&
            send(3, frames + 88, 88, MSG_DONTWAIT | MSG_NOSIGNAL) == 88);
        return 0;
    }
    printf("PHANTOWD_SERVER_OPEN_SOURCE_READY refusals=%u dso_refusals=%u real_fd=true real_getters=true synthetic_open=true active_worker=false authority=false scope=qemu-only\n", refusals, refusals);
    return 0;
}
