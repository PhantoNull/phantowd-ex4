/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Dedicated capture variant: the loader-only fixture remains unchanged. */
#if !defined(PHANTOWD_SAMBA_SERVER_CAPTURE_FIXTURE) || PHANTOWD_SAMBA_SERVER_CAPTURE_FIXTURE != 1
#error "Dedicated disposable capture fixture only"
#endif
#include "includes.h"
#include "smbd/smbd.h"
#include "lib/util/samba_modules.h"
#include "lib/util/tevent_unix.h"
#include "samba-server-observer-endpoint.h"
#define PHANTOWD_SAMBA_SERVER_OBSERVER_FIXTURE 1
#include "samba-server-open-observer-fixture.c"
#include <sys/prctl.h>

_Static_assert(SMB_VFS_INTERFACE_VERSION == 50, "Pinned Samba VFS ABI");

struct capture_state {
    struct observer_endpoint sender;
    struct phantowd_server_open_observation_v1 first;
    unsigned sequence;
    bool failed;
    bool in_flight;
};
static bool capture_attempted;
static bool capture_review;

static int capture_connect(struct vfs_handle_struct *handle,
    const char *service, const char *user)
{
    /* Once per worker process, including refused attempts. This module is
     * never enabled by ordinary product config or the loader-only fixture. */
    if (capture_attempted) { capture_review = true; errno = EIO; return -1; }
    capture_attempted = true;
    struct ucred creator = {0};
    socklen_t length = sizeof(creator);
    struct observer_endpoint endpoint;
    if (!handle || !handle->conn || !handle->conn->read_only ||
        handle->param || handle->data || !service || strcmp(service, "readonly") ||
        !user || strcmp(user, "nobody") ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        getsockopt(3, SOL_SOCKET, SO_PEERCRED, &creator, &length) ||
        length != sizeof(creator) || creator.pid <= 1 || creator.uid || creator.gid ||
        observer_sender_snapshot(3, creator, &endpoint)) {
        errno = EIO; return -1;
    }
    struct capture_state *state = talloc_zero(handle->conn, struct capture_state);
    if (!state) { errno = ENOMEM; return -1; }
    state->sender = endpoint;
    if (SMB_VFS_NEXT_CONNECT(handle, service, user) != 0) {
        TALLOC_FREE(state);
        return -1;
    }
    struct observer_endpoint final;
    if (observer_sender_snapshot(3, creator, &final) ||
        !observer_endpoint_equal(&endpoint, &final)) {
        SMB_VFS_NEXT_DISCONNECT(handle);
        TALLOC_FREE(state);
        errno = EIO; return -1;
    }
    handle->data = state;
    return 0;
}

/* Sample only during a bounded read callback while Samba owns the live FSA.
 * Retain scalar metadata, never a file/FSA pointer. The containing bridge must
 * independently verify the client's successful OPEN and original worker. */
static int capture_begin(vfs_handle_struct *handle, files_struct *file,
    size_t count, off_t offset)
{
    struct capture_state *state = handle ? handle->data : NULL;
    if (!state) { errno = EIO; return -1; }
    struct observer_endpoint endpoint;
    struct phantowd_server_open_observation_v1 observed;
    unsigned char frame[88];
    if (capture_review || state->failed || state->in_flight || state->sequence >= 2 ||
        !handle->conn || !handle->conn->read_only ||
        count != 1 || offset != 0 ||
        observer_sender_snapshot(3, state->sender.peer, &endpoint) ||
        !observer_endpoint_equal(&state->sender, &endpoint) ||
        phantowd_qemu_observe_server_open_v1(handle->conn, file, &observed) ||
        (state->sequence && memcmp(&state->first, &observed, sizeof(observed))) ||
        phantowd_qemu_encode_server_open_v1(frame, &observed, state->sequence + 1) ||
        send(3, frame, sizeof(frame), MSG_DONTWAIT | MSG_NOSIGNAL) != sizeof(frame)) {
        state->failed = true; errno = EIO; return -1;
    }
    struct phantowd_server_open_observation_v1 final;
    if (observer_sender_snapshot(3, state->sender.peer, &endpoint) ||
        !observer_endpoint_equal(&state->sender, &endpoint) ||
        phantowd_qemu_observe_server_open_v1(handle->conn, file, &final) ||
        memcmp(&observed, &final, sizeof(final))) {
        /* A sent frame cannot be retracted. It does not authorize admission;
         * every uncertainty permanently refuses further reads/samples. */
        state->failed = true; errno = EIO; return -1;
    }
    state->first = observed;
    state->sequence++;
    state->in_flight = true;
    return 0;
}

static ssize_t capture_pread(vfs_handle_struct *handle, files_struct *file,
    void *data, size_t count, off_t offset)
{
    if (capture_begin(handle, file, count, offset)) return -1;
    struct capture_state *state = handle->data;
    ssize_t result = SMB_VFS_NEXT_PREAD(handle, file, data, count, offset);
    state->in_flight = false;
    if (result != 1 || state->failed) {
        state->failed = true; errno = EIO; return -1;
    }
    return result;
}

/* The async request retains only its scalar control state, not an FSA or a
 * connection/handle pointer. Sampling completes in send_fn before delegation;
 * no file pointer is dereferenced from a completion/destruction callback. */
struct capture_read_state {
    struct capture_state *owner;
    ssize_t result;
    struct vfs_aio_state aio;
};

static void capture_read_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct capture_read_state *state = tevent_req_data(req, struct capture_read_state);
    state->result = SMB_VFS_PREAD_RECV(subreq, &state->aio);
    TALLOC_FREE(subreq);
    state->owner->in_flight = false;
    if (state->result != 1 || state->owner->failed || capture_review) {
        state->owner->failed = true;
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_done(req);
}

static struct tevent_req *capture_read_send(vfs_handle_struct *handle,
    TALLOC_CTX *mem_ctx, struct tevent_context *ev, files_struct *file,
    void *data, size_t count, off_t offset)
{
    struct capture_read_state *state;
    struct tevent_req *req = tevent_req_create(mem_ctx, &state, struct capture_read_state);
    if (!req) {
        if (handle && handle->data) ((struct capture_state *)handle->data)->failed = true;
        return NULL;
    }
    if (capture_begin(handle, file, count, offset)) {
        tevent_req_error(req, EIO);
        return tevent_req_post(req, ev);
    }
    state->owner = talloc_reference(state, handle->data);
    if (!state->owner) {
        ((struct capture_state *)handle->data)->failed = true;
        tevent_req_error(req, ENOMEM);
        return tevent_req_post(req, ev);
    }
    struct tevent_req *subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle,
        file, data, count, offset);
    if (!subreq) {
        state->owner->failed = true;
        tevent_req_error(req, ENOMEM);
        return tevent_req_post(req, ev);
    }
    tevent_req_set_callback(subreq, capture_read_done, req);
    return req;
}

static ssize_t capture_read_recv(struct tevent_req *req, struct vfs_aio_state *aio)
{
    struct capture_read_state *state = tevent_req_data(req, struct capture_read_state);
    if (tevent_req_is_unix_error(req, &aio->error)) return -1;
    *aio = state->aio;
    return state->result;
}

static void capture_disconnect(vfs_handle_struct *handle)
{
    capture_review = true;
    if (!handle) return;
    if (handle && handle->data) ((struct capture_state *)handle->data)->failed = true;
    SMB_VFS_NEXT_DISCONNECT(handle);
}

static const struct vfs_fn_pointers capture_functions = {
    .connect_fn = capture_connect,
    .pread_fn = capture_pread,
    .pread_send_fn = capture_read_send,
    .pread_recv_fn = capture_read_recv,
    .disconnect_fn = capture_disconnect,
};

__attribute__((visibility("default")))
NTSTATUS samba_init_module(TALLOC_CTX *ctx)
{
    (void)ctx;
    return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "phantowd_open_qemu",
        &capture_functions);
}
