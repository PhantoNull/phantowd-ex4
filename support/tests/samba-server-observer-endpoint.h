/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#ifndef PHANTOWD_OBSERVER_ENDPOINT_H
#define PHANTOWD_OBSERVER_ENDPOINT_H
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif
/* Private fixture snapshot only, not channel ownership or execution authority. */
struct observer_endpoint {
    dev_t device;
    ino_t inode;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    uint64_t cookie;
    struct ucred peer;
    bool passsec_unavailable;
};
static int observer_sender_snapshot(int fd, struct ucred creator,
    struct observer_endpoint *output)
{
    memset(output, 0, sizeof(*output));
    struct stat object;
    struct observer_endpoint observed = {0};
    socklen_t length;
    int value;
    if (creator.pid <= 0 || fstat(fd, &object) != 0 || !S_ISSOCK(object.st_mode) ||
        object.st_uid != creator.uid || object.st_gid != creator.gid ||
        fcntl(fd, F_GETFD) != 0 || fcntl(fd, F_GETFL) != O_RDWR)
        return -1;
#define OBSERVER_OPTION(option, expected) do { \
    value = -1; length = sizeof(value); \
    if (getsockopt(fd, SOL_SOCKET, (option), &value, &length) != 0 || \
        length != sizeof(value) || value != (expected)) return -1; \
} while (0)
    OBSERVER_OPTION(SO_DOMAIN, AF_UNIX);
    OBSERVER_OPTION(SO_TYPE, SOCK_SEQPACKET);
    OBSERVER_OPTION(SO_PROTOCOL, 0);
    OBSERVER_OPTION(SO_PASSCRED, 0);
    OBSERVER_OPTION(SO_PASSPIDFD, 0);
#undef OBSERVER_OPTION
    value = -1; length = sizeof(value);
    if (getsockopt(fd, SOL_SOCKET, SO_PASSSEC, &value, &length) != 0) {
        if (errno != EOPNOTSUPP) return -1;
        observed.passsec_unavailable = true;
    } else if (length != sizeof(value) || value != 0) {
        return -1;
    }
    length = sizeof(observed.cookie);
    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &observed.cookie, &length) != 0 ||
        length != sizeof(observed.cookie) || observed.cookie == 0)
        return -1;
    length = sizeof(observed.peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &observed.peer, &length) != 0 ||
        length != sizeof(observed.peer) || observed.peer.pid != creator.pid ||
        observed.peer.uid != creator.uid || observed.peer.gid != creator.gid)
        return -1;
    observed.device = object.st_dev;
    observed.inode = object.st_ino;
    observed.mode = object.st_mode;
    observed.uid = object.st_uid;
    observed.gid = object.st_gid;
    *output = observed;
    return 0;
}
static bool observer_endpoint_equal(const struct observer_endpoint *left,
    const struct observer_endpoint *right)
{
    return left->device == right->device && left->inode == right->inode &&
        left->mode == right->mode && left->uid == right->uid &&
        left->gid == right->gid && left->cookie == right->cookie &&
        left->peer.pid == right->peer.pid && left->peer.uid == right->peer.uid &&
        left->peer.gid == right->peer.gid &&
        left->passsec_unavailable == right->passsec_unavailable;
}
#endif
