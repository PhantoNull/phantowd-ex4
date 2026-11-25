/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <nettle/sha2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int output(const uint8_t *data, size_t length) {
    while (length) {
        ssize_t n = write(STDOUT_FILENO, data, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        data += n; length -= (size_t)n;
    }
    return 0;
}

int main(int argc, char **argv) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    char *end;
    unsigned long count;
    uint64_t total = 0;
    if (argc != 3 || strcmp(argv[1], "sha256-v1") || getuid() != 59999 ||
        geteuid() != 59999 || getgid() != 59999 || getegid() != 59999 || getgroups(0, NULL) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        syscall(SYS_capget, &header, caps)) return 10;
    for (unsigned i = 0; i < 2; i++)
        if (caps[i].effective || caps[i].permitted || caps[i].inheritable) return 10;
    errno = 0;
    count = strtoul(argv[2], &end, 10);
    if (errno || !*argv[2] || *end || count < 1 || count > 256) return 11;
    uint8_t prefix[12] = {'P','H','W','D','H','S','0','1',0,0,0,0};
    for (unsigned j = 0; j < 4; j++) prefix[8+j] = (uint8_t)(count >> (8*j));
    if (output(prefix, sizeof(prefix))) return 16;
    for (unsigned long i = 0; i < count; i++) {
        int fd = 4 + (int)i, flags = fcntl(fd, F_GETFL);
        struct stat st;
        struct sha256_ctx hash;
        uint8_t buffer[32768], record[40];
        off_t offset = 0;
        if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || (flags & O_PATH) || fstat(fd, &st) ||
            !S_ISREG(st.st_mode) || st.st_size <= 0 || (uint64_t)st.st_size > (64U<<20)-total) return 12;
        total += (uint64_t)st.st_size;
        sha256_init(&hash);
        for (;;) {
            ssize_t n = pread(fd, buffer, sizeof(buffer), offset);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) return 13;
            if (!n) break;
            offset += n;
            if (offset > st.st_size) return 14;
            sha256_update(&hash, (size_t)n, buffer);
        }
        if (offset != st.st_size) return 15;
        for (unsigned j = 0; j < 8; j++) record[j] = (uint8_t)((uint64_t)offset >> (8*j));
        sha256_digest(&hash, SHA256_DIGEST_SIZE, record+8);
        if (output(record, sizeof(record))) return 16;
    }
    return 0;
}
