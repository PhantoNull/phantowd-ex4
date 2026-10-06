/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Dynamic glibc conversion probe, executed only in the disposable QEMU root. */
#define _GNU_SOURCE
#include <iconv.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <linux/capability.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>

static int convert(const char *to, const char *from,
                   const unsigned char *input, size_t input_size,
                   const unsigned char *expected, size_t expected_size)
{
    iconv_t handle = iconv_open(to, from);
    if (handle == (iconv_t)-1) {
        perror("fixture CP850 iconv_open");
        return 1;
    }
    unsigned char output[32] = {0};
    char *in = (char *)input, *out = (char *)output;
    size_t available = sizeof(output), remaining = input_size;
    size_t result = iconv(handle, &in, &remaining, &out, &available);
    int mismatch = result != 0 || remaining != 0 ||
        sizeof(output) - available != expected_size ||
        memcmp(output, expected, expected_size);
    if (iconv_close(handle) != 0)
        mismatch = 1;
    return mismatch;
}

/* Separate lookup-only experiment; no credential or Samba command. The fixed
 * expected IDs independently check the real Owner's deterministic allocation. */
static int native_lookup(void)
{
    // The actual post-exec libc probe, not just the privileged bootstrap,
    // verifies that neither original namespace nor configuration FDs survive.
    for (int fd = 3; fd <= 64; ++fd)
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
            return 1;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    struct statvfs flags;
    struct stat info;
    if (getuid() != 65534 || geteuid() != 65534 || getgid() != 65534 ||
        getegid() != 65534 || getgroups(0, NULL) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        syscall(SYS_capget, &header, caps) || caps[0].effective ||
        caps[0].permitted || caps[0].inheritable || caps[1].effective ||
        caps[1].permitted || caps[1].inheritable ||
        statvfs("/", &flags) || !(flags.f_flag & ST_RDONLY) ||
        statvfs("/etc", &flags) ||
        (flags.f_flag & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) !=
            (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC))
        return 1;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        int bounded = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (bounded < 0) {
            if (errno != EINVAL || cap <= CAP_LAST_CAP)
                return 1;
            break;
        }
        if (bounded || prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET,
                             cap, 0, 0) != 0)
            return 1;
    }
    const char *absent[] = {"/proc", "/sys", "/dev", "/state", "/shares",
        "/etc/shadow", "/etc/samba", "/run/phantowd-native-lookup"};
    for (size_t i = 0; i < sizeof(absent) / sizeof(absent[0]); ++i)
        if (!lstat(absent[i], &info) || errno != ENOENT)
            return 1;
    const char *names[] = {"qpmanaged", "qpsecond"};
    for (size_t i = 0; i < 2; ++i) {
        uid_t expected = 2000 + i;
        struct passwd *user = getpwnam(names[i]);
        if (!user || user->pw_uid != expected || user->pw_gid != expected ||
            strcmp(user->pw_name, names[i]) || strcmp(user->pw_passwd, "!") ||
            strcmp(user->pw_dir, "/") || strcmp(user->pw_shell, "/sbin/nologin"))
            return 1;
        user = getpwuid(expected);
        if (!user || strcmp(user->pw_name, names[i]))
            return 1;
        struct group *group = getgrnam(names[i]);
        if (!group || group->gr_gid != expected || group->gr_mem[0])
            return 1;
        group = getgrgid(expected);
        if (!group || strcmp(group->gr_name, names[i]))
            return 1;
        gid_t groups[8];
        int count = 8;
        if (getgrouplist(names[i], expected, groups, &count) != 1 ||
            count != 1 || groups[0] != expected)
            return 1;
    }
    for (size_t i = 0; i < 3; ++i) {
        const char *foreign[] = {"qpwriter", "qpreader", "qpoutsider"};
        if (getpwnam(foreign[i]) || getpwuid(1801 + i))
            return 1;
    }
    if (getgrnam("qpgroup") || getgrgid(1800))
        return 1;
    unsigned int users = 0, groups = 0;
    setpwent();
    while (getpwent())
        if (++users > 4)
            return 1;
    endpwent();
    setgrent();
    while (getgrent())
        if (++groups > 4)
            return 1;
    endgrent();
    if (users != 4 || groups != 4)
        return 1;
    puts("PHANTOWD_NATIVE_LIBC_LOOKUP_READY accounts=2 private_groups=true "
         "foreign_omitted=true readonly_root=true caps_zero=true no_state=true "
         "scope=qemu-only");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "native-lookup")) {
        int result = native_lookup();
        if (result)
            fputs("PHANTOWD_NATIVE_LIBC_LOOKUP_REFUSED\n", stderr);
        return result;
    }
    if (argc != 1)
        return 1;
    /* Distinct accented and box-drawing characters, not ASCII identity. */
    const unsigned char cp850[] = {0x82, 0x9c, 0xa0, 0xe1, 0xb3};
    const unsigned char utf8[] = {0xc3, 0xa9, 0xc2, 0xa3, 0xc3, 0xa1,
                                  0xc3, 0x9f, 0xe2, 0x94, 0x82};
    const char *aliases[] = {"CP850", "850", "CSPC850MULTILINGUAL",
                              "OSF10020352", "IBM850"};
    for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); ++i) {
        if (convert("UTF-8", aliases[i], cp850, sizeof(cp850), utf8, sizeof(utf8)) ||
            convert(aliases[i], "UTF-8", utf8, sizeof(utf8), cp850, sizeof(cp850))) {
            fputs("fixture CP850 byte conversion failed\n", stderr);
            return 1;
        }
    }
    /* No replacement, transliteration or ASCII fallback for unsupported data. */
    const char unsupported[] = "\xce\xb2"; /* Greek beta, absent in CP850. */
    const char *invalid[] = {unsupported, "\xff", "\xc3"};
    const size_t sizes[] = {2, 1, 1};
    const int errors[] = {EILSEQ, EILSEQ, EINVAL};
    for (size_t i = 0; i < 3; ++i) {
        iconv_t handle = iconv_open("CP850", "UTF-8");
        if (handle == (iconv_t)-1)
            return 1;
        char output[16] = {0}, *out = output, *in = (char *)invalid[i];
        size_t remaining = sizes[i], available = sizeof(output);
        errno = 0;
        size_t result = iconv(handle, &in, &remaining, &out, &available);
        int mismatch = result != (size_t)-1 || errno != errors[i] ||
            remaining != sizes[i] || available != sizeof(output);
        if (iconv_close(handle) != 0 || mismatch)
            return 1;
    }
    puts("PHANTOWD_SAMBA_ROOT_CHARSET_READY charset=CP850 bytes=true "
         "roundtrip=true isolated_root=true scope=qemu-only");
    return 0;
}
