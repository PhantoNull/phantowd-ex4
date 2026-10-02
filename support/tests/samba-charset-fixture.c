/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Dynamic glibc conversion probe, executed only in the disposable QEMU root. */
#include <iconv.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

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

int main(void)
{
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
