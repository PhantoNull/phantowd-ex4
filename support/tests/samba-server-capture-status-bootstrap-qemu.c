/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Fixed STATUS-only entry; unchanged twelve-input native root boundary. */
#if !defined(PHANTOWD_SAMBA_CAPTURE_STATUS_FIXTURE) || PHANTOWD_SAMBA_CAPTURE_STATUS_FIXTURE != 1
#error "Disposable QEMU fixture only"
#endif
#define main phantowd_unused_native_fixture_entry
#include "samba-root-launcher-fixture.c"
#undef main

int main(int argc, char **argv)
{
    if (guard() || argc != 4 || strcmp(argv[1], "native-credential") ||
        strcmp(argv[2], "status") || argv[3][0]) return fail();
    return native_credential_fixture("status", "");
}
