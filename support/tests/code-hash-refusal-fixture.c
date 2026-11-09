/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#include <unistd.h>

/* Disposable protocol-failure fixture, never installed as the hash reader. */
int main(void) {
#if FIXTURE_CASE == 1
    const char partial[] = "PHWDHS01\002\000\000\000";
    return write(1, partial, sizeof(partial)-1) == sizeof(partial)-1 ? 0 : 2;
#elif FIXTURE_CASE == 2
    return 1;
#elif FIXTURE_CASE == 3
    return write(2, "unexpected\n", 11) == 11 ? 0 : 2;
#elif FIXTURE_CASE == 4
    for (;;) pause();
#else
#error unknown fixture case
#endif
}
