/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#include <stdio.h>
#include "lio-lun-set.h"

int main(void)
{
    uint16_t luns[4] = {0}, second, a, b;
    uint32_t count;
    if (fixture_lun_set_matches(0, 2, 1) ||
        fixture_lun_set_matches(luns, 2, 2))
        return 1;
    for (second = 1; second <= 3; second += 2) {
        for (a = 0; a < 8; a++) {
            for (b = 0; b < 8; b++) {
                luns[0] = a;
                luns[1] = b;
                for (count = 0; count < 4; count++) {
                    int expected = count == 2 &&
                        ((a == 0 && b == second) || (a == second && b == 0));
                    if (fixture_lun_set_matches(luns, count, second) != expected) {
                        puts("PHANTOWD_LIO_LUN_SET_ERROR case=exact-unordered-set");
                        return 1;
                    }
                }
            }
        }
    }
    luns[0] = UINT16_MAX;
    luns[1] = 0;
    if (fixture_lun_set_matches(luns, 2, 1))
        return 1;
    if (fixture_owned_lun_set_matches(0, 2))
        return 1;
    for (a = 0; a < 9; a++) {
        for (b = 0; b < 9; b++) {
            luns[0] = a;
            luns[1] = b;
            for (count = 0; count < 4; count++) {
                int expected = count == 2 && ((a == 0 && b == 7) || (a == 7 && b == 0));
                if (fixture_owned_lun_set_matches(luns, count) != expected)
                    return 1;
            }
        }
    }
    puts("PHANTOWD_LIO_LUN_SET_READY permutations=true exact_cardinality=true duplicates_refused=true missing_refused=true foreign_refused=true scope=pure-native-matcher-only");
    return 0;
}
