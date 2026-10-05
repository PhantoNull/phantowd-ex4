/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Fixed fixture-only ACL LUN set, not product discovery/admission. */
#ifndef PHANTOWD_FIXTURE_LIO_LUN_SET_H
#define PHANTOWD_FIXTURE_LIO_LUN_SET_H
#include <stdint.h>

static inline int fixture_lun_set_matches(const uint16_t *luns, uint32_t count,
                                         uint16_t second)
{
    if (luns == 0 || count != 2 || (second != 1 && second != 3))
        return 0;
    /* LIO emits its ACL hlist order, not numeric order. Require the exact set. */
    return (luns[0] == 0 && luns[1] == second) ||
           (luns[0] == second && luns[1] == 0);
}
static inline int fixture_owned_lun_set_matches(const uint16_t *luns, uint32_t count)
{
    return luns != 0 && count == 2 &&
           ((luns[0] == 0 && luns[1] == 7) || (luns[0] == 7 && luns[1] == 0));
}
#endif
