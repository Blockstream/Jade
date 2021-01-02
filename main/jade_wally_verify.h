#ifndef JADE_WALLY_VERIFY_H_
#define JADE_WALLY_VERIFY_H_

#include "jade_assert.h"
#include <wally_core.h>

// Macro to make a libwally call and assert that the result is WALLY_OK
#define JADE_WALLY_VERIFY(expr)                                                                                        \
    do {                                                                                                               \
        const int r = (expr);                                                                                          \
        JADE_ASSERT_MSG(r == WALLY_OK, "WALLY ERROR: %d", r);                                                          \
    } while (false)

#endif
