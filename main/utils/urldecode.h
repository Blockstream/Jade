#ifndef UTILS_URLDECODE_H_
#define UTILS_URLDECODE_H_

#include <stdbool.h>
#include <stddef.h>

#include "../jade_assert.h"

WARN_UNUSED_RESULT bool urldecode(const char* src, size_t src_len, char* dest, size_t dest_len);
WARN_UNUSED_RESULT bool urlencode(const char* src, size_t src_len, char* dest, size_t dest_len);

#endif /* UTILS_URLDECODE_H_ */
