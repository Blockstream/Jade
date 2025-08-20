#ifndef _LIBJADE_SODIUM_UTILS_H_
#define _LIBJADE_SODIUM_UTILS_H_ 1

static inline int sodium_memcmp(const void* p1, const void* p2, size_t n) { return memcmp(p1, p2, n); };

#endif // _LIBJADE_SODIUM_UTILS_H_
