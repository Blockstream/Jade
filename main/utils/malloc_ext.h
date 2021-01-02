#ifndef UTILS_MALLOC_EXT_H_
#define UTILS_MALLOC_EXT_H_

#include "jade_assert.h"

#include <esp_heap_caps.h>

// Ensures memory allocated from local dram (and not external spiram)
// Freed with normal heap_caps_free() or free() functions.
static inline void* malloc_dram(const char* file, int line, size_t size)
{
    void* ptr = heap_caps_malloc(size, MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL);
    JADE_ASSERT_MSG(ptr, "heap_caps_malloc failed %s:%d", file, line);
    return ptr;
}

// Prefers memory to be allocated from SPIRAM if available.
// Falls back to interam dram if spiram full or not present.
// Freed with normal heap_caps_free() or free() functions.
static inline void* malloc_prefer_spiram(const char* file, int line, size_t size)
{
    void* ptr = heap_caps_malloc_prefer(size, MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM, MALLOC_CAP_DEFAULT);
    JADE_ASSERT_MSG(ptr, "heap_caps_malloc_prefer failed %s:%d", file, line);
    return ptr;
}

static inline void* jade_malloc(const char* file, int line, size_t size)
{
    void* ptr = malloc(size);
    JADE_ASSERT_MSG(ptr, "malloc failed %s:%d", file, line);
    return ptr;
}

static inline void* jade_calloc(const char* file, int line, size_t num, size_t size)
{
    void* ptr = calloc(num, size);
    JADE_ASSERT_MSG(ptr, "calloc failed %s:%d", file, line);
    return ptr;
}

#define JADE_MALLOC(size) jade_malloc(__FILE__, __LINE__, size)
#define JADE_CALLOC(num, size) jade_calloc(__FILE__, __LINE__, num, size)
#define JADE_MALLOC_PREFER_SPIRAM(size) malloc_prefer_spiram(__FILE__, __LINE__, size)
#define JADE_MALLOC_DRAM(size) malloc_dram(__FILE__, __LINE__, size)

#endif /* UTILS_MALLOC_EXT_H_ */
