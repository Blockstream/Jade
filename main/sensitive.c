#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "utils/malloc_ext.h"

#include <wally_crypto.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// Keep this size as small as possible for memory-constrained devices
#define SENS_STACK_SIZE 32
// Use index 1+ as 0 is reserved for pthread according to esp-idf documentation
#define TLS_INDEX_SENSITIVE 1

#if TLS_INDEX_SENSITIVE >= CONFIG_FREERTOS_THREAD_LOCAL_STORAGE_POINTERS
#error "Error, CONFIG_FREERTOS_THREAD_LOCAL_STORAGE_POINTERS should be increased"
#endif

struct sens_elem {
    const char* file;
    int line;
    void* addr;
    size_t size;
};

struct sens_stack {
    struct sens_elem* top;
    struct sens_elem elems[SENS_STACK_SIZE];
};

// Clear any items on the passed stack.
// Return true if any items present and needed clearing, false if stack already empty.
static bool sensitive_clear_stack_impl(struct sens_stack* stack)
{
    JADE_LOGD("sensitive_clear_stack_impl() called for stack pointer %p by task '%s'", stack, pcTaskGetTaskName(NULL));

    bool had_items = false;
    if (stack) {
        JADE_LOGD("sensitive_clear_stack_impl() stack->top = %p, stack->elems = %p", stack->top, stack->elems);
        while (stack->top > stack->elems) {
            stack->top--;
            JADE_LOGW("sensitive_clear_stack_impl() clearing %p %d bytes from %s:%d", stack->top->addr,
                stack->top->size, stack->top->file, stack->top->line);
            JADE_WALLY_VERIFY(wally_bzero(stack->top->addr, stack->top->size));
            had_items = true;
        }
    }
    return had_items;
}

static inline struct sens_stack* get_sens_stack(void)
{
    struct sens_stack* stack = pvTaskGetThreadLocalStoragePointer(NULL, TLS_INDEX_SENSITIVE);
    JADE_LOGD("get_sens_stack returned %p for task '%s'", stack, pcTaskGetTaskName(NULL));
    return stack;
}

// This callback appears to be called from the IDLE task, and *NOT* from the task
// that the callback was registered from.  Hence the use of 'sensitive_clear_stack_impl()'
// taking an explicit pointer, as the 'current tls pointer' would not be correct in this
// case (ie. would not be the same as 'ptr').
// NOTE: also avoided ASSERT or ABORT calls in this callback, as causing that kind of
// chaos in the system IDLE task would probably not go down well.
static void sensitive_delete_cb(int index, void* ptr)
{
    JADE_LOGI("sensitive_delete_cb() called for pointer %p (from tls index %d) by task '%s'", ptr, index,
        pcTaskGetTaskName(NULL));

    if (!ptr) {
        JADE_LOGE("sensitive_delete_cb() called with null ptr!  Doing nothing.");
        return;
    }

    if (index == TLS_INDEX_SENSITIVE) {
        sensitive_clear_stack_impl((struct sens_stack*)ptr);
    } else {
        JADE_LOGE("sensitive_delete_cb() called with index %u - Skipping call to clear stack!", index);
    }

    free(ptr);
}

void sensitive_init(void)
{
    struct sens_stack* stack = get_sens_stack();
    JADE_ASSERT_MSG(!stack, "sensitive_init() has been called multiple times for task '%s'", pcTaskGetTaskName(NULL));
    stack = JADE_MALLOC_PREFER_SPIRAM(sizeof(struct sens_stack));
    stack->top = stack->elems;
    JADE_LOGI("Setting sens stack tls pointer to %p for task '%s'", stack, pcTaskGetTaskName(NULL));
    vTaskSetThreadLocalStoragePointerAndDelCallback(NULL, TLS_INDEX_SENSITIVE, stack, &sensitive_delete_cb);
    JADE_ASSERT(get_sens_stack());
}

void sensitive_push(const char* file, int line, void* addr, size_t size)
{
    JADE_LOGD("sensitive_push  %s:%d %p %d bytes", file, line, addr, size);
    struct sens_stack* stack = get_sens_stack();
    JADE_ASSERT_MSG(stack, "sensitive_init() has not been called for task '%s'", pcTaskGetTaskName(NULL));

    stack->top->file = file;
    stack->top->line = line;
    stack->top->addr = addr;
    stack->top->size = size;

    stack->top++;
    JADE_ASSERT_MSG(stack->top < (stack->elems + sizeof(stack->elems) / sizeof(stack->elems[0])),
        "sensitive_push() exhausted sensitive stack");
}

void sensitive_pop(const char* file, int line, void* addr)
{
    JADE_LOGD("sensitive_pop  %s:%d %p", file, line, addr);
    struct sens_stack* stack = get_sens_stack();
    JADE_ASSERT_MSG(stack, "sensitive_init() has not been called for task '%s'", pcTaskGetTaskName(NULL));

    JADE_ASSERT(stack->top > stack->elems);
    stack->top--;
    JADE_WALLY_VERIFY(wally_bzero(stack->top->addr, stack->top->size));

    if (addr != stack->top->addr) {
        JADE_LOGE("sensitive_pop %s:%d unexpectedly popping addr %p", file, line, addr);
        JADE_LOGE("sensitive_pop expected addr %p (%d bytes pushed from %s:%d)", stack->top->addr, stack->top->size,
            stack->top->file, stack->top->line);
        JADE_ABORT();
    }
}

void sensitive_clear_stack(void)
{
    JADE_LOGI("sensitive_clear_stack() called for task '%s'", pcTaskGetTaskName(NULL));
    sensitive_clear_stack_impl(get_sens_stack());
}

void sensitive_assert_empty(void)
{
    JADE_LOGD("sensitive_assert_empty() called for task '%s'", pcTaskGetTaskName(NULL));
    if (sensitive_clear_stack_impl(get_sens_stack())) {
        JADE_LOGE("Sensitive stack not empty!");
        JADE_ABORT();
    }
}
