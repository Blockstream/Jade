#include "jade_assert.h"
#include "jade_log.h"
#include "utils/malloc_ext.h"

#include <wally_crypto.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// Keep this size as small as possible for memory-constrained devices
#define SENS_STACK_SIZE 32
#define TLS_INDEX 0

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

void sensitive_init(void)
{
    struct sens_stack* stack = JADE_MALLOC_PREFER_SPIRAM(sizeof(struct sens_stack));
    stack->top = stack->elems;
    JADE_LOGI("Setting sens stack tls pointer to %p for task '%s'", stack, pcTaskGetTaskName(NULL));
    vTaskSetThreadLocalStoragePointer(NULL, TLS_INDEX, stack);
}

static inline struct sens_stack* get_sens_stack(void)
{
    struct sens_stack* stack = pvTaskGetThreadLocalStoragePointer(NULL, TLS_INDEX);
    JADE_LOGD("get_sens_stack returned %p for task '%s'", stack, pcTaskGetTaskName(NULL));
    return stack;
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
    wally_bzero(stack->top->addr, stack->top->size);

    if (addr != stack->top->addr) {
        JADE_LOGE("sensitive_pop %s:%d unexpectedly popping addr %p", file, line, addr);
        JADE_LOGE("sensitive_pop expected addr %p (%d bytes pushed from %s:%d)", stack->top->addr, stack->top->size,
            stack->top->file, stack->top->line);
        JADE_ABORT();
    }
}

void sensitive_clear_stack(void)
{
    JADE_LOGD("sensitive_clear_stack()");
    struct sens_stack* stack = get_sens_stack();
    if (stack) {
        while (stack->top > stack->elems) {
            stack->top--;
            JADE_LOGD("sensitive_clear_stack clearing %d bytes at addr %p", stack->top->size, stack->top->addr);
            wally_bzero(stack->top->addr, stack->top->size);
        }
    }

    // Free the stack structure
    JADE_LOGI("Freeing sens stack tls pointer %p for task '%s'", stack, pcTaskGetTaskName(NULL));
    vTaskSetThreadLocalStoragePointer(NULL, TLS_INDEX, NULL);
    free(stack);
}

void sensitive_assert_empty(void)
{
    JADE_LOGD("sensitive_assert_empty()");
    struct sens_stack* stack = get_sens_stack();
    if (stack) {
        JADE_LOGD("sensitive_assert_empty() stack->top = %p, stack->elems = %p", stack->top, stack->elems);
        if (stack->top > stack->elems) {
            JADE_LOGE("sensitive stack not empty:");
            struct sens_elem* top = stack->top;
            while (top > stack->elems) {
                top--;
                JADE_LOGE("  %s:%d %p %d bytes", top->file, top->line, top->addr, top->size);
            }

            // JADE_ABORT will call sensitive_clear_stack before aborting
            JADE_ABORT();
        }
    }
}
