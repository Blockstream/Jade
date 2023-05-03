#include "temporary_stack.h"
#include "jade_assert.h"

#include <esp_expression_with_stack.h>
#include <utils/malloc_ext.h>

// Helper to run function which may require a large amount of stack space on a temporary stack.
// The esp-idf callback meachanism doesn't pass a (void* ctx) or similar, so we have to pass data in
// static variables.  Horrible, so we wrap it here to hide that and provide the preferred interface.
// Function protected by a mutex so can only be running once (protects statics used, and also prevents
// excessive memory allocation of multiple large stacks).
static SemaphoreHandle_t overall_mutex = NULL;
static SemaphoreHandle_t stack_mutex = NULL;
static temporary_stack_function_t s_fn = NULL;
static void* s_ctx = NULL;
static bool s_rslt = false;

void temp_stack_init(void)
{
    // Create the necessary mutexes
    overall_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(overall_mutex);
    stack_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(stack_mutex);
}

// Convert the esp-idf 'void f(void)' signature into a more user-friendly 'bool f(void* ctx)'
static void fn_wrapper(void)
{
    JADE_ASSERT(s_fn);
    s_rslt = s_fn(s_ctx);
    JADE_LOGI("Temporary stack HWM: %u free", uxTaskGetStackHighWaterMark(NULL));
}

bool run_on_temporary_stack(const size_t stack_size, temporary_stack_function_t fn, void* ctx)
{
    JADE_ASSERT(stack_size >= CONFIG_ESP_MINIMAL_SHARED_STACK_SIZE);
    JADE_ASSERT(fn);
    // ctx is optional

    // Take the overall mutex and set the static variables
    while (xSemaphoreTake(overall_mutex, portMAX_DELAY) != pdTRUE) {
        // wait for mutex
    }

    s_fn = fn;
    s_ctx = ctx;
    s_rslt = false;

    // Allocate temporary stack
    uint8_t* const temporary_stack = JADE_MALLOC(stack_size);

    // Run the wrapping function on the temporary stack.
    // It will invoke the user-supplied function with the passed context argument
    esp_execute_shared_stack_function(stack_mutex, temporary_stack, stack_size, fn_wrapper);
    const bool rslt = s_rslt;

    // Reset the static variables
    s_fn = NULL;
    s_ctx = NULL;
    s_rslt = false;

    // Free temporary stack and return overall mutex
    free(temporary_stack);
    xSemaphoreGive(overall_mutex);

    // Return the boolean result - any other output info should be in the ctx object
    return rslt;
}