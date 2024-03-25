#include "temporary_stack.h"
#include "jade_assert.h"
#include "jade_tasks.h"

#include <esp_expression_with_stack.h>
#include <freertos/idf_additions.h>
#include <utils/malloc_ext.h>

// Helper to run function which may require a large amount of stack space on a temporary stack or in
// a temporary task.
// The esp-idf callback meachanism doesn't pass a (void* ctx) or similar, so we have to pass data in
// static variables.  Horrible, so we wrap it here to hide that and provide the preferred interface.
// Function protected by a mutex so can only be running once (protects statics used, and also prevents
// excessive memory allocation of multiple large stacks).
static SemaphoreHandle_t overall_mutex = NULL;
static SemaphoreHandle_t stack_mutex = NULL;
static SemaphoreHandle_t task_semaphore = NULL;
static temporary_stack_function_t s_fn = NULL;
static void* s_ctx = NULL;
static bool s_rslt = false;

void temp_stack_init(void)
{
    // Create the necessary mutexes and semaphores
    overall_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(overall_mutex);
    stack_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(stack_mutex);
    task_semaphore = xSemaphoreCreateBinary();
    JADE_ASSERT(task_semaphore);
}

// Convert the esp-idf 'void f(void)' signature into a more user-friendly 'bool f(void* ctx)'
static void temp_stack_wrapper(void)
{
    JADE_ASSERT(s_fn);
    s_rslt = s_fn(s_ctx);
    JADE_LOGI("Temporary stack HWM: %u free", uxTaskGetStackHighWaterMark(NULL));
}

// Temporarily switch the stack of the current task for a (presumably larger) stack to run the passed function
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
    JADE_LOGI("Using temporary stack of size: %u", stack_size);
#ifdef CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY
    uint8_t* const temporary_stack = JADE_MALLOC_PREFER_SPIRAM(stack_size);
#else
    uint8_t* const temporary_stack = JADE_MALLOC_DRAM(stack_size);
#endif

    // Run the wrapping function on the temporary stack.
    // It will invoke the user-supplied function with the passed context argument
    esp_execute_shared_stack_function(stack_mutex, temporary_stack, stack_size, temp_stack_wrapper);
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

static void temp_task_wrapper(void* ctx)
{
    JADE_ASSERT(s_fn);
    JADE_ASSERT(ctx == s_ctx);

    // Run the passed function, then signal the completion semaphore
    s_rslt = s_fn(s_ctx);
    JADE_LOGI("Temporary task stack HWM: %u free", uxTaskGetStackHighWaterMark(NULL));
    xSemaphoreGive(task_semaphore);

    // Await death
    for (;;) {
        vTaskDelay(portMAX_DELAY);
    }
}

// Run the passed function in an entirely new (short lived) task with the given stack size
bool run_in_temporary_task(const size_t stack_size, temporary_stack_function_t fn, void* ctx)
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

    // Run the temporary task
    JADE_LOGI("Using temporary task with stack of size: %u", stack_size);
#ifdef CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY
    const UBaseType_t mem_caps = MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM;
#else
    const UBaseType_t mem_caps = MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL;
#endif

    TaskHandle_t temporary_task;
    const BaseType_t retval = xTaskCreatePinnedToCoreWithCaps(&temp_task_wrapper, "temporary_task", stack_size, ctx,
        JADE_TASK_PRIO_TEMPORARY, &temporary_task, JADE_CORE_SECONDARY, mem_caps);
    JADE_ASSERT_MSG(retval == pdPASS, "Failed to create temporary task, xTaskCreatePinnedToCore() returned %d", retval);

    // Wait for the task to flag completion and copy the result
    while (xSemaphoreTake(task_semaphore, portMAX_DELAY) != pdTRUE) {
        // wait for mutex
    }
    const bool rslt = s_rslt;

    // Reset the static variables
    s_fn = NULL;
    s_ctx = NULL;
    s_rslt = false;

    // Kill the task and return overall mutex
    vTaskDeleteWithCaps(temporary_task);
    xSemaphoreGive(overall_mutex);

    // Return the boolean result - any other output info should be in the ctx object
    return rslt;
}
