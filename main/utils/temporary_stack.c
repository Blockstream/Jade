#ifndef AMALGAMATED_BUILD
#include "temporary_stack.h"
#include "jade_assert.h"
#include "jade_tasks.h"

#include <freertos/idf_additions.h>
#include <utils/malloc_ext.h>

#ifndef CONFIG_ESP_MINIMAL_SHARED_STACK_SIZE
#define CONFIG_ESP_MINIMAL_SHARED_STACK_SIZE 2048
#endif

// Helper to run function which may require a larger amount of stack space in a temporary task.
// Function protected by a mutex so can only be running once (prevents excessive memory
// allocation of multiple large stacks).
static SemaphoreHandle_t overall_mutex = NULL;

// Struct to pass function, context, result and synchronisation to the temporary task
typedef struct {
    temporary_stack_function_t fn;
    void* ctx;
    bool rslt;
    SemaphoreHandle_t semaphore;
} temp_task_args_t;

void temp_stack_init(void)
{
    // Create the necessary mutex
    overall_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(overall_mutex);
}

static void temp_task_wrapper(void* ctx)
{
    temp_task_args_t* args = (temp_task_args_t*)ctx;
    JADE_ASSERT(args && args->fn);

    // Run the passed function, then signal the completion semaphore
    args->rslt = args->fn(args->ctx);
    JADE_LOGI("Temporary task stack HWM: %u free", uxTaskGetStackHighWaterMark(NULL));
    xSemaphoreGive(args->semaphore);

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

    // Create a fresh semaphore for this call to avoid cross-call contamination
    // from a late semaphore-give by a previous timed-out temporary task.
    SemaphoreHandle_t task_semaphore = xSemaphoreCreateBinary();
    JADE_ASSERT(task_semaphore);

    // Allocate args struct to pass function, context, result and semaphore to the temporary task
    temp_task_args_t* args = JADE_MALLOC_DRAM(sizeof(temp_task_args_t));
    args->fn = fn;
    args->ctx = ctx;
    args->rslt = false;
    args->semaphore = task_semaphore;

    // Take the overall mutex to prevent re-entrancy
    while (xSemaphoreTake(overall_mutex, portMAX_DELAY) != pdTRUE) {
        // wait for mutex
    }

    // Run the temporary task
    JADE_LOGI("Using temporary task with stack of size: %u", stack_size);
#ifdef CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM
    const UBaseType_t mem_caps = MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM;
#else
    const UBaseType_t mem_caps = MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL;
#endif

    // Pin the temporary task to the same core as the caller.
    // The caller is suspended waiting for the semaphore anyway, so using the
    // same core avoids cross-core task deletion concerns
    TaskHandle_t temporary_task;
    const BaseType_t retval = xTaskCreatePinnedToCoreWithCaps(&temp_task_wrapper, "temporary_task", stack_size, args,
        JADE_TASK_PRIO_TEMPORARY, &temporary_task, xPortGetCoreID(), mem_caps);
    JADE_ASSERT_MSG(retval == pdPASS, "Failed to create temporary task, xTaskCreatePinnedToCore() returned %d", retval);

    // Wait for the task to flag completion and copy the result.
    // Use a timeout to avoid deadlocking if the temporary task hangs/crashes.
#ifdef CONFIG_ETH_USE_OPENETH
    const TickType_t timeout_ms = 300000 / portTICK_PERIOD_MS; // 5 minutes for QEMU
#else
    const TickType_t timeout_ms = 30000 / portTICK_PERIOD_MS; // 30 seconds for real hardware
#endif
    if (xSemaphoreTake(task_semaphore, timeout_ms) != pdTRUE) {
        JADE_LOGE("Temporary task %p timed out - task appears to have hung or crashed", (void*)temporary_task);
        args->rslt = false;
    }
    const bool rslt = args->rslt;

    // Kill the task, return overall mutex, destroy the semaphore and free args.
    vTaskDeleteWithCaps(temporary_task);
    xSemaphoreGive(overall_mutex);
    vSemaphoreDelete(task_semaphore);
    free(args);

    // Return the boolean result - any other output info should be in the ctx object
    return rslt;
}
#endif // AMALGAMATED_BUILD
