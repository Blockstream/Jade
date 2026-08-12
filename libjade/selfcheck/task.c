#include "selfcheck.h"

#include "jade_assert.h"
#include "jade_log.h"

#include "utils/temporary_stack.h"

#include <freertos/task.h>
#include <string.h>

#ifndef CONFIG_ESP_MINIMAL_SHARED_STACK_SIZE
#define CONFIG_ESP_MINIMAL_SHARED_STACK_SIZE 2048
#endif

#define STRESS_TEST_STACK_VARIANTS 5

typedef struct {
    size_t counter;
    size_t stack_size;
} stress_test_ctx_t;

static bool stress_test_workload_fn(void* ctx)
{
    stress_test_ctx_t* stress_ctx = (stress_test_ctx_t*)ctx;
    JADE_ASSERT(stress_ctx);

    // consume some stack space
    volatile char stack_burn[512];
    memset((void*)stack_burn, 0xAA, sizeof(stack_burn));

    // small amount of work
    for (volatile size_t i = 0; i < 1000; i++) {
        stack_burn[i % sizeof(stack_burn)] = (char)(i & 0xFF);
    }

    // increment the counter
    stress_ctx->counter++;

    // recurse if we have enough stack space left to do so
    const size_t stack_use = sizeof(stack_burn) + 256; // add extra for stack frame etc
    stress_ctx->stack_size -= stack_use;
    if (stack_use < stress_ctx->stack_size) {
        return stress_test_workload_fn(ctx);
    }

    return true;
}

static bool run_temporary_stack_stress_test(const size_t iterations, const size_t base_stack_size)
{
    JADE_ASSERT(iterations > 0);
    JADE_ASSERT(base_stack_size >= CONFIG_ESP_MINIMAL_SHARED_STACK_SIZE);

    JADE_LOGI("=== Temporary Stack Stress Test ===");
    JADE_LOGI("Running on core: %u", xPortGetCoreID());
    JADE_LOGI("Iterations: %u", iterations);
    JADE_LOGI("Base stack size: %u", base_stack_size);

    // stack sizes to cycle through:
    // base, base*2, base*4, base*8, base*16
    const size_t stack_sizes[STRESS_TEST_STACK_VARIANTS] = {
        base_stack_size,
        base_stack_size * 2,
        base_stack_size * 4,
        base_stack_size * 8,
        base_stack_size * 16,
    };

    size_t success_count = 0;
    size_t failure_count = 0;
    size_t counter = 0;

    const TickType_t start_ticks = xTaskGetTickCount();

    for (size_t i = 0; i < iterations; i++) {
        // cycle through different stack sizes
        const size_t stack_size = stack_sizes[i % STRESS_TEST_STACK_VARIANTS];

        stress_test_ctx_t stress_ctx = {
            .counter = counter,
            .stack_size = stack_size,
        };
        const bool rslt = run_in_temporary_task(stack_size, stress_test_workload_fn, &stress_ctx);
        counter = stress_ctx.counter;

        if (rslt) {
            success_count++;
        } else {
            failure_count++;
            JADE_LOGW("Stress test iteration %u failed (stack_size=%u)", i, stack_size);
        }

        // yield to allow idle task to clean up deleted tasks
        vTaskDelay(1);

        // progress log every 100 iterations
        if ((i + 1) % 100 == 0) {
            JADE_LOGI("Stress test progress: %u/%u iterations (success: %u, fail: %u)", i + 1, iterations,
                success_count, failure_count);
        }
    }

    const TickType_t elapsed_ticks = xTaskGetTickCount() - start_ticks;
    const uint32_t elapsed_ms = elapsed_ticks * portTICK_PERIOD_MS;

    JADE_LOGI("=== Stress Test Complete ===");
    JADE_LOGI("Total iterations: %u", iterations);
    JADE_LOGI("Success: %u, Failure: %u", success_count, failure_count);
    JADE_LOGI("Counter (should equal success): %u", counter);
    JADE_LOGI("Elapsed time: %u ms", elapsed_ms);
    JADE_LOGI("Free heap: %u", xPortGetFreeHeapSize());
    JADE_LOGI("Main task stack HWM: %u free", uxTaskGetStackHighWaterMark(NULL));

    return failure_count == 0;
}

bool debug_selfcheck(jade_process_t* process)
{
    (void)process;

    // Stress test the temporary-task code
    if (!run_temporary_stack_stress_test(50, 2048)) {
        FAIL();
    }

    return true;
}
