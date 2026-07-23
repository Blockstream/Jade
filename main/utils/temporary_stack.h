#include <stdbool.h>
#include <stddef.h>

#include "jade_assert.h"

// Helper to run function which may require a larger temporary stack.
// Function should take an optional void* context, and return bool.
typedef bool (*temporary_stack_function_t)(void*);

// Run the passed function in an entirely new (short lived) task with the given stack size.
// The task must run without pausing and without user interaction or it will time out.
WARN_UNUSED_RESULT bool run_in_temporary_task(const size_t stack_size, temporary_stack_function_t fn, void* ctx);

void temp_stack_init(void);
