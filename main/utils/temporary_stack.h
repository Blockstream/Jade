#include <stdbool.h>
#include <stddef.h>

// Helper to run function which may require a large stack on a temporary stack.
// Funciton should take an optional void* context, and return bool.
// (ie. 'bool f(void* ctx)' - more user friendly that the underlying 'void f(void)')
typedef bool (*temporary_stack_function_t)(void*);

// Temporarily switch the stack of the current task for a (presumably larger) stack to run the passed function
bool run_on_temporary_stack(size_t stack_size, temporary_stack_function_t fn, void* ctx);

// Run the passed function in an entirely new (short lived) task with the given stack size
bool run_in_temporary_task(const size_t stack_size, temporary_stack_function_t fn, void* ctx);

void temp_stack_init(void);
