#define _GNU_SOURCE 1 // For extra pthread functions
#include "freertos/timecvt.h"
#include "jade_assert.h"
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

// Per-thread condition variable for portMAX_DELAY waits, stored in TLS.

static void _task_cond_free(void* p)
{
    pthread_cond_destroy((pthread_cond_t*)p);
    free(p);
}

static pthread_key_t _task_cond_key;
static pthread_once_t _task_cond_key_once = PTHREAD_ONCE_INIT;
static void _task_cond_key_init(void) { pthread_key_create(&_task_cond_key, _task_cond_free); }

static pthread_cond_t* _get_task_cond(void)
{
    pthread_once(&_task_cond_key_once, _task_cond_key_init);
    pthread_cond_t* c = pthread_getspecific(_task_cond_key);
    if (!c) {
        c = malloc(sizeof(pthread_cond_t));
        JADE_ASSERT(c);
        pthread_cond_init(c, NULL);
        pthread_setspecific(_task_cond_key, c);
    }
    return c;
}

#define MAX_WAITERS 32
static pthread_mutex_t _waiter_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct {
    pthread_t tid;
    pthread_cond_t* cond;
} _waiters[MAX_WAITERS];
static size_t _waiter_count = 0;

// HW: TLS/Sensitive
static void* _tls_ptrs[3];

void* pvTaskGetThreadLocalStoragePointer(void* task, size_t idx)
{
    JADE_ASSERT(idx <= sizeof(_tls_ptrs) / sizeof(_tls_ptrs[0]));
    return _tls_ptrs[idx];
}

void vTaskSetThreadLocalStoragePointerAndDelCallback(void* task, size_t idx, void* p, TlsDeleteCallbackFunction_t cb)
{
    JADE_ASSERT(idx <= sizeof(_tls_ptrs) / sizeof(_tls_ptrs[0]));
    _tls_ptrs[idx] = p;
    // FIXME: call cb atexit()/thread exit?
}

const char* pcTaskGetName(void* task)
{
    JADE_ASSERT(task == NULL); // Only ever called for the current task
#if 0
    // TODO: Implement if desired - only used for logging ATM
    char name[32];
    pthread_t thread_id = (pthread_t)task;
    JADE_ASSERT(pthread_getname_np(thread_id, name, sizeof(name)) == 0);
    return name;
#endif
    return "dummy";
}

TaskHandle_t xTaskGetCurrentTaskHandle(void) { return (TaskHandle_t)pthread_self(); }

typedef struct {
    TaskFunction_t func;
    void* arg;
} pthread_shim_args_t;

void* pthread_shim_func(void* arg)
{
    pthread_shim_args_t* args = (pthread_shim_args_t*)arg;
    TaskFunction_t func = args->func;
    void* func_arg = args->arg;
    free(args);
    func(func_arg);
    return NULL;
}

BaseType_t xTaskCreatePinnedToCore(TaskFunction_t func, const char* name, uint32_t stack_size, void* params,
    uint32_t ux_prio, TaskHandle_t* output, uint32_t xCoreID)
{
    BaseType_t result = pdTRUE;
    pthread_attr_t attr = { 0 };
    pthread_t thread_id = 0;
    *output = NULL;
    if (pthread_attr_init(&attr) != 0) {
        JADE_LOGE("pthread_attr_init failed for task %s", name);
        return pdFALSE;
    }
    if (stack_size < PTHREAD_STACK_MIN) {
        stack_size = PTHREAD_STACK_MIN;
    }
    if (strcmp(name, "jade_camera") == 0) {
        // give the camera thread more stack
        stack_size *= 2;
    }
    if (pthread_attr_setstacksize(&attr, stack_size) != 0) {
        JADE_LOGE("pthread_attr_setstacksize failed for task %s", name);
        result = pdFALSE;
        goto cleanup;
    }
    JADE_LOGI("creating pthread shim args");
    pthread_shim_args_t* shim_args = malloc(sizeof(pthread_shim_args_t));
    JADE_ASSERT(shim_args);
    shim_args->func = func;
    shim_args->arg = params;
    JADE_LOGI("calling pthread_create");
    if (pthread_create(&thread_id, &attr, pthread_shim_func, shim_args) != 0) {
        free(shim_args);
        JADE_LOGE("pthread_create failed for task %s", name);
        result = pdFALSE;
        goto cleanup;
    }
    *output = (TaskHandle_t)thread_id;
    if (pthread_setname_np(thread_id, name) != 0) {
        JADE_LOGE("pthread_setname_np failed for task %s", name);
        result = pdFALSE;
        goto cleanup;
    }
cleanup:
    if (thread_id != 0) {
        pthread_attr_destroy(&attr);
    }
    if (result != pdTRUE && thread_id != 0) {
        pthread_kill(thread_id, SIGTERM);
        *output = NULL;
    }
    return result;
}

BaseType_t xTaskCreatePinnedToCoreWithCaps(TaskFunction_t func, const char* const name, uint32_t stack_size,
    void* const params, UBaseType_t ux_prio, TaskHandle_t* const output, const BaseType_t xCoreID,
    UBaseType_t uxMemoryCaps)
{
    // We ignore the memory caps
    return xTaskCreatePinnedToCore(func, name, stack_size, params, ux_prio, output, xCoreID);
}

unsigned int uxTaskPriorityGet(void* task) { return 0; }

unsigned int uxTaskGetStackHighWaterMark(void* task) { return 0xffffff; }

unsigned int xPortGetCoreID(void) { return 0; }

unsigned int xPortGetFreeHeapSize(void) { return 0xffffff; }

void vTaskDelay(TickType_t delay)
{
    // if portMAX_DELAY we will make the thread listen for a signal to exit instead of sleeping,
    if (delay == portMAX_DELAY) {
        pthread_cond_t* cond = _get_task_cond();
        const pthread_t self = pthread_self();
        pthread_mutex_lock(&_waiter_mutex);
        JADE_ASSERT(_waiter_count < MAX_WAITERS);
        _waiters[_waiter_count].tid = self;
        _waiters[_waiter_count].cond = cond;
        _waiter_count++;
        pthread_cond_wait(cond, &_waiter_mutex);
        // remove self from registry
        for (size_t i = 0; i < _waiter_count; i++) {
            if (pthread_equal(_waiters[i].tid, self)) {
                _waiters[i] = _waiters[--_waiter_count];
                break;
            }
        }
        pthread_mutex_unlock(&_waiter_mutex);
        // jade often uses vTaskDelay(portMAX_DELAY) in a loop so we need to exit the thread here
        pthread_exit(NULL);
        return;
    }
    // otherwise sleep as normal
    struct timespec ts = timespec_from_ticktype(delay);
    nanosleep(&ts, NULL);
}

void vTaskDelayUntil(TickType_t* prev_wake_time, const TickType_t delay)
{
    // Only used by the GUI main loop
    TickType_t current_time = xTaskGetTickCount();
    if (*prev_wake_time + delay > current_time) {
        vTaskDelay(*prev_wake_time + delay - current_time);
    }
    *prev_wake_time += delay;
}

void vTaskDelete(void* task)
{
    // if deleting the current task we can just use pthread_exit.
    // pthread_exit() cannot be used to terminate another thread (like vTaskDelete can),
    // so if task != current we have to use cooperation with the other thread to signal it to exit.
    if (task == NULL) {
        pthread_exit(NULL);
    } else {
        pthread_mutex_lock(&_waiter_mutex);
        for (size_t i = 0; i < _waiter_count; i++) {
            if (pthread_equal(_waiters[i].tid, (pthread_t)task)) {
                pthread_cond_signal(_waiters[i].cond);
                break;
            }
        }
        pthread_mutex_unlock(&_waiter_mutex);
    }
}

void vTaskDeleteWithCaps(void* task) { vTaskDelete(task); }

TickType_t xTaskGetTickCount(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        abort();
    }
    return ((TickType_t)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

int xTaskNotify(TaskHandle_t task, unsigned int v, int action)
{
    // FIXME: Implement?
    JADE_ASSERT(action == eNoAction);
    return pdTRUE;
}
