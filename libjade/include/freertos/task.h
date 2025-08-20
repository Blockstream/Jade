#ifndef _LIBJADE_FREERTOS_TASK_H
#define _LIBJADE_FREERTOS_TASK_H 1

#include <freertos/projdefs.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t BaseType_t; // Probably belongs elsewhere

typedef void* TaskHandle_t;
typedef void (*TaskFunction_t)(void* arg);

#define tskIDLE_PRIORITY 1

typedef unsigned long long TickType_t;

typedef void (*TlsDeleteCallbackFunction_t)(int idx, void* p);

void* pvTaskGetThreadLocalStoragePointer(void* task, size_t idx);

void vTaskSetThreadLocalStoragePointerAndDelCallback(void* task, size_t idx, void* p, TlsDeleteCallbackFunction_t cb);

const char* pcTaskGetName(void* task);

TaskHandle_t xTaskGetCurrentTaskHandle(void) { return NULL; }

BaseType_t xTaskCreatePinnedToCore(TaskFunction_t func, const char* name, uint32_t stack_size, void* params,
    uint32_t ux_prio, TaskHandle_t* output, uint32_t xCoreID);

unsigned int uxTaskPriorityGet(void* task) { return 0; }
unsigned int uxTaskGetStackHighWaterMark(void* task);

unsigned int xPortGetCoreID(void) { return 0; }
unsigned int xPortGetFreeHeapSize(void);

#define portTICK_PERIOD_MS 1
void vTaskDelay(TickType_t delay);
void vTaskDelayUntil(TickType_t* prev_wake_time, const TickType_t delay);
void vTaskDelete(void* task);
TickType_t xTaskGetTickCount(void);

#define eNoAction 0

int xTaskNotify(TaskHandle_t task, unsigned int v, int action);

#endif // _LIBJADE_FREERTOS_TASK_H
