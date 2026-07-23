#ifndef _LIBJADE_FREERTOS_IDF_ADDITIONS_H
#define _LIBJADE_FREERTOS_IDF_ADDITIONS_H 1

#include <freertos/task.h>

BaseType_t xTaskCreatePinnedToCoreWithCaps(TaskFunction_t func, const char* const name, uint32_t stack_size,
    void* const params, UBaseType_t ux_prio, TaskHandle_t* const output, const BaseType_t xCoreID,
    UBaseType_t uxMemoryCaps);

#endif // _LIBJADE_FREERTOS_IDF_ADDITIONS_H
