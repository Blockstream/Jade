#ifndef SERIAL_H_
#define SERIAL_H_

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdbool.h>

bool serial_init(TaskHandle_t* serial_handle);

#endif /* SERIAL_H_ */
