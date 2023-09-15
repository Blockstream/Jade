#ifndef SERIAL_H_
#define SERIAL_H_

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdbool.h>

bool serial_init(TaskHandle_t* serial_handle);
bool serial_enabled(void);
void serial_start(void);
void serial_stop(void);

#endif /* SERIAL_H_ */
