#ifndef BLE_H_
#define BLE_H_

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdbool.h>

bool ble_init(TaskHandle_t* ble_handle);

bool ble_enabled(void);
bool ble_connected(void);

void ble_start(void);
void ble_stop(void);

bool ble_remove_all_devices(void);

#endif /* BLE_H_ */
