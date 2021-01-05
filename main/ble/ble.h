#ifndef BLE_H_
#define BLE_H_

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdbool.h>

bool ble_init(TaskHandle_t* ble_handle);

bool ble_enabled();
bool ble_connected();

void ble_start();
void ble_stop();

void ble_start_advertising();
void ble_stop_advertising();

int ble_get_mac(char* mac, size_t length);

bool ble_remove_all_devices();

#endif /* BLE_H_ */
