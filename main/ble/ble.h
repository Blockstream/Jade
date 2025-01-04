#ifndef BLE_H_
#define BLE_H_

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdbool.h>

#ifdef CONFIG_BT_ENABLED
bool ble_init(TaskHandle_t* ble_handle);

bool ble_enabled(void);
bool ble_connected(void);

void ble_start(void);
void ble_stop(void);

bool ble_remove_all_devices(void);

#else /* CONFIG_BT_ENABLED */

/* Provide stub implementations to simplify calling code */

#include "../jade_assert.h"

static inline bool ble_init(TaskHandle_t* ble_handle) { return false; }

static inline bool ble_enabled(void) { return false; }
static inline bool ble_connected(void) { return false; }

static inline void ble_start(void) { JADE_ASSERT(false); }
static inline void ble_stop(void) { return; }

static inline bool ble_remove_all_devices(void) { JADE_ASSERT(false); }
#endif /* CONFIG_BT_ENABLED */

#endif /* BLE_H_ */
