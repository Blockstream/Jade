/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#ifndef H_BLE_ESP_HS_
#define H_BLE_ESP_HS_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Deinitializes the NimBLE host. This function must be called after the
 * NimBLE host stop procedure is complete.
 */
void ble_hs_deinit(void);

#ifdef __cplusplus
}
#endif

#endif
