/*
 * SPDX-FileCopyrightText: 2017-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef H_BLE_SVC_PROX_
#define H_BLE_SVC_PROX_

struct ble_hs_cfg;

/* 16 Bit Proximity Sensor Service UUID */
#define BLE_SVC_IMMEDIATE_ALERT_UUID16                      0x1802
#define BLE_SVC_LINK_LOSS_UUID16                            0x1803
#define BLE_SVC_TX_POWER_UUID16                             0x1804

/* 16 Bit Proximity Sensor Service Characteristic UUIDs */
#define BLE_SVC_PROX_CHR_UUID16_ALERT_LVL                   0x2A06
#define BLE_SVC_PROX_CHR_UUID16_TX_PWR_LVL                  0x2A07

/* 16 Bit Proximity Sensor Service Descriptors UUIDs */
#define BLE_SVC_PROX_DSC_UUID16_PRSNTN_FORMAT               0x2904

/* Error Definitions */
#define BLE_SVC_HS_ERR_CMD_NOT_SUPPORTED                    0x80

/**
 * @brief  Initializes proximity service.
 */
void ble_svc_prox_init(void);

#endif
