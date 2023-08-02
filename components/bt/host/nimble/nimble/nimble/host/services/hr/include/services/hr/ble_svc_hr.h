/*
 * SPDX-FileCopyrightText: 2017-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef H_BLE_SVC_HR_
#define H_BLE_SVC_HR_

struct ble_hs_cfg;

/* 16 Bit Heart Rate Service UUID */
#define BLE_SVC_HR_UUID16                                   0x180D

/* 16 Bit Heart Rate Service Characteristic UUIDs */
#define BLE_SVC_HR_CHR_UUID16_MEASUREMENT                   0x2A37
#define BLE_SVC_HR_CHR_UUID16_BODY_SENSOR_LOC               0x2A38
#define BLE_SVC_HR_CHR_UUID16_CTRL_PT                       0x2A39

/* Error Definitions */
#define BLE_SVC_HS_ERR_CMD_NOT_SUPPORTED                    0x80

void ble_svc_hr_on_gap_connect(uint16_t conn_handle);

void ble_svc_hr_on_gap_disconnect(uint16_t conn_handle);

void ble_svc_hr_init(void);

#endif
