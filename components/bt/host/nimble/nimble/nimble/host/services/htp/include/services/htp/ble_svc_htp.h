/*
 * SPDX-FileCopyrightText: 2017-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef H_BLE_SVC_HTP_
#define H_BLE_SVC_HTP_

struct ble_hs_cfg;

/* 16 Bit Health Thermometer Service UUID */
#define BLE_SVC_HTP_UUID16                                   0x1809

/* 16 Bit Health Thermometer Service Characteristic UUIDs */
#define BLE_SVC_HTP_CHR_UUID16_TEMP_MEASUREMENT              0x2A1C
#define BLE_SVC_HTP_CHR_UUID16_TEMP_TYPE                     0x2A1D
#define BLE_SVC_HTP_CHR_UUID16_INTERMEDIATE_TEMP             0x2A1E
#define BLE_SVC_HTP_CHR_UUID16_MEASUREMENT_ITVL              0x2A21

/* 16 Bit Health Thermometer Service Descriptor UUID */
#define BLE_SVC_HTP_DSC_UUID16_VALID_RANGE                   0x2906

/* Error Definitions */
#define BLE_SVC_HS_ERR_OUT_OF_RANGE                          0x80

enum chr_subs {
    TEMP_MEASUREMENT,
    INTERMEDIATE_TEMP,
    MEASUREMENT_ITVL,
};

/* Stores if characteristic is subscribed or not of a particular connection handle */
struct chr_subscribe {
    bool chr_subs[3];
};

void ble_svc_htp_on_disconnect(uint16_t conn_handle);

bool ble_svc_htp_is_subscribed(uint16_t conn_handle, int chr);

void ble_svc_htp_subscribe(uint16_t conn_handle, uint16_t attr_handle);

int ble_svc_htp_indicate(uint16_t conn_handle, float temp, bool temp_unit);

int ble_svc_htp_notify(uint16_t conn_handle, float temp, bool temp_unit);

void ble_svc_htp_init(void);

#endif
