/*
 * SPDX-FileCopyrightText: 2017-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <string.h>

#include "sysinit/sysinit.h"
#include "syscfg/syscfg.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "services/hr/ble_svc_hr.h"

/* Characteristic values */
static uint8_t ble_svc_hr_measurement;
static uint16_t ble_svc_hr_body_sensor_loc;
static uint8_t ble_svc_hr_ctrl_pt;

/* Characteristic value handles */
static uint16_t ble_svc_hr_measurement_val_handle;
static uint16_t ble_svc_hr_body_sensor_loc_val_handle;
static uint16_t ble_svc_hr_ctrl_pt_val_handle;

static int ble_svc_hr_conn_handle[MYNEWT_VAL(BLE_MAX_CONNECTIONS) + 1];

static int
ble_svc_hr_access(uint16_t conn_handle, uint16_t attr_handle,
                  struct ble_gatt_access_ctxt *ctxt,
                  void *arg);
int ble_svc_hr_notify_measurement(void);
static int
ble_svc_hr_chr_write(struct os_mbuf *om, uint16_t min_len,
                     uint16_t max_len, void *dst,
                     uint16_t *len);

static const struct ble_gatt_svc_def ble_svc_hr_defs[] = {
    {
        /*** Heart Rate Measurement Service. */
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(BLE_SVC_HR_UUID16),
        .characteristics = (struct ble_gatt_chr_def[])
        { {
                /** Heart Rate Measurement
                 *
                 * This characteristic exposes heart rate measurement value
                 * by notifying.
                 */
                .uuid = BLE_UUID16_DECLARE(BLE_SVC_HR_CHR_UUID16_MEASUREMENT),
                .access_cb = ble_svc_hr_access,
                .val_handle = &ble_svc_hr_measurement_val_handle,
                .flags = BLE_GATT_CHR_F_NOTIFY,
            }, {
                /** Body Sensor Location
                 *
                 * This characteristic exposes information about
                 * the location of the heart rate measurement device.
                 */
                .uuid = BLE_UUID16_DECLARE(BLE_SVC_HR_CHR_UUID16_BODY_SENSOR_LOC),
                .access_cb = ble_svc_hr_access,
                .val_handle = &ble_svc_hr_body_sensor_loc_val_handle,
                .flags = BLE_GATT_CHR_F_READ,
            }, {
                /** Heart Rate Control Point
                 *
                 * This characteristic enable a Client to write control
                 * points to a Server to control behavior
                 */
                .uuid = BLE_UUID16_DECLARE(BLE_SVC_HR_CHR_UUID16_CTRL_PT),
                .access_cb = ble_svc_hr_access,
                .val_handle = &ble_svc_hr_ctrl_pt_val_handle,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE,
            }, {
                0, /* No more characteristics in this service. */
            }
        },
    },

    {
        0, /* No more services. */
    },
};

/**
 * HR access function
 */
static int
ble_svc_hr_access(uint16_t conn_handle, uint16_t attr_handle,
                  struct ble_gatt_access_ctxt *ctxt,
                  void *arg)
{
    uint16_t uuid16;
    int rc;

    uuid16 = ble_uuid_u16(ctxt->chr->uuid);
    assert(uuid16 != 0);

    switch (uuid16) {
    case BLE_SVC_HR_CHR_UUID16_MEASUREMENT:
        rc = ble_svc_hr_notify_measurement();
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;

    case BLE_SVC_HR_CHR_UUID16_BODY_SENSOR_LOC:
        assert(ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR);
        rc = os_mbuf_append(ctxt->om, &ble_svc_hr_body_sensor_loc,
                            sizeof(ble_svc_hr_body_sensor_loc));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;

    case BLE_SVC_HR_CHR_UUID16_CTRL_PT:
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
            rc = ble_svc_hr_chr_write(ctxt->om, 0, sizeof(ble_svc_hr_ctrl_pt),
                                      &ble_svc_hr_ctrl_pt,
                                      NULL);

            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        } else if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            rc = os_mbuf_append(ctxt->om, &ble_svc_hr_ctrl_pt,
                                sizeof(ble_svc_hr_ctrl_pt));
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        } else {
            return BLE_SVC_HS_ERR_CMD_NOT_SUPPORTED;
        }

    default:
        assert(0);
        return BLE_ATT_ERR_UNLIKELY;
    }
}

/**
 * This function must be called with the connection handle when a gap
 * connect event is received in order to send notifications to the
 * client.
 *
 * @params conn_handle          The connection handle for the current
 *                                  connection.
 */
void
ble_svc_hr_on_gap_connect(uint16_t conn_handle)
{
    ble_svc_hr_conn_handle[conn_handle] = conn_handle;
}

/**
* This function must be called with the connection handle when a gap
* disconnect event.
*
* @params conn_handle          The connection handle for the current
*                              disconnected event.
*/
void
ble_svc_hr_on_gap_disconnect(uint16_t conn_handle)
{
    ble_svc_hr_conn_handle[conn_handle] = -1;
}

/**
 * Send a notification for current heart rate measured.
 *
 * @return 0 on success, non-zero error code otherwise.
 */
int
ble_svc_hr_notify_measurement(void)
{
    int rc;
    struct os_mbuf *txom = NULL;

    for (int i = 0; i < MYNEWT_VAL(BLE_MAX_CONNECTIONS); i++) {
        if (ble_svc_hr_conn_handle[i] != -1) {

            txom = ble_hs_mbuf_from_flat(&ble_svc_hr_measurement,
                                         sizeof(ble_svc_hr_measurement));
            if (!txom) {
                return ESP_FAIL;
            }

            rc = ble_gatts_notify_custom(ble_svc_hr_conn_handle[i],
                                         ble_svc_hr_measurement_val_handle, txom);
            if (rc != 0) {
                return rc;
            }
        }
    }
    return 0;
}

/**
 * Writes the received value from a characteristic write to
 * the given destination.
 */
static int
ble_svc_hr_chr_write(struct os_mbuf *om, uint16_t min_len,
                     uint16_t max_len, void *dst,
                     uint16_t *len)
{
    uint16_t om_len;
    int rc;

    om_len = OS_MBUF_PKTLEN(om);
    if (om_len < min_len || om_len > max_len) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    rc = ble_hs_mbuf_to_flat(om, dst, max_len, len);
    if (rc != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    return 0;
}

void
ble_svc_hr_init(void)
{
    int rc;

    /* Ensure this function only gets called by sysinit. */
    SYSINIT_ASSERT_ACTIVE();

    rc = ble_gatts_count_cfg(ble_svc_hr_defs);
    SYSINIT_PANIC_ASSERT(rc == 0);

    rc = ble_gatts_add_svcs(ble_svc_hr_defs);
    SYSINIT_PANIC_ASSERT(rc == 0);

    ble_svc_hr_measurement = 0;

    /* Initializing connection handle array */
    for (int i = 0; i <= MYNEWT_VAL(BLE_MAX_CONNECTIONS); i++) {
        ble_svc_hr_conn_handle[i] = -1;
    }
}
