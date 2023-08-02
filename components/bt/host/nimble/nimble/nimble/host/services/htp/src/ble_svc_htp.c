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
#include "services/htp/ble_svc_htp.h"

/* Characteristic values */
static uint16_t ble_svc_htp_temp_type;
static uint16_t ble_svc_htp_temp_msr_itvl;

/* Health thermometer characteristic value handles */
static uint16_t ble_svc_htp_temp_measurement_val_handle;
static uint16_t ble_svc_htp_temp_type_val_handle;
static uint16_t ble_svc_htp_intr_temp_val_handle;
static uint16_t ble_svc_htp_msr_itvl_val_handle;

static struct chr_subscribe conn_chr_subs[MYNEWT_VAL(BLE_MAX_CONNECTIONS) + 1];

static int
ble_svc_htp_access(uint16_t conn_handle, uint16_t attr_handle,
                   struct ble_gatt_access_ctxt *ctxt,
                   void *arg);
int ble_svc_htp_notify_measurement(void);
static int
ble_svc_htp_chr_write(struct os_mbuf *om, uint16_t min_len,
                      uint16_t max_len, void *dst,
                      uint16_t *len);

static const struct ble_gatt_svc_def ble_svc_htp_defs[] = {
    {
        /*** Health Thermomter Service. */
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(BLE_SVC_HTP_UUID16),
        .characteristics = (struct ble_gatt_chr_def[])
        { {
                /** Temperature Measurement Characteristic */
                .uuid = BLE_UUID16_DECLARE(BLE_SVC_HTP_CHR_UUID16_TEMP_MEASUREMENT),
                .access_cb = ble_svc_htp_access,
                .val_handle = &ble_svc_htp_temp_measurement_val_handle,
                .flags = BLE_GATT_CHR_F_INDICATE,
            }, {
                /** Temparature Type Characteristic */
                .uuid = BLE_UUID16_DECLARE(BLE_SVC_HTP_CHR_UUID16_TEMP_TYPE),
                .access_cb = ble_svc_htp_access,
                .val_handle = &ble_svc_htp_temp_type_val_handle,
                .flags = BLE_GATT_CHR_F_READ,
            }, {
                /** Intermediate Temperature Characteristic */
                .uuid = BLE_UUID16_DECLARE(BLE_SVC_HTP_CHR_UUID16_INTERMEDIATE_TEMP),
                .access_cb = ble_svc_htp_access,
                .val_handle = &ble_svc_htp_intr_temp_val_handle,
                .flags = BLE_GATT_CHR_F_NOTIFY,
            }, {
                /** Temperature Measurement Interval Characteristic */
                .uuid = BLE_UUID16_DECLARE(BLE_SVC_HTP_CHR_UUID16_MEASUREMENT_ITVL),
                .access_cb = ble_svc_htp_access,
                .val_handle = &ble_svc_htp_msr_itvl_val_handle,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_INDICATE,
                .descriptors = (struct ble_gatt_dsc_def[])
                {
                    {
                        .uuid = BLE_UUID16_DECLARE(BLE_SVC_HTP_DSC_UUID16_VALID_RANGE),
                        .att_flags = BLE_ATT_F_READ | BLE_ATT_F_WRITE,
                        .access_cb = ble_svc_htp_access,
                    }, {
                        0,
                    }
                },
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
ble_svc_htp_access(uint16_t conn_handle, uint16_t attr_handle,
                   struct ble_gatt_access_ctxt *ctxt,
                   void *arg)
{
    uint16_t uuid16;
    int rc;

    uuid16 = ble_uuid_u16(ctxt->chr->uuid);
    assert(uuid16 != 0);

    switch (uuid16) {
    case BLE_SVC_HTP_CHR_UUID16_TEMP_MEASUREMENT:
        return BLE_ATT_ERR_INSUFFICIENT_RES;

    case BLE_SVC_HTP_CHR_UUID16_TEMP_TYPE:
        assert(ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR);
        rc = os_mbuf_append(ctxt->om, &ble_svc_htp_temp_type,
                            sizeof(ble_svc_htp_temp_type));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;

    case BLE_SVC_HTP_CHR_UUID16_INTERMEDIATE_TEMP:
        return BLE_ATT_ERR_INSUFFICIENT_RES;

    case BLE_SVC_HTP_CHR_UUID16_MEASUREMENT_ITVL:
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
            rc = ble_svc_htp_chr_write(ctxt->om, 0, sizeof(ble_svc_htp_temp_msr_itvl),
                                       &ble_svc_htp_temp_msr_itvl,
                                       NULL);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        } else if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            rc = os_mbuf_append(ctxt->om, &ble_svc_htp_temp_msr_itvl,
                                sizeof(ble_svc_htp_temp_msr_itvl));
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        } else {
            return BLE_SVC_HS_ERR_OUT_OF_RANGE;
        }

    default:
        assert(0);
        return BLE_ATT_ERR_UNLIKELY;
    }
}

void
ble_svc_htp_on_disconnect(uint16_t conn_handle)
{
    conn_chr_subs[conn_handle].chr_subs[TEMP_MEASUREMENT] = false;
    conn_chr_subs[conn_handle].chr_subs[INTERMEDIATE_TEMP] = false;
    conn_chr_subs[conn_handle].chr_subs[MEASUREMENT_ITVL]  = false;
}

/**
 * Returns if the characteristic is subscribed or not
 */
bool
ble_svc_htp_is_subscribed(uint16_t conn_handle, int chr)
{
    return conn_chr_subs[conn_handle].chr_subs[chr];
}

/**
 * Stores the subscribed state of each characteristic
 *
 * @params
 * attr_handle:     Attribute handle of the characteristic
 *
 * @return 0 on success, non-zero error code otherwise.
 */
void
ble_svc_htp_subscribe(uint16_t conn_handle, uint16_t attr_handle)
{
    if (attr_handle == ble_svc_htp_temp_measurement_val_handle) {
        conn_chr_subs[conn_handle].chr_subs[TEMP_MEASUREMENT] = true;

    } else if (attr_handle == ble_svc_htp_intr_temp_val_handle) {
        conn_chr_subs[conn_handle].chr_subs[INTERMEDIATE_TEMP] = true;

    } else if (attr_handle == ble_svc_htp_msr_itvl_val_handle) {
        conn_chr_subs[conn_handle].chr_subs[MEASUREMENT_ITVL] = true;
    }
}

/**
 * Send a notification for intermediate temperature
 *
 * @return 0 on success, non-zero error code otherwise.
 */
int
ble_svc_htp_notify(uint16_t conn_handle, float temp, bool temp_unit)
{
    int rc;
    struct os_mbuf *txom = NULL;

    /* 0th byte is flag, next 4 bytes is the temperature */
    uint8_t flags = {0x00};

    if (temp_unit) {
        flags |= 1 << 0; /* Setting 0 th bit of flags to 1 if temp unit is Fahrenheit */
    }

    txom = ble_hs_mbuf_from_flat(&flags, sizeof(flags));
    if (!txom) {
        return ESP_FAIL;
    }

    rc = os_mbuf_copyinto(txom, sizeof(flags), &temp, sizeof(temp));
    if (rc != 0) {
        goto err;
    }

    rc = ble_gatts_notify_custom(conn_handle,
                                 ble_svc_htp_intr_temp_val_handle, txom);
    if (rc != 0) {
        goto err;
    }

    ble_gatts_chr_updated(ble_svc_htp_intr_temp_val_handle);
err:
    return rc;
}

/**
 * Send a indicate for temperature measurement
 *
 * @return 0 on success, non-zero error code otherwise.
 */
int
ble_svc_htp_indicate(uint16_t conn_handle, float temp, bool temp_unit)
{
    int rc;
    struct os_mbuf *txom = NULL;

    /* 0th byte is flag, next 4 bytes is the temperature */

    uint8_t flags = {0x00};

    if (temp_unit) {
        flags |= 1 << 0;   /* Setting 0 th bit of flags to 1 if temp unit is Fahrenheit */
    }

    txom = ble_hs_mbuf_from_flat(&flags, sizeof(flags));
    if (!txom) {
        return ESP_FAIL;
    }

    rc = os_mbuf_copyinto(txom, sizeof(flags), &temp, sizeof(temp));
    if (rc != 0) {
        return rc;
    }

    rc = ble_gatts_indicate_custom(conn_handle,
                                   ble_svc_htp_temp_measurement_val_handle, txom);
    return rc;
}


/**
 * Writes the received value from a characteristic write to
 * the given destination.
 */
static int
ble_svc_htp_chr_write(struct os_mbuf *om, uint16_t min_len,
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
ble_svc_htp_init(void)
{
    int rc;

    /* Ensure this function only gets called by sysinit. */
    SYSINIT_ASSERT_ACTIVE();

    rc = ble_gatts_count_cfg(ble_svc_htp_defs);
    SYSINIT_PANIC_ASSERT(rc == 0);

    rc = ble_gatts_add_svcs(ble_svc_htp_defs);
    SYSINIT_PANIC_ASSERT(rc == 0);

    ble_svc_htp_temp_type = 2;
    ble_svc_htp_temp_msr_itvl = 2; /* 2 sec */

    memset(&conn_chr_subs, 0, sizeof(conn_chr_subs));
}
