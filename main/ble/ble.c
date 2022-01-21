#include "ble.h"
#include "../button_events.h"
#include "../gui.h"
#include "../jade_assert.h"
#include "../jade_tasks.h"
#include "../jade_wally_verify.h"
#include "../process.h"
#include "../random.h"
#include "../storage.h"
#include "../utils/malloc_ext.h"
#include "../wire.h"
#include <ctype.h>
#include <esp_nimble_hci.h>
#include <esp_system.h>
#include <freertos/event_groups.h>
#include <host/ble_hs.h>
#include <host/ble_hs_pvcy.h>
#include <host/ble_store.h>
#include <host/ble_uuid.h>
#include <host/util/util.h>
#include <nimble/ble.h>
#include <nimble/nimble_port.h>
#include <nimble/nimble_port_freertos.h>
#include <services/gap/ble_svc_gap.h>
#include <services/gatt/ble_svc_gatt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>
#include <wally_crypto.h>

#define JSON_EOM_CHAR '\n'

#define BLE_CONNECTION_TIMEOUT_MS 5000

// 6E400001-B5A3-F393-E0A9-E50E24DCCA9E
static const ble_uuid128_t service_uuid
    = BLE_UUID128_INIT(0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x01, 0x00, 0x40, 0x6e);

// 6E400003-B5A3-F393-E0A9-E50E24DCCA9E
static const ble_uuid128_t tx_service_uuid
    = BLE_UUID128_INIT(0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x03, 0x00, 0x40, 0x6e);

// 6E400002-B5A3-F393-E0A9-E50E24DCCA9E
static const ble_uuid128_t rx_service_uuid
    = BLE_UUID128_INIT(0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x02, 0x00, 0x40, 0x6e);

static bool ble_is_enabled = false;
static bool ble_is_connected = false;
static size_t ble_read = 0;
static uint8_t own_addr_type = BLE_OWN_ADDR_RANDOM;
static uint8_t* ble_data_in = NULL;
static uint8_t* full_ble_data_in = NULL;
static uint8_t* ble_data_out = NULL;
static uint16_t peer_conn_handle = 0;
static uint16_t peer_conn_attr_handle = 0;
static const size_t ATT_OVERHEAD = 3;
static size_t ble_max_write_size = CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU - ATT_OVERHEAD;
static TaskHandle_t* ble_writer_handle = NULL;

void make_ble_confirmation_activity(gui_activity_t** activity_ptr, const uint32_t numcmp);

int ble_get_mac(char* mac, size_t length)
{
    if (length < 18)
        return -1;

    esp_efuse_mac_get_default((uint8_t*)mac);
    char* hexout = NULL;
    JADE_WALLY_VERIFY(wally_hex_from_bytes((uint8_t*)mac, 6, &hexout));

    mac[0] = toupper((int)hexout[0]);
    mac[1] = toupper((int)hexout[1]);
    mac[2] = ':';
    mac[3] = toupper((int)hexout[2]);
    mac[4] = toupper((int)hexout[3]);
    mac[5] = ':';
    mac[6] = toupper((int)hexout[4]);
    mac[7] = toupper((int)hexout[5]);
    mac[8] = ':';
    mac[9] = toupper((int)hexout[6]);
    mac[10] = toupper((int)hexout[7]);
    mac[11] = ':';
    mac[12] = toupper((int)hexout[8]);
    mac[13] = toupper((int)hexout[9]);
    mac[14] = ':';
    mac[15] = toupper((int)hexout[10]);
    mac[16] = toupper((int)hexout[11]);
    mac[17] = '\0';

    wally_free_string(hexout);

    return 18;
}

static int gatt_chr_event(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt* ctxt, void* arg)
{
    JADE_LOGI("Entering gatt_chr_event %d", ctxt->op);
    const ble_uuid_t* uuid;
    int rc;

    uuid = ctxt->chr->uuid;

    uint16_t ble_msg_len;

    if (ble_uuid_cmp(uuid, &rx_service_uuid.u) == 0) {
        switch (ctxt->op) {
        case BLE_GATT_ACCESS_OP_WRITE_CHR:
            JADE_LOGI("Reading from ble device");

            ble_msg_len = OS_MBUF_PKTLEN(ctxt->om);
            JADE_LOGI("Reading %u bytes", ble_msg_len);

            if (ble_msg_len == 0) {
                return 0;
            }

            // Check we won't overrun the buffer
            if (ble_read + ble_msg_len >= MAX_INPUT_MSG_SIZE) {
                // FIXME: need to call handle_data() with full buffer,  with reject_if_no_msg set to true
                JADE_LOGE("Error reading bytes from ble device - data discarded (%u bytes)", ble_read + ble_msg_len);
                ble_read = 0;
                return 0;
            }

            uint16_t out_copy_len;

            rc = ble_hs_mbuf_to_flat(ctxt->om, ble_data_in + ble_read, ble_msg_len, &out_copy_len);
            JADE_ASSERT(rc == 0);
            JADE_ASSERT(out_copy_len == ble_msg_len);

            const size_t initial_offset = ble_read;
            ble_read += ble_msg_len;
            const bool reject_if_no_msg = (ble_read == MAX_INPUT_MSG_SIZE); // FIXME never happens atm
            JADE_LOGD("Passing %u bytes from ble device to common handler", ble_read);
            handle_data(full_ble_data_in, initial_offset, &ble_read, reject_if_no_msg, ble_data_out, SOURCE_BLE);
            return 0;

        default:
            JADE_LOGW("Unexpected gatt access op: %u, ignoring", ctxt->op);
            return 0;
        }
    } else if (ble_uuid_cmp(uuid, &tx_service_uuid.u) == 0) {
        JADE_LOGW("Received op %u for tx uuid, ignoring", ctxt->op);
        return 0;
    }

    char buf[BLE_UUID_STR_LEN];
    JADE_LOGW("Unexpected uuid, ignoring: %s", ble_uuid_to_str(uuid, buf));
    return 0;
}

static const struct ble_gatt_svc_def gatt_svr_svcs[] = {
    {
        // Protect both read and write characteristics with the flags
        // that mandate an encrypted connection.
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &service_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]){ { .uuid = &tx_service_uuid.u,
                                                            .access_cb = gatt_chr_event,
                                                            .flags = BLE_GATT_CHR_F_INDICATE | BLE_GATT_CHR_F_READ_ENC
                                                                | BLE_GATT_CHR_F_READ_AUTHEN },
            { .uuid = &rx_service_uuid.u,
                .access_cb = gatt_chr_event,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC | BLE_GATT_CHR_F_WRITE_AUTHEN },
            {
                0,
            } },
    },

    {
        0,
    },
};

static void gatt_svr_register_cb(struct ble_gatt_register_ctxt* ctxt, void* arg)
{
    char buf[BLE_UUID_STR_LEN];

    switch (ctxt->op) {
    case BLE_GATT_REGISTER_OP_SVC:
        JADE_LOGI(
            "Registered service %s with handle=%d\n", ble_uuid_to_str(ctxt->svc.svc_def->uuid, buf), ctxt->svc.handle);
        break;

    case BLE_GATT_REGISTER_OP_CHR:
        JADE_LOGI("Registering characteristic %s with "
                  "def_handle=%d val_handle=%d\n",
            ble_uuid_to_str(ctxt->chr.chr_def->uuid, buf), ctxt->chr.def_handle, ctxt->chr.val_handle);
        break;

    case BLE_GATT_REGISTER_OP_DSC:
        JADE_LOGI("Registering descriptor %s with handle=%d\n", ble_uuid_to_str(ctxt->dsc.dsc_def->uuid, buf),
            ctxt->dsc.handle);
        break;

    default:
        JADE_ASSERT(0);
        break;
    }
}

static int gatt_svr_init(void)
{
    int rc;

    ble_svc_gap_init();
    ble_svc_gatt_init();

    rc = ble_gatts_count_cfg(gatt_svr_svcs);
    if (rc != 0) {
        return rc;
    }

    rc = ble_gatts_add_svcs(gatt_svr_svcs);
    if (rc != 0) {
        return rc;
    }

    return 0;
}

static int ble_gap_event(struct ble_gap_event* event, void* arg);
void ble_store_config_init(void);

static void print_addr(const void* addr)
{
    const uint8_t* u8p = addr;
    JADE_LOGI("%02x:%02x:%02x:%02x:%02x:%02x", u8p[5], u8p[4], u8p[3], u8p[2], u8p[1], u8p[0]);
}

static void ble_print_conn_desc(struct ble_gap_conn_desc* desc)
{
    JADE_LOGI("handle=%d our_ota_addr_type=%d our_ota_addr=", desc->conn_handle, desc->our_ota_addr.type);
    print_addr(desc->our_ota_addr.val);
    JADE_LOGI(" our_id_addr_type=%d our_id_addr=", desc->our_id_addr.type);
    print_addr(desc->our_id_addr.val);
    JADE_LOGI(" peer_ota_addr_type=%d peer_ota_addr=", desc->peer_ota_addr.type);
    print_addr(desc->peer_ota_addr.val);
    JADE_LOGI(" peer_id_addr_type=%d peer_id_addr=", desc->peer_id_addr.type);
    print_addr(desc->peer_id_addr.val);
    JADE_LOGI(" conn_itvl=%d conn_latency=%d supervision_timeout=%d "
              "encrypted=%d authenticated=%d bonded=%d\n",
        desc->conn_itvl, desc->conn_latency, desc->supervision_timeout, desc->sec_state.encrypted,
        desc->sec_state.authenticated, desc->sec_state.bonded);
}

void ble_start_advertising(void)
{
    JADE_LOGI("ble_start_advertising() - Starting ble advertising with own_addr_type: %d", own_addr_type);

    // 'ble_gap_adv_start()' fails if we try to 'start advertising' when BLE is not started/enabled
    if (!ble_is_enabled) {
        JADE_LOGW("ble_start_advertising() called but BLE is disabled/not running");
        return;
    }

    // 'ble_gap_adv_set_fields()' fails if we try to 'start advertising' when it's already running
    if (ble_gap_adv_active()) {
        JADE_LOGW("ble_start_advertising() called but already advertising!");
        return;
    }
    ble_max_write_size = CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU - ATT_OVERHEAD;

    struct ble_gap_adv_params adv_params;
    struct ble_hs_adv_fields fields;
    const char* name;
    int rc;

    // All we really need in the advertising packet is the device name ('Jade abcdef' - 11 bytes)
    // and the service id (128bit - 16bytes) - with 2 bytes of overhead (type, length) per field,
    // this takes up the entire advertising packet (31 bytes max.)
    memset(&fields, 0, sizeof fields);

    name = ble_svc_gap_device_name();
    fields.name = (uint8_t*)name;
    fields.name_len = strlen(name);
    fields.name_is_complete = 1;

    // It appears the test framework needs certain flags to be set - without them the tests fails to connect.
    // It also appears that the 128bit uuid causes the test framework to fail to detect the device in a scan.
    // However, the uuid is preferable since it allows clients to filter when scanning.
    // Alas there is no space in the 31 bytes allowed to set both.
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    fields.uuids128 = (ble_uuid128_t[]){ service_uuid };
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;
#else
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
#endif

    // This errors (with BLE_HS_EMSGSIZE, 4) if the serialised 'fields' bytes exceeds 31
    rc = ble_gap_adv_set_fields(&fields);
    JADE_ASSERT_MSG(rc == 0, "ble_gap_adv_set_fields() failed with error %d", rc);

    memset(&adv_params, 0, sizeof adv_params);
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER, &adv_params, ble_gap_event, NULL);
    if (rc != 0) {
        JADE_LOGE("ble_gap_adv_start() failed with error %d", rc);
    }

    // Log advertised address
    uint8_t addr_val[6] = { 0 };
    rc = ble_hs_id_copy_addr(own_addr_type, addr_val, NULL);
    JADE_LOGI("Advertising started, with address:");
    print_addr(addr_val);

    // Refeed entropy - this is called whenever the advertisied address changes  - ie.
    // when BLE enabled, and every minute or so all the time no client is connected.
    // Called again when the client disconnects.  So frequent (if BLE enabled) but not
    // completely predictable ...
    refeed_entropy(addr_val, sizeof(addr_val));
}

void ble_stop_advertising(void)
{
    JADE_LOGI("ble_stop_advertising() - Stopping ble advertising");
    ble_gap_adv_stop();
}

static bool write_ble(char* msg, size_t towrite)
{

    JADE_LOGD("Request to write %u bytes", towrite);

    size_t written = 0;
    while (written < towrite) {
        const size_t writenow = written + ble_max_write_size <= towrite ? ble_max_write_size : towrite - written;
        int rc = 0, try = 0;

        do {
            ++try;
            // os_mbuf data is consumed by indicate_custom, regardless of the outcome
            struct os_mbuf* data = ble_hs_mbuf_from_flat(msg + written, writenow);
            JADE_ASSERT(data);

            rc = ble_gattc_indicate_custom(peer_conn_handle, peer_conn_attr_handle, data);
            if (rc != 0) {
                JADE_LOGW("ble_gattc_indicate_custom() returned error %d trying to write %u bytes, attempt %u", rc,
                    writenow, try);
                vTaskDelay(100 / portTICK_PERIOD_MS);
            }
        } while (rc != 0 && try < 10);

        if (rc != 0) {
            JADE_LOGE("ble_gattc_indicate_custom() multiple failures writing %u bytes - written %u bytes of %u, bad "
                      "connection",
                writenow, written, towrite);
            // FIXME: fail/error the connection ?
            return false;
        }

        JADE_LOGD("written %u bytes", writenow);
        written += writenow;
        xTaskNotifyWait(0x00, ULONG_MAX, NULL, portMAX_DELAY);
    }
    return true;
}

static void ble_writer(void* ignore)
{
    while (1) {
        while (jade_process_get_out_message(&write_ble, SOURCE_BLE)) {
            // process messages
        }
        xTaskNotifyWait(0x00, ULONG_MAX, NULL, portMAX_DELAY);
    }
}

/**
 * FIXME: patch in esp-idf/components/bt/host/nimble/nimble/nimble/host/src/ble_hs_pvcy.c
 * Expects this function to exist and provide the default IRK
 * Based on suggestion: https://github.com/espressif/esp-nimble/issues/24#issuecomment-924072566
 *
 * NOTE:
 * By using the device key from 'storage_get_pin_privatekey()', we get something secret, unique and
 * largely persistent - although it is deleted/reset if we do a full factory reset of the unit (seems good).
 * We could derive any key from it - hmac'ing with the efuse mac (which is fixed/persistent [never changed]
 * and should be unique per hw unit) seems as good as anything.
 *
 * NOTE:
 * This function is called on the internal nimble 'ble' task
 *
 * REMOVE WHEN ISSUE FIXED UPSTREAM
 */
void ble_hs_pvcy_get_default_irk(uint8_t* new_irk_out, const size_t new_irk_len)
{
    JADE_ASSERT(new_irk_out);
    JADE_LOGI("ble_hs_pvcy_get_default_irk() called");

    uint8_t output[HMAC_SHA256_LEN];
    JADE_ASSERT(new_irk_len <= sizeof(output));

    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);

    unsigned char privatekey[EC_PRIVATE_KEY_LEN];
    const bool ret = storage_get_pin_privatekey(privatekey, sizeof(privatekey));
    JADE_ASSERT(ret);

    const int wret = wally_hmac_sha256(privatekey, sizeof(privatekey), mac, sizeof(mac), output, sizeof(output));
    wally_bzero(privatekey, sizeof(privatekey));
    JADE_ASSERT(wret == WALLY_OK);

    memcpy(new_irk_out, output, new_irk_len);
}

static void ble_on_reset(int reason) { JADE_LOGI("ble resetting state; reason=%d", reason); }

static void ble_on_sync(void)
{
    // In a debug unattended ci build do not use RPA as it doesn't appear to
    // to work on the CI machine atm, but is preferred for android/ios apps.
#ifdef CONFIG_DEBUG_UNATTENDED_CI
    int rc = ble_hs_util_ensure_addr(0);
    JADE_ASSERT_MSG(rc == 0, "Error from ble_hs_util_ensure_addr(0); rc=%d", rc);

    // From the bleprph example main.c
    JADE_LOGI("ble sync() - Debug/CI mode using non-RPA fixed address");
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    JADE_ASSERT_MSG(rc == 0, "Error from ble_hs_id_infer_auto(0,...); rc=%d", rc);
#else
    int rc = ble_hs_util_ensure_addr(1);
    JADE_ASSERT_MSG(rc == 0, "Error from ble_hs_util_ensure_addr(1); rc=%d", rc);

    // From the bleprph example README (no actual example code provided):
    // For RPA feature (currently Host based privacy feature is supported), use API
    // `ble_hs_pvcy_rpa_config` to enable/disable host based privacy, `own_addr_type`
    // needs to be set to `BLE_ADDR_RANDOM` to use this feature.
    //
    // See also: https://github.com/espressif/esp-nimble/issues/8, which says:
    // Ideally, we should not call ble_hs_id_infer_auto when using Host based privacy
    // (RPA), the first parameter(privacy) passed is for Controller based privacy
    // (default for NimBLE).
    // ...
    // So to sum it all, just setting addr_type to BLE_OWN_ADDR_RANDOM before
    // advertising/scanning and calling ble_hs_pvcy_rpa_config(1) should suffice.
    //
    // NOTE: There is also an attached patch at:
    // https://github.com/espressif/esp-nimble/issues/8#issuecomment-615130885
    JADE_LOGI("ble sync() - Using RPA address");
    own_addr_type = BLE_OWN_ADDR_RANDOM;
    rc = ble_hs_pvcy_rpa_config(1);
    JADE_ASSERT_MSG(rc == 0, "Error from ble_hs_pvcy_rpa_config(1); rc=%d", rc);
#endif

    // Start advertising
    ble_start_advertising();
}

static void ble_task(void* param)
{
    JADE_LOGI("BLE Host Task Started");
    // This function blocks
    // Returns when nimble_port_stop() runs
    nimble_port_run();

    nimble_port_freertos_deinit();
}

bool ble_init(TaskHandle_t* ble_handle)
{
    JADE_ASSERT(ble_handle);
    JADE_ASSERT(!full_ble_data_in);
    JADE_ASSERT(!ble_data_in);
    JADE_ASSERT(!ble_data_out);

    // Sanity check
    JADE_ASSERT(ble_max_write_size >= 64);

    // Extra byte at the start for source-id
    full_ble_data_in = (uint8_t*)JADE_MALLOC_PREFER_SPIRAM(MAX_INPUT_MSG_SIZE + 1);

    full_ble_data_in[0] = SOURCE_BLE;
    ble_data_in = full_ble_data_in + 1;
    ble_data_out = JADE_MALLOC_PREFER_SPIRAM(MAX_OUTPUT_MSG_SIZE);

    const BaseType_t retval = xTaskCreatePinnedToCore(
        &ble_writer, "ble_writer", 2 * 1024, NULL, JADE_TASK_PRIO_WRITER, ble_handle, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create ble_writer task, xTaskCreatePinnedToCore() returned %d", retval);

    ble_writer_handle = ble_handle;

    // Start automatically only if persisted flag set
    // (This won't start automatically on first boot - only once user has explicitly enabled)
    // Always default to enabled for CI build
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const uint8_t ble_flags = storage_get_ble_flags();
#else
    const uint8_t ble_flags = BLE_ENABLED;
#endif

    if (ble_flags & BLE_ENABLED) {
        JADE_LOGI("Starting BLE by default (flags = %d)", ble_flags);
        ble_start();
    } else {
        JADE_LOGI("Not starting BLE by default (flags = %d)", ble_flags);
    }

    return true;
}

void ble_start(void)
{
    /*
     * FIXME: should be able to free more memory
       esp_bt_controller_disable();
       esp_bt_controller_deinit();
       esp_bt_mem_release(ESP_BT_MODE_BTDM);
     */
    const esp_err_t hci_init = esp_nimble_hci_and_controller_init();
    JADE_ASSERT(hci_init == ESP_OK);
    nimble_port_init();

    ble_hs_cfg.reset_cb = ble_on_reset;
    ble_hs_cfg.sync_cb = ble_on_sync;
    ble_hs_cfg.gatts_register_cb = gatt_svr_register_cb;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    // Set IO-cap to DisplayYesNo - this should then display a key that both
    // parties will need to independently verify.
    // Also set the MITM and SC flags.
    ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_DISP_YES_NO;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 1;
    ble_hs_cfg.sm_sc = 1;

    // In a CI build do not set these as they don't appear to work on the CI
    // machine, but are necessary for RPA to work (as used in non-CI builds).
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
#endif

    int rc = gatt_svr_init();
    JADE_ASSERT(rc == 0);

    const char* device_name = get_jade_id();
    JADE_ASSERT(device_name);
    rc = ble_svc_gap_device_name_set(device_name);
    JADE_ASSERT(rc == 0);

    ble_store_config_init();

    nimble_port_freertos_init(ble_task);

    ble_is_enabled = true;
}

void ble_stop(void)
{
    int ret = nimble_port_stop();
    if (ret == 0) {
        nimble_port_deinit();
        ret = esp_nimble_hci_and_controller_deinit();
        if (ret != ESP_OK) {
            JADE_LOGE("esp_nimble_hci_and_controller_deinit() failed with error: %d", ret);
        }
    }
    ble_is_enabled = false;
}

bool ble_enabled(void)
{
    // FIXME: get from NIMBLE
    return ble_is_enabled;
}

bool ble_connected(void) { return ble_is_connected; }

static int ble_gap_event(struct ble_gap_event* event, void* arg)
{
    struct ble_gap_conn_desc desc;
    JADE_LOGI("Event %d", event->type);
    int rc;

    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        /* A new connection was established or a connection attempt failed. */
        JADE_LOGI(
            "connection %s; status=%d ", event->connect.status == 0 ? "established" : "failed", event->connect.status);
        if (event->connect.status == 0) {
            // Increase timeouts - not sure if this is the best/only way ...
            // Note: these values are in specific units/increments
            rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
            JADE_ASSERT(rc == 0);
            struct ble_gap_upd_params params;
            params.itvl_min = BLE_GAP_INITIAL_CONN_ITVL_MIN;
            params.itvl_max = BLE_GAP_INITIAL_CONN_ITVL_MAX;
            params.latency = desc.conn_latency;
            params.supervision_timeout = BLE_CONNECTION_TIMEOUT_MS / 10;
            params.min_ce_len = BLE_GAP_INITIAL_CONN_MIN_CE_LEN;
            params.max_ce_len = BLE_GAP_INITIAL_CONN_MAX_CE_LEN;
            rc = ble_gap_update_params(event->connect.conn_handle, &params);
            JADE_ASSERT(rc == 0);

            // enable ble security
            rc = ble_gap_security_initiate(event->connect.conn_handle);
            JADE_ASSERT(rc == 0);

            rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
            JADE_ASSERT(rc == 0);
            ble_print_conn_desc(&desc);
        }
        JADE_LOGI("\n");

        if (event->connect.status != 0) {
            ble_start_advertising();
        }
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        JADE_LOGI("disconnect; reason=%d ", event->disconnect.reason);
        ble_read = 0;
        ble_print_conn_desc(&event->disconnect.conn);
        JADE_LOGI("\n");
        peer_conn_handle = 0;
        peer_conn_attr_handle = 0;
        ble_is_connected = false;

        // Restart advertising if ble enabled
        if (ble_is_enabled) {
            ble_start_advertising();
        }

        return 0;

    case BLE_GAP_EVENT_CONN_UPDATE:
        JADE_LOGI("connection updated; status=%d ", event->conn_update.status);
        rc = ble_gap_conn_find(event->conn_update.conn_handle, &desc);
        JADE_ASSERT(rc == 0);
        ble_print_conn_desc(&desc);
        JADE_LOGI("\n");
        return 0;

    case BLE_GAP_EVENT_NOTIFY_TX:
        // ble device got our notification, we can send the next msg
        JADE_LOGI("notify tx received, notifying writer");
        if (ble_writer_handle != NULL) {
            xTaskNotify(*ble_writer_handle, 0, eNoAction);
        }
        break;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        // restart advertising if ble enabled
        JADE_LOGI("advertise complete; reason=%d", event->adv_complete.reason);
        if (ble_is_enabled) {
            ble_start_advertising();
        }
        return 0;

    case BLE_GAP_EVENT_ENC_CHANGE:
        /* Encryption has been enabled or disabled for this connection. */
        JADE_LOGI("encryption change event; status=%d ", event->enc_change.status);
        rc = ble_gap_conn_find(event->enc_change.conn_handle, &desc);
        JADE_ASSERT(rc == 0);
        ble_print_conn_desc(&desc);
        JADE_LOGI("\n");
        return 0;

    case BLE_GAP_EVENT_SUBSCRIBE:
        JADE_LOGI("subscribe event; conn_handle=%d attr_handle=%d "
                  "reason=%d prevn=%d curn=%d previ=%d curi=%d\n",
            event->subscribe.conn_handle, event->subscribe.attr_handle, event->subscribe.reason,
            event->subscribe.prev_notify, event->subscribe.cur_notify, event->subscribe.prev_indicate,
            event->subscribe.cur_indicate);
        peer_conn_handle = event->subscribe.conn_handle;
        peer_conn_attr_handle = event->subscribe.attr_handle;
        ble_is_connected = true;
        return 0;

    case BLE_GAP_EVENT_MTU:
        JADE_LOGI("mtu update event; conn_handle=%d cid=%d mtu=%d\n", event->mtu.conn_handle, event->mtu.channel_id,
            event->mtu.value);
        ble_max_write_size = event->mtu.value - ATT_OVERHEAD;
        return 0;

    case BLE_GAP_EVENT_REPEAT_PAIRING:
        JADE_LOGI("Repeat pairing");

        // Delete the old bond information.
        rc = ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc);
        JADE_ASSERT(rc == 0);
        ble_store_util_delete_peer(&desc.peer_id_addr);

        // Return BLE_GAP_REPEAT_PAIRING_RETRY to indicate that the host should
        // continue with the pairing operation (ie. re-do the NUMCMP)
        return BLE_GAP_REPEAT_PAIRING_RETRY;

    case BLE_GAP_EVENT_PASSKEY_ACTION:
        JADE_LOGI("PASSKEY_ACTION_EVENT started: %d \n", event->passkey.params.action);
        rc = ble_gap_conn_find(event->passkey.conn_handle, &desc);
        JADE_ASSERT(rc == 0);
        ble_print_conn_desc(&desc);

        struct ble_sm_io pkey = { 0 };
        if (event->passkey.params.action == BLE_SM_IOACT_NUMCMP) {
            // User is given a chance to review passkey on devices and ack/nack
            // (Eg. when both are DisplayYesNo).  This is the supported option.
            JADE_LOGI("PASSKEY_ACTION_EVENT: NUMCMP");
            pkey.action = event->passkey.params.action;
            JADE_LOGI("Passkey on device's display: %d", event->passkey.params.numcmp);

            // Display passkey on Jade GUI and get confirm/deny response - assume deny after timeout
            gui_activity_t* prior_activity = gui_current_activity();
            gui_activity_t* activity;
            make_ble_confirmation_activity(&activity, event->passkey.params.numcmp);

            JADE_LOGI("Showing BLE confirm screen");
            int32_t ev_id;
            gui_set_current_activity(activity);

// In a debug unattended ci build, assume 'confirm' button clicked after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
            const bool retval = gui_activity_wait_event(
                activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 30000 / portTICK_PERIOD_MS);
#else
            vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
            const bool retval = true;
            ev_id = BTN_BLE_CONFIRM;
#endif

            if (retval && ev_id == BTN_BLE_CONFIRM) {
                // Confirmed
                JADE_LOGI("User pressed confirm");
                pkey.numcmp_accept = 1;

                rc = ble_sm_inject_io(event->passkey.conn_handle, &pkey);
                if (rc != 0) {
                    JADE_LOGE("ble_sm_inject_io errored: %d", rc);
                }
            } else {
                if (retval) {
                    // Denied
                    JADE_LOGI("User pressed deny");
                } else {
                    // error/timeout
                    JADE_LOGW("Error/timeout awaiting BLE pairing confirmation");
                }

                pkey.numcmp_accept = 0;
                rc = ble_sm_inject_io(event->passkey.conn_handle, &pkey);
                // It seems it is normal to return BLE_HS_SM_US_ERR(BLE_SM_ERR_NUMCMP) [1036] here
                if (rc != BLE_HS_SM_US_ERR(BLE_SM_ERR_NUMCMP)) {
                    JADE_LOGW("ble_sm_inject_io unexpected result: %d (expecting %d)", rc,
                        BLE_HS_SM_US_ERR(BLE_SM_ERR_NUMCMP));
                }

                // fully disconnect peer
                rc = ble_gap_unpair(&desc.peer_id_addr);
                if (rc != 0) {
                    JADE_LOGE("Failed to disconnect peer, error: %d", rc);
                }
            }

            // Replace prior activity if we're still current
            if (gui_current_activity() == activity) {
                gui_set_current_activity(prior_activity);
            }
        } else if (event->passkey.params.action == BLE_SM_IOACT_DISP) {
            // This mode displays the passkey on jade, and forces the peer to enter it.
            // We aren't interested in this mode atm.
            JADE_LOGW("PASSKEY_ACTION_EVENT: DISPLAY - not implemented");
        } else if (event->passkey.params.action == BLE_SM_IOACT_OOB) {
            // Out of band pairing - the secret is shared via some other means
            // than BLE eg. qrcode.  We aren't interested in this mode atm
            // but could be good to use qr scanner of image displayed on phone ?
            JADE_LOGW("PASSKEY_ACTION_EVENT: OOB - not implemented");
        } else if (event->passkey.params.action == BLE_SM_IOACT_INPUT) {
            // In this case user inputs the key on Jade
            // We aren't interested in this mode.
            JADE_LOGW("PASSKEY_ACTION_EVENT: INPUT - not implemented");
        }
        return 0;
    }

    return 0;
}

bool ble_remove_all_devices(void)
{
    bool errored = false;
    ble_addr_t peer_id_addrs[CONFIG_BT_NIMBLE_MAX_BONDS];
    int num_peers;
    int res;

    // Get bonded peer data for all saved peers
    res = ble_store_util_bonded_peers(peer_id_addrs, &num_peers, CONFIG_BT_NIMBLE_MAX_BONDS);
    if (res != 0) {
        JADE_LOGE("Failed to get bonded peer info, error: %d", res);
        return false;
    }

    // Loop through saved peers - attempt to unpair (errors if peer not currently
    // connected), then delete the stored bond (ie. pairing) information.
    JADE_LOGI("Found %u saved peers", num_peers);
    for (int i = 0; i < num_peers; ++i) {
        JADE_LOGI("Removing bonded peer:");
        print_addr(peer_id_addrs[i].val);

        // Ignore failure here, peer probably not currently connected
        res = ble_gap_unpair(&peer_id_addrs[i]);
        if (res != 0) {
            JADE_LOGD("Failed to unpair peer (not connected?), error: %d", res);
        }

        // Delete saved bond information
        res = ble_store_util_delete_peer(&peer_id_addrs[i]);
        if (res != 0) {
            JADE_LOGE("Failed to delete bonded peer, error: %d", res);
            errored = true;
        }
    }

    return !errored;
}
