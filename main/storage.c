#include "storage.h"
#include "jade_assert.h"
#include "keychain.h"
#include <esp_system.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <wally_crypto.h>

#ifdef CONFIG_NVS_ENCRYPTION
// As named in partitions.csv file
static const char* NVS_KEYS_PARTITION_LABEL = "nvs_key";
#endif

static const char* STORAGE_NAMESPACE = "PIN";
static const char* PIN_PRIVATEKEY_FIELD = "privatekey";
static const char* PIN_COUNTER_FIELD = "counter";
static const char* BLOB_FIELD = "blob";
static const char* NETWORK_TYPE_FIELD = "networktype";
static const char* IDLE_TIMEOUT_FIELD = "idletimeout";
static const char* CLICK_EVENT_FIELD = "clickevent";
static const char* BLE_FLAGS_FIELD = "bleflags";

static bool store_blob(const char* name, const unsigned char* data, const size_t len)
{
    JADE_ASSERT(name);
    JADE_ASSERT(data);
    JADE_ASSERT(len > 0);

    nvs_handle handle;
    esp_err_t err;

    err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        JADE_LOGE("nvs_open() for %s failed: %u", STORAGE_NAMESPACE, err);
        return false;
    }

    err = nvs_set_blob(handle, name, data, len);

    if (err != ESP_OK) {
        JADE_LOGE("nvs_set_blob() for %s failed: %u", name, err);
        nvs_close(handle);
        return false;
    }

    err = nvs_commit(handle);
    if (err != ESP_OK) {
        JADE_LOGE("nvs_commit() failed: %u", err);
        nvs_close(handle);
        return false;
    }

    nvs_close(handle);
    return true;
}

static bool read_blob(const char* name, unsigned char* data, const size_t len)
{
    JADE_ASSERT(name);
    JADE_ASSERT(data);
    JADE_ASSERT(len > 0);

    nvs_handle handle;
    esp_err_t err;

    err = nvs_open(STORAGE_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        JADE_LOGE("nvs_open() for %s failed: %u", STORAGE_NAMESPACE, err);
        return false;
    }

    size_t required_size = len;
    err = nvs_get_blob(handle, name, data, &required_size);

    if (err != ESP_OK || len != required_size) {
        JADE_LOGE("nvs_get_blob() for %s failed or unexpected length - ret: %u (required length: %u)", name, err,
            required_size);
        nvs_close(handle);
        return false;
    }

    nvs_close(handle);
    return true;
}

static bool erase_blob(const char* name)
{
    JADE_ASSERT(name);

    nvs_handle handle;
    esp_err_t err;

    err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        JADE_LOGE("nvs_open() for %s failed: %u", STORAGE_NAMESPACE, err);
        return false;
    }

    err = nvs_erase_key(handle, name);

    if (err != ESP_OK) {
        if (err != ESP_ERR_NVS_INVALID_HANDLE) {
            JADE_LOGE("nvs_erase_key() for %s failed: %u", name, err);
            nvs_close(handle);
        }
        return false;
    }

    err = nvs_commit(handle);
    if (err != ESP_OK) {
        if (err != ESP_ERR_NVS_INVALID_HANDLE) {
            JADE_LOGE("nvs_commit() failed: %u", err);
            nvs_close(handle);
        }
        return false;
    }

    nvs_close(handle);
    return true;
}

static esp_err_t init_nvs_flash()
{
    esp_err_t err;

#ifdef CONFIG_NVS_ENCRYPTION
    JADE_LOGI("Looking for nvs keys");
    const esp_partition_t* part_keys = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS, NVS_KEYS_PARTITION_LABEL);
    JADE_ASSERT_MSG(part_keys, "Unable to find nvs_keys partition");
    JADE_ASSERT(part_keys->encrypted);

    JADE_LOGI("Loading nvs keys");
    nvs_sec_cfg_t cfg;
    err = nvs_flash_read_security_cfg(part_keys, &cfg);
    if (err != ESP_OK) {
        JADE_LOGI("Loading nvs keys failed - creating keys");
        err = nvs_flash_generate_keys(part_keys, &cfg);
    }

    if (err == ESP_OK) {
        JADE_LOGI("Calling nvs_flash_secure_init()");
        err = nvs_flash_secure_init(&cfg);
    }
#else
    JADE_LOGI("Calling nvs_flash_init()");
    err = nvs_flash_init();
#endif

    return err;
}

bool storage_init()
{
    esp_err_t err = init_nvs_flash();

    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        JADE_LOGW("init returned: %u - erasing and reinitialising", err);
        if (storage_erase()) {
            err = init_nvs_flash();
            if (err != ESP_OK) {
                JADE_LOGE("Re-init failed: %u", err);
            }
        }
    }

    esp_log_level_set("nvs", ESP_LOG_ERROR);
    return err == ESP_OK;
}

// Erase flash
bool storage_erase()
{
    const esp_err_t err = nvs_flash_erase();
    if (err != ESP_OK) {
        JADE_LOGE("nvs_flash_erase() failed: %u", err);
        return false;
    }
    return true;
}

bool storage_get_pin_privatekey(unsigned char* privatekey, const size_t key_len)
{
    JADE_ASSERT(privatekey);
    JADE_ASSERT(key_len == EC_PRIVATE_KEY_LEN);

    if (!read_blob(PIN_PRIVATEKEY_FIELD, privatekey, key_len)) {
        return false;
    }

    const int wret = wally_ec_private_key_verify(privatekey, key_len);
    if (wret != WALLY_OK) {
        JADE_LOGE("wally_ec_private_key_verify() failed: %u", wret);
        return false;
    }
    return true;
}

bool storage_set_pin_privatekey(const unsigned char* privatekey, const size_t key_len)
{
    JADE_ASSERT(privatekey);
    JADE_ASSERT(key_len == EC_PRIVATE_KEY_LEN);

    const int wret = wally_ec_private_key_verify(privatekey, key_len);
    if (wret != WALLY_OK) {
        JADE_LOGE("wally_ec_private_key_verify() failed: %u", wret);
        return false;
    }
    return store_blob(PIN_PRIVATEKEY_FIELD, privatekey, key_len);
}

bool storage_erase_pin_privatekey() { return erase_blob(PIN_PRIVATEKEY_FIELD); }

bool storage_set_encrypted_blob(const unsigned char* encrypted, const size_t encrypted_len)
{
    JADE_ASSERT(encrypted);
    if (!storage_restore_counter()) {
        return false;
    }
    return store_blob(BLOB_FIELD, encrypted, encrypted_len);
}

bool storage_get_encrypted_blob(unsigned char* encrypted, const size_t encrypted_len)
{
    return read_blob(BLOB_FIELD, encrypted, encrypted_len);
}

bool storage_erase_encrypted_blob() { return erase_blob(BLOB_FIELD) && erase_blob(PIN_COUNTER_FIELD); }

bool storage_decrement_counter()
{
    uint8_t counter = storage_get_counter();
    if (counter == 0 || counter > 3) {
        storage_erase_encrypted_blob();
        return false;
    }

    --counter;

    if (!store_blob(PIN_COUNTER_FIELD, &counter, sizeof(counter))) {
        storage_erase_encrypted_blob();
        return false;
    }
    return true;
}

bool storage_restore_counter()
{
    const uint8_t counter = 3;
    return store_blob(PIN_COUNTER_FIELD, &counter, sizeof(counter));
}

uint8_t storage_get_counter()
{
    uint8_t counter = 0;
    return read_blob(PIN_COUNTER_FIELD, &counter, sizeof(counter)) ? counter : 0;
}

bool storage_set_network_type_restriction(network_type_t networktype)
{
    return store_blob(NETWORK_TYPE_FIELD, (unsigned char*)&networktype, sizeof(networktype));
}

network_type_t storage_get_network_type_restriction()
{
    network_type_t networktype = NONE;
    return read_blob(NETWORK_TYPE_FIELD, (unsigned char*)&networktype, sizeof(networktype)) ? networktype : NONE;
}

bool storage_set_idle_timeout(uint16_t timeout)
{
    return store_blob(IDLE_TIMEOUT_FIELD, (const unsigned char*)&timeout, sizeof(timeout));
}

uint16_t storage_get_idle_timeout()
{
    uint16_t timeout = 0;
    return read_blob(IDLE_TIMEOUT_FIELD, (unsigned char*)&timeout, sizeof(timeout)) ? timeout : 0;
}

bool storage_set_click_event(uint8_t event) { return store_blob(CLICK_EVENT_FIELD, &event, sizeof(event)); }

uint8_t storage_get_click_event()
{
    uint8_t event = 0;
    return read_blob(CLICK_EVENT_FIELD, &event, sizeof(event)) ? event : 0;
}

bool storage_set_ble_flags(uint8_t flags) { return store_blob(BLE_FLAGS_FIELD, &flags, sizeof(flags)); }

uint8_t storage_get_ble_flags()
{
    uint8_t flags = 0;
    return read_blob(BLE_FLAGS_FIELD, &flags, sizeof(flags)) ? flags : 0;
}
