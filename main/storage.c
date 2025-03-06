#ifndef AMALGAMATED_BUILD
#include "storage.h"
#include "jade_assert.h"
#include "keychain.h"

#include <ctype.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <string.h>
#include <wally_crypto.h>

#ifdef CONFIG_NVS_ENCRYPTION
// As named in partitions.csv file
static const char* NVS_KEYS_PARTITION_LABEL = "nvs_key";
#endif

static const char* DEFAULT_NAMESPACE = "PIN";
static const char* MULTISIG_NAMESPACE = "MULTISIGS";
static const char* DESCRIPTOR_NAMESPACE = "DESCRIPTORS";
static const char* OTP_NAMESPACE = "OTP";
static const char* HOTP_COUNTERS_NAMESPACE = "HOTPC";

static const char* PIN_PRIVATEKEY_FIELD = "privatekey";
static const char* PIN_COUNTER_FIELD = "counter";
static const char* REPLAY_COUNTER_FIELD = "antireplay";
static const char* BLOB_FIELD = "blob";
static const char* KEY_FLAGS_FIELD = "keyflags";
static const char* WALLET_ERASE_PIN = "walleterasepin";

static const char* USER_PINSERVER_URL_A = "pinsvrurlA";
static const char* USER_PINSERVER_URL_B = "pinsvrurlB";
static const char* USER_PINSERVER_PUBKEY = "pinsvrpubkey";
static const char* USER_PINSERVER_CERT = "pinsvrcert";

static const char* NETWORK_TYPE_FIELD = "networktype";
static const char* IDLE_TIMEOUT_FIELD = "idletimeout";
static const char* BRIGHTNESS_FIELD = "brightness";
static const char* GUI_FLAGS_FIELD = "guiflags";
static const char* BLE_FLAGS_FIELD = "bleflags";
static const char* QR_FLAGS_FIELD = "qrflags";

// Deprecated/removed keys
static const char* CLICK_EVENT_FIELD = "clickevent";

// NOTE: esp-idf reserve the final page of nvs entries for internal use (for defrag/consolidation)
// See: https://github.com/espressif/esp-idf/issues/5247#issuecomment-1048604221
// If the 'free entries' appears to include these entries, deduct them from the value returned.
#ifdef CONFIG_IDF_TARGET_ESP32S3
#define ESP_NVS_PARTITION_SIZE (64 * 1024)
#else
#define ESP_NVS_PARTITION_SIZE (16 * 1024)
#endif

#define ESP_NVS_PAGE_OVERHEAD (32 + 32)
#define ESP_NVS_ENTRY_SIZE 32
#define ESP_NVS_ENTRIES_PER_PAGE 126
#define ESP_NVS_PAGE_SIZE ((ESP_NVS_ENTRIES_PER_PAGE * ESP_NVS_ENTRY_SIZE) + ESP_NVS_PAGE_OVERHEAD)
// NOTE: ESP_NVS_PAGE_SIZE should be 4kb

#define ESP_NVS_PAGES (ESP_NVS_PARTITION_SIZE / ESP_NVS_PAGE_SIZE)
#define ESP_NVS_TOTAL_ENTRIES (ESP_NVS_PAGES * ESP_NVS_ENTRIES_PER_PAGE)

#define ESP_NVS_RESERVED_PAGES 1
#define ESP_NVS_RESERVED_ENTRIES (ESP_NVS_RESERVED_PAGES * ESP_NVS_ENTRIES_PER_PAGE)

// Building block macros for the store/read/erase functions.
// They all close the storage and return false on any error.

// Macro open nvs before a read or write
#define STORAGE_OPEN(h, ns, rwflags)                                                                                   \
    do {                                                                                                               \
        const esp_err_t err = nvs_open(ns, rwflags, &h);                                                               \
        if (err != ESP_OK) {                                                                                           \
            JADE_LOGE("nvs_open() for %s failed: %u", ns, err);                                                        \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// Macro to persist a known-length blob to nvs
#define STORAGE_SET_BLOB(h, k, v, l)                                                                                   \
    do {                                                                                                               \
        const esp_err_t err = nvs_set_blob(h, k, v, l);                                                                \
        if (err != ESP_OK) {                                                                                           \
            JADE_LOGE("nvs_set_blob() for %s failed: %u", k, err);                                                     \
            nvs_close(h);                                                                                              \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// Macro to persist a nul terminated string to nvs
#define STORAGE_SET_STRING(h, k, v)                                                                                    \
    do {                                                                                                               \
        const esp_err_t err = nvs_set_str(h, k, v);                                                                    \
        if (err != ESP_OK) {                                                                                           \
            JADE_LOGE("nvs_set_str() for %s failed: %u", k, err);                                                      \
            nvs_close(h);                                                                                              \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// Macro to fetch a variable-length blob from nvs
#define STORAGE_GET_BLOB(h, k, v, l, pw)                                                                               \
    do {                                                                                                               \
        *pw = l;                                                                                                       \
        const esp_err_t err = nvs_get_blob(h, k, v, pw);                                                               \
        if (err != ESP_OK) {                                                                                           \
            if (err == ESP_ERR_NVS_NOT_FOUND) {                                                                        \
                JADE_LOGI("nvs_get_blob() for %s - not found", k);                                                     \
            } else {                                                                                                   \
                JADE_LOGE("nvs_get_blob() for %s failed: %u", k, err);                                                 \
            }                                                                                                          \
            nvs_close(h);                                                                                              \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// Macro to fetch a nul terminated string from nvs
#define STORAGE_GET_STRING(h, k, v, l, pw)                                                                             \
    do {                                                                                                               \
        *pw = l;                                                                                                       \
        const esp_err_t err = nvs_get_str(h, k, v, pw);                                                                \
        if (err != ESP_OK) {                                                                                           \
            if (err == ESP_ERR_NVS_NOT_FOUND) {                                                                        \
                JADE_LOGI("nvs_get_str() for %s - not found", k);                                                      \
            } else {                                                                                                   \
                JADE_LOGE("nvs_get_str() for %s failed: %u", k, err);                                                  \
            }                                                                                                          \
            nvs_close(h);                                                                                              \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// Macro to erase an keyed entry from nvs
#define STORAGE_ERASE(h, k)                                                                                            \
    do {                                                                                                               \
        const esp_err_t err = nvs_erase_key(h, k);                                                                     \
        if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {                                                           \
            JADE_LOGE("nvs_erase_key() for %s failed: %u", k, err);                                                    \
            nvs_close(h);                                                                                              \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// Macro to commit changes to nvs after one or more updates/erasures
#define STORAGE_COMMIT(h)                                                                                              \
    do {                                                                                                               \
        const esp_err_t err = nvs_commit(h);                                                                           \
        if (err != ESP_OK) {                                                                                           \
            JADE_LOGE("nvs_commit() failed: %u", err);                                                                 \
            nvs_close(h);                                                                                              \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// Common code to close nvs after access
#define STORAGE_CLOSE(h)                                                                                               \
    do {                                                                                                               \
        nvs_close(h);                                                                                                  \
    } while (false)

static bool store_blob(const char* ns, const char* name, const uint8_t* data, const size_t len)
{
    JADE_ASSERT(ns);
    JADE_ASSERT(name);
    JADE_ASSERT(data);
    JADE_ASSERT(len > 0);

    nvs_handle handle;
    STORAGE_OPEN(handle, ns, NVS_READWRITE);
    STORAGE_SET_BLOB(handle, name, data, len);
    STORAGE_COMMIT(handle);
    STORAGE_CLOSE(handle);
    return true;
}

static bool read_blob(const char* ns, const char* name, uint8_t* data, const size_t len, size_t* written)
{
    JADE_ASSERT(ns);
    JADE_ASSERT(name);
    JADE_ASSERT(data);
    JADE_ASSERT(len > 0);
    JADE_INIT_OUT_SIZE(written);

    nvs_handle handle;
    STORAGE_OPEN(handle, ns, NVS_READONLY);
    STORAGE_GET_BLOB(handle, name, data, len, written);
    STORAGE_CLOSE(handle);
    return true;
}

static bool read_blob_fixed(const char* ns, const char* name, uint8_t* data, const size_t len)
{
    size_t written;
    if (!read_blob(ns, name, data, len, &written)) {
        return false;
    }
    if (written != len) {
        JADE_LOGE("nvs_get_blob_fixed() for %s unexpected length - expected: %u, got: %u)", name, len, written);
        return false;
    }
    return true;
}

static bool store_string(const char* ns, const char* name, const char* str)
{
    JADE_ASSERT(ns);
    JADE_ASSERT(name);
    JADE_ASSERT(str);

    nvs_handle handle;
    STORAGE_OPEN(handle, ns, NVS_READWRITE);
    STORAGE_SET_STRING(handle, name, str);
    STORAGE_COMMIT(handle);
    STORAGE_CLOSE(handle);
    return true;
}

static bool read_string(const char* ns, const char* name, char* str, const size_t len, size_t* written)
{
    JADE_ASSERT(ns);
    JADE_ASSERT(name);
    JADE_ASSERT(str);
    JADE_ASSERT(len > 0);
    JADE_INIT_OUT_SIZE(written);

    nvs_handle handle;
    STORAGE_OPEN(handle, ns, NVS_READONLY);
    STORAGE_GET_STRING(handle, name, str, len, written);
    STORAGE_CLOSE(handle);
    return true;
}

static bool erase_key(const char* ns, const char* name)
{
    JADE_ASSERT(ns);
    JADE_ASSERT(name);

    nvs_handle handle;
    STORAGE_OPEN(handle, ns, NVS_READWRITE);
    STORAGE_ERASE(handle, name);
    STORAGE_COMMIT(handle);
    STORAGE_CLOSE(handle);
    return true;
}

// NOTE: 'namespace' is optional (NULL implies all namespaces)
size_t get_entry_count(const char* namespace, const nvs_type_t type)
{
    size_t count = 0;
    nvs_iterator_t it = NULL;
    esp_err_t res = nvs_entry_find(NVS_DEFAULT_PART_NAME, namespace, type, &it);
    while (res == ESP_OK && it != NULL) {
        res = nvs_entry_next(&it);
        ++count;
    }
    return count;
}

// NOTE: 'namespace' is optional (NULL implies all namespaces)
static bool key_name_exists(const char* name, const char* namespace, const nvs_type_t type)
{
    JADE_ASSERT(name);

    nvs_iterator_t it = NULL;
    esp_err_t res = nvs_entry_find(NVS_DEFAULT_PART_NAME, namespace, type, &it);
    while (res == ESP_OK && it != NULL) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        if (strcmp(name, info.key) == 0) {
            nvs_release_iterator(it);
            return true;
        }
        res = nvs_entry_next(&it);
    }

    return false;
}

// NOTE: 'namespace' is optional (NULL implies all namespaces)
static bool get_all_key_names(const char* namespace, const nvs_type_t type, char names[][NVS_KEY_NAME_MAX_SIZE],
    const size_t num_names, size_t* num_written)
{
    JADE_ASSERT(names);
    JADE_ASSERT(*names);
    JADE_ASSERT(num_names > 0);
    JADE_INIT_OUT_SIZE(num_written);

    size_t count = 0;
    nvs_iterator_t it = NULL;
    esp_err_t res = nvs_entry_find(NVS_DEFAULT_PART_NAME, namespace, type, &it);
    while (res == ESP_OK && it != NULL && count < num_names) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        strcpy(names[count], info.key);
        res = nvs_entry_next(&it);
        ++count;
    }

    if (it) {
        nvs_release_iterator(it);
    }

    *num_written = count;
    return count <= num_names;
}

static esp_err_t init_nvs_flash(void)
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

bool storage_init(void)
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

    // Erase any now-deprecated keys
    erase_key(DEFAULT_NAMESPACE, CLICK_EVENT_FIELD);

    return err == ESP_OK;
}

// Erase flash
bool storage_erase(void)
{
    const esp_err_t err = nvs_flash_erase();
    if (err != ESP_OK) {
        JADE_LOGE("nvs_flash_erase() failed: %u", err);
        return false;
    }
    return true;
}

bool storage_get_stats(size_t* entries_used, size_t* entries_free)
{
    JADE_ASSERT(entries_used);
    JADE_ASSERT(entries_free);

    nvs_stats_t stats;
    if (nvs_get_stats(NVS_DEFAULT_PART_NAME, &stats) != ESP_OK) {
        return false;
    }

    *entries_used = stats.used_entries;

    // NOTE: esp-idf reserve the final page of nvs entries for internal use (for defrag/consolidation)
    // See: https://github.com/espressif/esp-idf/issues/5247#issuecomment-1048604221
    // If the 'free entries' appears to include these entries, deduct them from the value returned.
    if (stats.free_entries >= ESP_NVS_RESERVED_ENTRIES
        && stats.used_entries + stats.free_entries == ESP_NVS_TOTAL_ENTRIES) {
        *entries_free = stats.free_entries - ESP_NVS_RESERVED_ENTRIES;
    } else {
        JADE_LOGW("Fewer (free?) NVS entries than expected - is the 'reserved' page now not reported?");
        *entries_free = stats.free_entries;
    }
    return true;
}

bool storage_key_name_valid(const char* name)
{
    // Allow ascii 33-126 incl - ie. letters, numbers and other printable/punctuation characters
    // NOTE: space and \n are disllowed.
    // Also check length.
    const char* pch = name;
    while (*pch != '\0') {
        if ((pch - name) >= NVS_KEY_NAME_MAX_SIZE) {
            return false;
        }
        const unsigned char c = *pch;
        if (!isgraph(c)) {
            return false;
        }
        ++pch;
    }
    return pch > name;
}

bool storage_get_pin_privatekey(uint8_t* privatekey, const size_t key_len)
{
    JADE_ASSERT(privatekey);
    JADE_ASSERT(key_len == EC_PRIVATE_KEY_LEN);
    if (!read_blob_fixed(DEFAULT_NAMESPACE, PIN_PRIVATEKEY_FIELD, privatekey, key_len)) {
        return false;
    }

    const int wret = wally_ec_private_key_verify(privatekey, key_len);
    if (wret != WALLY_OK) {
        JADE_LOGE("wally_ec_private_key_verify() failed: %u", wret);
        return false;
    }
    return true;
}

bool storage_set_pin_privatekey(const uint8_t* privatekey, const size_t key_len)
{
    JADE_ASSERT(privatekey);
    JADE_ASSERT(key_len == EC_PRIVATE_KEY_LEN);

    const int wret = wally_ec_private_key_verify(privatekey, key_len);
    if (wret != WALLY_OK) {
        JADE_LOGE("wally_ec_private_key_verify() failed: %u", wret);
        return false;
    }
    return store_blob(DEFAULT_NAMESPACE, PIN_PRIVATEKEY_FIELD, privatekey, key_len);
}

bool storage_erase_pin_privatekey(void) { return erase_key(DEFAULT_NAMESPACE, PIN_PRIVATEKEY_FIELD); }

bool storage_set_encrypted_blob(const uint8_t* encrypted, const size_t encrypted_len)
{
    JADE_ASSERT(encrypted);
    if (!storage_restore_counter()) {
        return false;
    }
    return store_blob(DEFAULT_NAMESPACE, BLOB_FIELD, encrypted, encrypted_len);
}

bool storage_get_encrypted_blob(uint8_t* encrypted, const size_t encrypted_len, size_t* written)
{
    return read_blob(DEFAULT_NAMESPACE, BLOB_FIELD, encrypted, encrypted_len, written);
}

bool storage_erase_encrypted_blob(void)
{
    // Try to erase the counter
    erase_key(DEFAULT_NAMESPACE, PIN_COUNTER_FIELD);

    // Return whether or not we successfully erase the encrypted key
    return erase_key(DEFAULT_NAMESPACE, BLOB_FIELD);
}

bool storage_decrement_counter(void)
{
    uint8_t counter = storage_get_counter();
    if (counter == 0 || counter > 3) {
        storage_erase_encrypted_blob();
        return false;
    }

    --counter;

    if (!store_blob(DEFAULT_NAMESPACE, PIN_COUNTER_FIELD, &counter, sizeof(counter))) {
        storage_erase_encrypted_blob();
        return false;
    }
    return true;
}

bool storage_restore_counter(void)
{
    const uint8_t counter = 3;
    return store_blob(DEFAULT_NAMESPACE, PIN_COUNTER_FIELD, &counter, sizeof(counter));
}

uint8_t storage_get_counter(void)
{
    uint8_t counter = 0;
    return read_blob_fixed(DEFAULT_NAMESPACE, PIN_COUNTER_FIELD, &counter, sizeof(counter)) ? counter : 0;
}

bool storage_get_replay_counter(uint32_t* replay_counter)
{
    // returns the latest counter and increments the one on flash for next use.
    // Note that the replay counter is never reset, only incremented.
    // if no counter is set (i.e. brand new device), we create one set to 0.
    JADE_ASSERT(replay_counter);

    nvs_handle handle;
    STORAGE_OPEN(handle, DEFAULT_NAMESPACE, NVS_READWRITE);
    uint32_t j = UINT32_MAX;
    esp_err_t err = nvs_get_u32(handle, REPLAY_COUNTER_FIELD, &j);
    if (err != ESP_OK) {
        if (err != ESP_ERR_NVS_NOT_FOUND) {
            JADE_LOGE("nvs_get_u32() for %s failed: %u", REPLAY_COUNTER_FIELD, err);
            nvs_close(handle);
            return false;
        }
        JADE_LOGI("nvs_get_u32() for %s - not found", REPLAY_COUNTER_FIELD);
        j = 0;
    }
    JADE_ASSERT(j < UINT32_MAX);

    *replay_counter = j;
    err = nvs_set_u32(handle, REPLAY_COUNTER_FIELD, j + 1);
    if (err != ESP_OK) {
        JADE_LOGE("nvs_set_u32() for %s failed: %u", REPLAY_COUNTER_FIELD, err);
        nvs_close(handle);
        return false;
    }
    STORAGE_COMMIT(handle);
    STORAGE_CLOSE(handle);
    return true;
}

bool storage_set_pinserver_details(const char* urlA, const char* urlB, const uint8_t* pubkey, const size_t pubkey_len)
{
    JADE_ASSERT(urlA);
    JADE_ASSERT(urlB);

    // Commit all values, or none
    nvs_handle handle;
    STORAGE_OPEN(handle, DEFAULT_NAMESPACE, NVS_READWRITE);
    STORAGE_SET_STRING(handle, USER_PINSERVER_URL_A, urlA);
    STORAGE_SET_STRING(handle, USER_PINSERVER_URL_B, urlB);

    // Pubkey is optional (as just server public address may change)
    if (pubkey && pubkey_len > 0) {
        STORAGE_SET_BLOB(handle, USER_PINSERVER_PUBKEY, pubkey, pubkey_len);
    }
    STORAGE_COMMIT(handle);
    STORAGE_CLOSE(handle);
    return true;
}

bool storage_get_pinserver_urlA(char* url, const size_t len, size_t* written)
{
    return read_string(DEFAULT_NAMESPACE, USER_PINSERVER_URL_A, url, len, written);
}

bool storage_get_pinserver_urlB(char* url, const size_t len, size_t* written)
{
    return read_string(DEFAULT_NAMESPACE, USER_PINSERVER_URL_B, url, len, written);
}

bool storage_get_pinserver_pubkey(uint8_t* pubkey, const size_t pubkey_len)
{
    return read_blob_fixed(DEFAULT_NAMESPACE, USER_PINSERVER_PUBKEY, pubkey, pubkey_len);
}

bool storage_erase_pinserver_details(void)
{
    // Erase all of the pinserver fields, or none of them
    nvs_handle handle;
    STORAGE_OPEN(handle, DEFAULT_NAMESPACE, NVS_READWRITE);
    STORAGE_ERASE(handle, USER_PINSERVER_URL_A);
    STORAGE_ERASE(handle, USER_PINSERVER_URL_B);
    STORAGE_ERASE(handle, USER_PINSERVER_PUBKEY);
    STORAGE_COMMIT(handle);
    STORAGE_CLOSE(handle);
    return true;
}

bool storage_set_pinserver_cert(const char* cert) { return store_string(DEFAULT_NAMESPACE, USER_PINSERVER_CERT, cert); }

bool storage_get_pinserver_cert(char* cert, const size_t len, size_t* written)
{
    return read_string(DEFAULT_NAMESPACE, USER_PINSERVER_CERT, cert, len, written);
}

bool storage_erase_pinserver_cert(void) { return erase_key(DEFAULT_NAMESPACE, USER_PINSERVER_CERT); }

bool storage_set_network_type_restriction(network_type_t networktype)
{
    return store_blob(DEFAULT_NAMESPACE, NETWORK_TYPE_FIELD, (uint8_t*)&networktype, sizeof(networktype));
}

network_type_t storage_get_network_type_restriction(void)
{
    network_type_t networktype = NETWORK_TYPE_NONE;
    return read_blob_fixed(DEFAULT_NAMESPACE, NETWORK_TYPE_FIELD, (uint8_t*)&networktype, sizeof(networktype))
        ? networktype
        : NETWORK_TYPE_NONE;
}

bool storage_set_idle_timeout(uint16_t timeout)
{
    return store_blob(DEFAULT_NAMESPACE, IDLE_TIMEOUT_FIELD, (const uint8_t*)&timeout, sizeof(timeout));
}

uint16_t storage_get_idle_timeout(void)
{
    uint16_t timeout = 0;
    return read_blob_fixed(DEFAULT_NAMESPACE, IDLE_TIMEOUT_FIELD, (uint8_t*)&timeout, sizeof(timeout)) ? timeout : 0;
}

bool storage_set_brightness(uint8_t brightness)
{
    return store_blob(DEFAULT_NAMESPACE, BRIGHTNESS_FIELD, &brightness, sizeof(brightness));
}

uint8_t storage_get_brightness(void)
{
    uint8_t brightness = 0;
    return read_blob_fixed(DEFAULT_NAMESPACE, BRIGHTNESS_FIELD, &brightness, sizeof(brightness)) ? brightness : 0;
}

bool storage_set_gui_flags(uint8_t gui_flags)
{
    return store_blob(DEFAULT_NAMESPACE, GUI_FLAGS_FIELD, &gui_flags, sizeof(gui_flags));
}

uint8_t storage_get_gui_flags(void)
{
    uint8_t gui_flags = 0;
    return read_blob_fixed(DEFAULT_NAMESPACE, GUI_FLAGS_FIELD, &gui_flags, sizeof(gui_flags)) ? gui_flags : 0;
}

bool storage_set_ble_flags(uint8_t flags)
{
    return store_blob(DEFAULT_NAMESPACE, BLE_FLAGS_FIELD, &flags, sizeof(flags));
}

uint8_t storage_get_ble_flags(void)
{
    uint8_t flags = 0;
    return read_blob_fixed(DEFAULT_NAMESPACE, BLE_FLAGS_FIELD, &flags, sizeof(flags)) ? flags : 0;
}

bool storage_set_qr_flags(uint32_t flags)
{
    return store_blob(DEFAULT_NAMESPACE, QR_FLAGS_FIELD, (const uint8_t*)&flags, sizeof(flags));
}

uint32_t storage_get_qr_flags(void)
{
    uint32_t flags = 0;
    if (!read_blob_fixed(DEFAULT_NAMESPACE, QR_FLAGS_FIELD, (uint8_t*)&flags, sizeof(flags))) {
        uint16_t legacy_flags = 0; // flags used to be saved as 16bits only
        if (read_blob_fixed(DEFAULT_NAMESPACE, QR_FLAGS_FIELD, (uint8_t*)&legacy_flags, sizeof(legacy_flags))) {
            flags = legacy_flags;
        } else {
            flags = 0;
        }
    }
    return flags;
}

bool storage_set_key_flags(uint8_t flags)
{
    return store_blob(DEFAULT_NAMESPACE, KEY_FLAGS_FIELD, &flags, sizeof(flags));
}

uint8_t storage_get_key_flags(void)
{
    uint8_t flags = 0;
    return read_blob_fixed(DEFAULT_NAMESPACE, KEY_FLAGS_FIELD, &flags, sizeof(flags)) ? flags : 0;
}

bool storage_set_wallet_erase_pin(const uint8_t* pin, const size_t pin_len)
{
    return store_blob(DEFAULT_NAMESPACE, WALLET_ERASE_PIN, pin, pin_len);
}

bool storage_get_wallet_erase_pin(uint8_t* pin, const size_t pin_len)
{
    return read_blob_fixed(DEFAULT_NAMESPACE, WALLET_ERASE_PIN, pin, pin_len);
}

bool storage_erase_wallet_erase_pin(void) { return erase_key(DEFAULT_NAMESPACE, WALLET_ERASE_PIN); }

// Generic multisig
bool storage_set_multisig_registration(const char* name, const uint8_t* registration, const size_t registration_len)
{
    return store_blob(MULTISIG_NAMESPACE, name, registration, registration_len);
}

bool storage_get_multisig_registration(
    const char* name, uint8_t* registration, const size_t registration_len, size_t* written)
{
    return read_blob(MULTISIG_NAMESPACE, name, registration, registration_len, written);
}

size_t storage_get_multisig_registration_count(void) { return get_entry_count(MULTISIG_NAMESPACE, NVS_TYPE_BLOB); }

bool storage_multisig_name_exists(const char* name) { return key_name_exists(name, MULTISIG_NAMESPACE, NVS_TYPE_BLOB); }

bool storage_get_all_multisig_registration_names(
    char names[][NVS_KEY_NAME_MAX_SIZE], const size_t num_names, size_t* num_written)
{
    return get_all_key_names(MULTISIG_NAMESPACE, NVS_TYPE_BLOB, names, num_names, num_written);
}

bool storage_erase_multisig_registration(const char* name) { return erase_key(MULTISIG_NAMESPACE, name); }

// Descriptor wallets
bool storage_set_descriptor_registration(const char* name, const uint8_t* registration, const size_t registration_len)
{
    return store_blob(DESCRIPTOR_NAMESPACE, name, registration, registration_len);
}

bool storage_get_descriptor_registration(
    const char* name, uint8_t* registration, const size_t registration_len, size_t* written)
{
    return read_blob(DESCRIPTOR_NAMESPACE, name, registration, registration_len, written);
}

size_t storage_get_descriptor_registration_count(void) { return get_entry_count(DESCRIPTOR_NAMESPACE, NVS_TYPE_BLOB); }

bool storage_descriptor_name_exists(const char* name)
{
    return key_name_exists(name, DESCRIPTOR_NAMESPACE, NVS_TYPE_BLOB);
}

bool storage_get_all_descriptor_registration_names(
    char names[][NVS_KEY_NAME_MAX_SIZE], const size_t num_names, size_t* num_written)
{
    return get_all_key_names(DESCRIPTOR_NAMESPACE, NVS_TYPE_BLOB, names, num_names, num_written);
}

bool storage_erase_descriptor_registration(const char* name) { return erase_key(DESCRIPTOR_NAMESPACE, name); }

// HOTP / TOTP
bool storage_set_otp_data(const char* name, const uint8_t* data, const size_t data_len)
{
    return store_blob(OTP_NAMESPACE, name, data, data_len);
}

bool storage_get_otp_data(const char* name, uint8_t* data, const size_t data_len, size_t* written)
{
    return read_blob(OTP_NAMESPACE, name, data, data_len, written);
}

bool storage_set_otp_hotp_counter(const char* name, const uint64_t counter)
{
    return store_blob(HOTP_COUNTERS_NAMESPACE, name, (uint8_t*)&counter, sizeof(counter));
}

uint64_t storage_get_otp_hotp_counter(const char* name)
{
    uint64_t counter = 0;
    return read_blob_fixed(HOTP_COUNTERS_NAMESPACE, name, (uint8_t*)&counter, sizeof(counter)) ? counter : 0;
}

size_t storage_get_otp_count(void) { return get_entry_count(OTP_NAMESPACE, NVS_TYPE_BLOB); }

bool storage_otp_exists(const char* name) { return key_name_exists(name, OTP_NAMESPACE, NVS_TYPE_BLOB); }

bool storage_get_all_otp_names(char names[][NVS_KEY_NAME_MAX_SIZE], const size_t num_names, size_t* num_written)
{
    return get_all_key_names(OTP_NAMESPACE, NVS_TYPE_BLOB, names, num_names, num_written);
}

bool storage_erase_otp(const char* name)
{
    // Erase any hotp counter, then erase the uri record
    erase_key(HOTP_COUNTERS_NAMESPACE, name);
    return erase_key(OTP_NAMESPACE, name);
}
#endif // AMALGAMATED_BUILD
