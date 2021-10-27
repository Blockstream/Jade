#include "storage.h"
#include "jade_assert.h"
#include "keychain.h"
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

static const char* PIN_PRIVATEKEY_FIELD = "privatekey";
static const char* PIN_COUNTER_FIELD = "counter";
static const char* BLOB_FIELD = "blob";

static const char* USER_PINSERVER_URL_A = "pinsvrurlA";
static const char* USER_PINSERVER_URL_B = "pinsvrurlB";
static const char* USER_PINSERVER_PUBKEY = "pinsvrpubkey";
static const char* USER_PINSERVER_CERT = "pinsvrcert";

static const char* NETWORK_TYPE_FIELD = "networktype";
static const char* IDLE_TIMEOUT_FIELD = "idletimeout";
static const char* CLICK_EVENT_FIELD = "clickevent";
static const char* BLE_FLAGS_FIELD = "bleflags";

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

// Macro to persist a null-terminated string to nvs
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
            JADE_LOGE("nvs_get_blob() for %s failed: %u", k, err);                                                     \
            nvs_close(h);                                                                                              \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// Macro to fetch a null-terminated string from nvs
#define STORAGE_GET_STRING(h, k, v, l, pw)                                                                             \
    do {                                                                                                               \
        *pw = l;                                                                                                       \
        const esp_err_t err = nvs_get_str(h, k, v, pw);                                                                \
        if (err != ESP_OK) {                                                                                           \
            JADE_LOGE("nvs_get_str() for %s failed: %u", k, err);                                                      \
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

static bool store_blob(const char* ns, const char* name, const unsigned char* data, const size_t len)
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

static bool read_blob(const char* ns, const char* name, unsigned char* data, const size_t len, size_t* written)
{
    JADE_ASSERT(ns);
    JADE_ASSERT(name);
    JADE_ASSERT(data);
    JADE_ASSERT(len > 0);

    nvs_handle handle;
    STORAGE_OPEN(handle, ns, NVS_READONLY);
    STORAGE_GET_BLOB(handle, name, data, len, written);
    STORAGE_CLOSE(handle);
    return true;
}

static bool read_blob_fixed(const char* ns, const char* name, unsigned char* data, const size_t len)
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
    JADE_ASSERT(written);
    JADE_ASSERT(*written == 0);

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
    *entries_free = stats.free_entries;
    return true;
}

bool storage_get_pin_privatekey(unsigned char* privatekey, const size_t key_len)
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

bool storage_set_pin_privatekey(const unsigned char* privatekey, const size_t key_len)
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

bool storage_set_encrypted_blob(const unsigned char* encrypted, const size_t encrypted_len)
{
    JADE_ASSERT(encrypted);
    if (!storage_restore_counter()) {
        return false;
    }
    return store_blob(DEFAULT_NAMESPACE, BLOB_FIELD, encrypted, encrypted_len);
}

bool storage_get_encrypted_blob(unsigned char* encrypted, const size_t encrypted_len, size_t* written)
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

bool storage_set_pinserver_details(
    const char* urlA, const char* urlB, const unsigned char* pubkey, const size_t pubkey_len)
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

bool storage_get_pinserver_pubkey(unsigned char* pubkey, const size_t pubkey_len)
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
    return store_blob(DEFAULT_NAMESPACE, NETWORK_TYPE_FIELD, (unsigned char*)&networktype, sizeof(networktype));
}

network_type_t storage_get_network_type_restriction(void)
{
    network_type_t networktype = NETWORK_TYPE_NONE;
    return read_blob_fixed(DEFAULT_NAMESPACE, NETWORK_TYPE_FIELD, (unsigned char*)&networktype, sizeof(networktype))
        ? networktype
        : NETWORK_TYPE_NONE;
}

bool storage_set_idle_timeout(uint16_t timeout)
{
    return store_blob(DEFAULT_NAMESPACE, IDLE_TIMEOUT_FIELD, (const unsigned char*)&timeout, sizeof(timeout));
}

uint16_t storage_get_idle_timeout(void)
{
    uint16_t timeout = 0;
    return read_blob_fixed(DEFAULT_NAMESPACE, IDLE_TIMEOUT_FIELD, (unsigned char*)&timeout, sizeof(timeout)) ? timeout
                                                                                                             : 0;
}

bool storage_set_click_event(uint8_t event)
{
    return store_blob(DEFAULT_NAMESPACE, CLICK_EVENT_FIELD, &event, sizeof(event));
}

uint8_t storage_get_click_event(void)
{
    uint8_t event = 0;
    return read_blob_fixed(DEFAULT_NAMESPACE, CLICK_EVENT_FIELD, &event, sizeof(event)) ? event : 0;
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

bool storage_set_multisig_registration(const char* name, const uint8_t* registration, const size_t registration_len)
{
    return store_blob(MULTISIG_NAMESPACE, name, registration, registration_len);
}

bool storage_get_multisig_registration(
    const char* name, uint8_t* registration, const size_t registration_len, size_t* written)
{
    return read_blob(MULTISIG_NAMESPACE, name, registration, registration_len, written);
}

size_t storage_get_multisig_registration_count(void)
{
    size_t count = 0;
    nvs_iterator_t it = nvs_entry_find(NVS_DEFAULT_PART_NAME, MULTISIG_NAMESPACE, NVS_TYPE_BLOB);
    while (it != NULL) {
        it = nvs_entry_next(it);
        ++count;
    };
    return count;
}

bool storage_multisig_name_exists(const char* name)
{
    JADE_ASSERT(name);

    nvs_iterator_t it = nvs_entry_find(NVS_DEFAULT_PART_NAME, MULTISIG_NAMESPACE, NVS_TYPE_BLOB);
    while (it != NULL) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        if (strcmp(name, info.key) == 0) {
            nvs_release_iterator(it);
            return true;
        }
        it = nvs_entry_next(it);
    };

    return false;
}

bool storage_get_all_multisig_registration_names(
    char names[][NVS_KEY_NAME_MAX_SIZE], const size_t names_len, size_t* written)
{
    JADE_ASSERT(names);
    JADE_ASSERT(*names);
    JADE_ASSERT(names_len > 0);
    JADE_ASSERT(written);

    size_t count = 0;
    nvs_iterator_t it = nvs_entry_find(NVS_DEFAULT_PART_NAME, MULTISIG_NAMESPACE, NVS_TYPE_BLOB);
    while (it != NULL && count < names_len) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        strcpy(names[count], info.key);
        it = nvs_entry_next(it);
        ++count;
    };

    if (it) {
        nvs_release_iterator(it);
    }

    *written = count;
    return count <= names_len;
}

bool storage_erase_multisig_registration(const char* name) { return erase_key(MULTISIG_NAMESPACE, name); }
