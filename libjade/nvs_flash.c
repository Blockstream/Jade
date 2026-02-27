#include "nvs_flash.h"
#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>
#include <wally_map.h>

// HW: NVS storage
static struct wally_map nvs_storage[5]; // Map of field name to contents

// Binary NVS format: magic header (8 bytes) followed by entries.
// Each entry:
//   ns_len(uint8), ns(ns_len bytes),
//   key_len(uint8), key(key_len bytes),
//   value_len(uint32_t LE), value(value_len bytes).
static const char NVS_FILE_MAGIC[8] = { 'J', 'A', 'D', 'E', '_', 'N', 'V', 'S' };

static struct wally_map* get_nvs_ns(const char* ns)
{
    if (!strcmp(ns, DEFAULT_NAMESPACE)) {
        return &nvs_storage[0];
    }
    if (!strcmp(ns, MULTISIG_NAMESPACE)) {
        return &nvs_storage[1];
    }
    if (!strcmp(ns, DESCRIPTOR_NAMESPACE)) {
        return &nvs_storage[2];
    }
    if (!strcmp(ns, OTP_NAMESPACE)) {
        return &nvs_storage[3];
    }
    if (!strcmp(ns, HOTP_COUNTERS_NAMESPACE)) {
        return &nvs_storage[4];
    }
    return NULL;
}

#define ensure_n(n)                                                                                                    \
    do {                                                                                                               \
        if (p + n > end)                                                                                               \
            goto error;                                                                                                \
    } while (0)

esp_err_t libjade_load_nvs(const uint8_t* bytes, const size_t bytes_len)
{
    const uint8_t *p = bytes, *end = bytes + bytes_len;
    ensure_n(sizeof(NVS_FILE_MAGIC));
    if (memcmp(p, NVS_FILE_MAGIC, sizeof(NVS_FILE_MAGIC))) {
        goto error;
    }
    p += sizeof(NVS_FILE_MAGIC);
    while (p < end) {
        // ns_len(1), ns(ns_len)
        char ns[NVS_NS_NAME_MAX_SIZE] = { 0 };
        ensure_n(1 + p[0]);
        if (p[0] >= sizeof(ns)) {
            goto error;
        }
        memcpy(ns, p + 1, p[0]);
        p += 1 + p[0];

        // key_len(1), key(key_len), value_len(4), value(value_len)
        uint8_t key[NVS_KEY_NAME_MAX_SIZE] = { 0 };
        ensure_n(1);
        size_t key_len = p[0];
        ensure_n(1 + key_len);
        if (key_len >= sizeof(key)) {
            goto error;
        }
        memcpy(key, p + 1, key_len);
        p += 1 + p[0];

        // value_len(4), value(value_len)
        uint32_t value_len;
        ensure_n(sizeof(value_len));
        memcpy(&value_len, p, sizeof(value_len));
        value_len = le32toh(value_len);
        p += sizeof(value_len);
        ensure_n(value_len);

        struct wally_map* m = get_nvs_ns(ns);
        if (m) {
            wally_map_replace(m, key, key_len, p, value_len);
        }
        p += value_len;
    }
    return ESP_OK;
error:
    // TODO: Wipe NVS on failure?
    return ESP_ERR_INVALID_ARG;
}

esp_err_t libjade_save_nvs(uint8_t** output, size_t* output_len)
{
    const char* const ns_names[] = {
        DEFAULT_NAMESPACE,
        MULTISIG_NAMESPACE,
        DESCRIPTOR_NAMESPACE,
        OTP_NAMESPACE,
        HOTP_COUNTERS_NAMESPACE,
    };
    JADE_INIT_OUT_PPTR(output);
    JADE_INIT_OUT_SIZE(output_len);

    size_t required_len = sizeof(NVS_FILE_MAGIC);
    for (size_t i = 0; i < sizeof(ns_names) / sizeof(ns_names[0]); ++i) {
        const size_t ns_len = strlen(ns_names[i]);
        const struct wally_map* m = get_nvs_ns(ns_names[i]);
        JADE_ASSERT(m);
        for (size_t j = 0; j < m->num_items; ++j) {
            const struct wally_map_item* item = &m->items[j];
            required_len += 1 + ns_len + 1 + item->key_len + sizeof(uint32_t) + item->value_len;
        }
    }
    if (!required_len || !(*output = malloc(required_len))) {
        return ESP_FAIL;
    }
    uint8_t* p = *output;
    memcpy(p, NVS_FILE_MAGIC, sizeof(NVS_FILE_MAGIC));
    p += sizeof(NVS_FILE_MAGIC);
    for (size_t i = 0; i < sizeof(ns_names) / sizeof(ns_names[0]); ++i) {
        const size_t ns_len = strlen(ns_names[i]);
        const struct wally_map* m = get_nvs_ns(ns_names[i]);
        for (size_t j = 0; j < m->num_items; ++j) {
            const struct wally_map_item* item = &m->items[j];
            *p++ = ns_len;
            memcpy(p, ns_names[i], ns_len);
            p += ns_len;
            *p++ = (uint8_t)item->key_len;
            memcpy(p, item->key, item->key_len);
            p += item->key_len;
            const uint32_t value_len = htole32(item->value_len);
            memcpy(p, &value_len, sizeof(value_len));
            p += sizeof(value_len);
            memcpy(p, item->value, item->value_len);
            p += value_len;
        }
    }
    JADE_ASSERT(p - *output == required_len);
    *output_len = required_len;
    return ESP_OK;
}

esp_err_t nvs_flash_init(void) { return ESP_OK; }

esp_err_t nvs_open(const char* ns, nvs_open_mode_t open_mode, nvs_handle_t* out_handle)
{
    *out_handle = get_nvs_ns(ns);
    return *out_handle ? ESP_OK : ESP_ERR_NVS_NOT_FOUND;
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length)
{
    int ret = wally_map_replace(handle, (const unsigned char*)key, strlen(key), value, length);
    return ret == WALLY_OK ? ESP_OK : ESP_FAIL;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* out_value, size_t* length)
{
    const struct wally_map_item* item = wally_map_get(handle, (const unsigned char*)key, strlen(key));
    if (!item || item->value_len > *length) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    memcpy(out_value, item->value, item->value_len);
    *length = item->value_len;
    return ESP_OK;
}

esp_err_t nvs_set_str(nvs_handle_t handle, const char* key, const char* value)
{
    return nvs_set_blob(handle, key, value, strlen(value) + 1); // Include NUL terminator
}

esp_err_t nvs_get_str(nvs_handle_t handle, const char* key, char* out_value, size_t* length)
{
    return nvs_get_blob(handle, key, out_value, length);
}

esp_err_t nvs_set_u32(nvs_handle_t handle, const char* key, uint32_t value)
{
    const uint32_t le_value = htole32(value);
    return nvs_set_blob(handle, key, &le_value, sizeof(le_value));
}

esp_err_t nvs_get_u32(nvs_handle_t handle, const char* key, uint32_t* out_value)
{
    uint32_t le_value;
    size_t length = sizeof(le_value);
    const esp_err_t ret = nvs_get_blob(handle, key, &le_value, &length);
    if (ret == ESP_OK) {
        *out_value = le32toh(le_value);
    }
    return ret;
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key)
{
    if (wally_map_remove(handle, (const unsigned char*)key, strlen(key)) != WALLY_OK) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    return ESP_OK;
}

esp_err_t nvs_entry_find(const char* part_name, const char* ns, nvs_type_t type, nvs_iterator_t* output_iterator)
{
    *output_iterator = malloc(sizeof(**output_iterator));
    if (!*output_iterator) {
        return ESP_FAIL;
    }
    if (!((*output_iterator)->m = get_nvs_ns(ns)) || !(*output_iterator)->m->num_items) {
        goto fail;
    }
    // FIXME: Ignores type, pretty sure we only store the same type in each map?
    (*output_iterator)->idx = 0;
    return ESP_OK;
fail:
    free(*output_iterator);
    *output_iterator = NULL;
    return ESP_ERR_NVS_NOT_FOUND;
}

esp_err_t nvs_entry_next(nvs_iterator_t* iterator)
{
    ++(*iterator)->idx;
    if ((*iterator)->idx >= (*iterator)->m->num_items) {
        nvs_release_iterator(*iterator);
        *iterator = NULL;
        return ESP_ERR_NVS_NOT_FOUND;
    }
    return ESP_OK;
}

esp_err_t nvs_entry_info(const nvs_iterator_t iterator, nvs_entry_info_t* out_info)
{
    // FIXME: Only sets key, as thats all we ever read
    if (!iterator || iterator->idx >= iterator->m->num_items) {
        return ESP_ERR_INVALID_ARG;
    }
    const struct wally_map_item* item = iterator->m->items + iterator->idx;
    if (item->key_len >= NVS_KEY_NAME_MAX_SIZE) {
        abort();
    }
    memcpy(out_info->key, item->key, item->key_len);
    out_info->key[item->key_len] = '\0';
    return ESP_OK;
}

void nvs_release_iterator(nvs_iterator_t iterator)
{
    if (iterator) {
        free(iterator);
    }
}

esp_err_t nvs_flash_erase(void)
{
    for (size_t i = 0; i < sizeof(nvs_storage) / sizeof(nvs_storage[0]); ++i) {
        wally_map_clear(&nvs_storage[i]);
    }
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t handle) { return ESP_OK; }

esp_err_t nvs_get_stats(const char* part_name, nvs_stats_t* nvs_stats)
{
    nvs_stats->used_entries = 0;
    for (size_t i = 0; i < sizeof(nvs_storage) / sizeof(nvs_storage[0]); ++i) {
        nvs_stats->used_entries += nvs_storage[i].num_items;
    }
    nvs_stats->free_entries = ESP_NVS_TOTAL_ENTRIES - nvs_stats->used_entries;
    return ESP_OK;
}
