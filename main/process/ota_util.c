#include "ota_util.h"
#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "ota_defines.h"

#include <ctype.h>
#include <deflate.h>
#include <esp_efuse.h>
#include <sodium/utils.h>
#include <string.h>

// UI screens to confirm ota
void make_ota_versions_activity(gui_activity_t** activity_ptr, const char* current_version, const char* new_version,
    const char* expected_hash_hexstr, bool full_fw_hash);
void make_show_ota_hash_activity(gui_activity_t** activity_ptr, const char* expected_hash_hexstr, bool full_fw_hash);

const __attribute__((section(".rodata_custom_desc"))) esp_custom_app_desc_t custom_app_desc
    = { .version = 1, .board_type = JADE_OTA_BOARD_TYPE, .features = JADE_OTA_FEATURES, .config = JADE_OTA_CONFIG };

static void send_ok(const char* id, const jade_msg_source_t source)
{
    JADE_ASSERT(id);

    uint8_t ok_msg[MAXLEN_ID + 10];
    bool ok = true;
    jade_process_reply_to_message_result_with_id(id, ok_msg, sizeof(ok_msg), source, &ok, cbor_result_boolean_cb);
}

void handle_in_bin_data(void* ctx, uint8_t* data, const size_t rawsize)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(data);
    JADE_ASSERT(rawsize >= 2);

    CborParser parser;
    CborValue value;
    const CborError cberr = cbor_parser_init(data + 1, rawsize - 1, CborValidateBasic, &parser, &value);
    JADE_ASSERT(cberr == CborNoError);
    JADE_ASSERT(rpc_request_valid(&value));

    jade_ota_ctx_t* joctx = (jade_ota_ctx_t*)ctx;

    size_t written = 0;
    JADE_ASSERT(joctx->id[0] == '\0');
    rpc_get_id(&value, joctx->id, MAXLEN_ID + 1, &written);
    JADE_ASSERT(written != 0);

    // If we are carrying a cached error abandon immediately
    // (the error will be returned with this id)
    if (*joctx->ota_return_status != SUCCESS) {
        return;
    }

    if (!rpc_is_method(&value, "ota_data")) {
        *joctx->ota_return_status = ERROR_BADDATA;
        return;
    }

    written = 0;
    const uint8_t* inbound_buf = NULL;

    rpc_get_bytes_ptr("params", &value, &inbound_buf, &written);

    if (written == 0 || data[0] != *joctx->expected_source || written > JADE_OTA_BUF_SIZE || !inbound_buf) {
        *joctx->ota_return_status = ERROR_BADDATA;
        return;
    }

    if (written > joctx->remaining_compressed) {
        JADE_LOGE("Received %u bytes when only needed %u", written, joctx->remaining_compressed);
        *joctx->ota_return_status = ERROR_BADDATA;
        return;
    }

    // Ideally we would send 'ok' message here, so we are decompressing this packet while the client
    // sends us the next.  However this seems to cause some data to be missed and some random OTA failures.
    // For the time being, send ok *after* the processing/decompression steps.

    // Return any non-zero error code from the decompress routine
    const int ret = joctx->dctx->write_compressed(joctx->dctx, (uint8_t* const)inbound_buf, written);
    if (ret) {
        *joctx->ota_return_status = ret < 0 ? ERROR_DECOMPRESS : ret;
        return;
    }

    if (joctx->hash_type == HASHTYPE_FILEDATA) {
        // Add received file data to hasher
        mbedtls_sha256_update(joctx->sha_ctx, inbound_buf, written);
    }

    joctx->remaining_compressed -= written;

    JADE_LOGI("Received ota_data msg %s, payload size %u", joctx->id, written);

    JADE_LOGI("compressed:   total = %u, current = %u", joctx->compressedsize,
        joctx->compressedsize - joctx->remaining_compressed);
    JADE_LOGI("uncompressed: total = %u, current = %u", joctx->uncompressedsize,
        joctx->uncompressedsize - *joctx->remaining_uncompressed);

    // Send ack after all processing - see comment above.
    JADE_LOGI("Sending ok for %s", joctx->id);
    send_ok(joctx->id, *joctx->expected_source);

    // Blank out the current msg id once 'ok' is sent for it
    joctx->id[0] = '\0';
}

bool ota_init(jade_ota_ctx_t* joctx)
{
    JADE_ASSERT(joctx);

    mbedtls_sha256_init(joctx->sha_ctx);
    joctx->running_partition = esp_ota_get_running_partition();
    JADE_ASSERT(joctx->running_partition);
    JADE_LOGI("Running partition ptr: %p", joctx->running_partition);

    // Check partition
    joctx->update_partition = esp_ota_get_next_update_partition(NULL);
    JADE_LOGI("Update partition: %p", joctx->update_partition);

    if (joctx->update_partition == NULL) {
        JADE_LOGE("Failed to get next update partition");
        return false;
    }

    if (joctx->update_partition == joctx->running_partition) {
        JADE_LOGE("Cannot OTA on running partition: %p", joctx->running_partition);
        return false;
    }

    mbedtls_sha256_starts(joctx->sha_ctx, 0);

    const esp_err_t err = esp_ota_begin(joctx->update_partition, joctx->firmwaresize, joctx->ota_handle);
    if (err != ESP_OK) {
        JADE_LOGE("Failed to begin ota, error: %d", err);
        return false;
    }

    return true;
}

enum ota_status post_ota_check(jade_ota_ctx_t* joctx, bool* ota_end_called)
{
    JADE_ASSERT(joctx);
    JADE_ASSERT(ota_end_called);

    // Ensure no cached error - if so return it now
    if (*joctx->ota_return_status != SUCCESS) {
        return *joctx->ota_return_status;
    }

    if (joctx->remaining_compressed || *joctx->remaining_uncompressed || !joctx->compressedsize
        || !joctx->uncompressedsize) {
        JADE_LOGE("OTA checks failed: uncompressed size: %u, compressed size: %u, remaining compressed %u, remaining "
                  "uncompressed %u",
            joctx->uncompressedsize, joctx->compressedsize, joctx->remaining_compressed,
            *joctx->remaining_uncompressed);
        return ERROR_OTA_INIT;
    }

    // Verify calculated compressed file hash matches expected
    uint8_t calculated_hash[SHA256_LEN];
    mbedtls_sha256_finish(joctx->sha_ctx, calculated_hash);

    JADE_ASSERT(joctx->expected_hash);
    JADE_ASSERT(joctx->expected_hash_hexstr);

    if (sodium_memcmp(joctx->expected_hash, calculated_hash, sizeof(calculated_hash))) {
        char* calc_hash_hexstr = NULL;
        JADE_WALLY_VERIFY(wally_hex_from_bytes(calculated_hash, sizeof(calculated_hash), &calc_hash_hexstr));

        JADE_LOGE("Firmware hash mismatch: expected: %s, got: %s", joctx->expected_hash_hexstr, calc_hash_hexstr);
        JADE_WALLY_VERIFY(wally_free_string(calc_hash_hexstr));

        return ERROR_BAD_HASH;
    }

    // All good, finalise the ota and set the partition to boot
    esp_err_t err = esp_ota_end(*joctx->ota_handle);
    *ota_end_called = true;

    if (err != ESP_OK) {
        JADE_LOGE("esp_ota_end() returned %d", err);
        return ERROR_FINISH;
    }

    err = esp_ota_set_boot_partition(joctx->update_partition);
    if (err != ESP_OK) {
        JADE_LOGE("esp_ota_set_boot_partition() returned %d", err);
        return ERROR_SETPARTITION;
    }

    return SUCCESS;
}

// NOTE: 'dest' is assumed to be at least as long as 'strlen(src)'
static void to_lower(char* dest, const char* src)
{
    while (*src) {
        *dest++ = tolower(*src++);
    }
    *dest = '\0';
}

enum ota_status ota_user_validation(jade_ota_ctx_t* joctx, const uint8_t* uncompressed)
{
    JADE_ASSERT(joctx);
    JADE_ASSERT(uncompressed);

    JADE_ASSERT(joctx->expected_hash);
    JADE_ASSERT(joctx->expected_hash_hexstr);
    JADE_ASSERT(joctx->update_partition);
    JADE_ASSERT(joctx->running_partition);
    JADE_ASSERT(joctx->ota_handle);

    esp_app_desc_t running_app_info;
    esp_err_t err = esp_ota_get_partition_description(joctx->running_partition, &running_app_info);
    if (err != ESP_OK) {
        JADE_LOGE("Failed to get running partition data, error: %d", err);
        return ERROR_BADPARTITION;
    }
    JADE_LOGI("Running firmware version: %s", running_app_info.version);

    // Check chip
    const esp_image_header_t* header = (esp_image_header_t*)uncompressed;
    if (header->chip_id != CONFIG_IDF_FIRMWARE_CHIP_ID) {
        JADE_LOGE("Mismatch chip id, expected %d, found %d", CONFIG_IDF_FIRMWARE_CHIP_ID, header->chip_id);
        return ERROR_INVALIDFW;
    }

    const size_t app_info_offset = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);
    const esp_app_desc_t* new_app_info = (esp_app_desc_t*)(uncompressed + app_info_offset);

    JADE_LOGI("New firmware version: %s", new_app_info->version);

    if (esp_efuse_check_secure_version(new_app_info->secure_version) == false) {
        JADE_LOGE("Secure version downgrade not allowed");
        return ERROR_NODOWNGRADE;
    }

    const size_t custom_info_offset = app_info_offset + sizeof(esp_app_desc_t);
    const esp_custom_app_desc_t* custom_info = (esp_custom_app_desc_t*)(uncompressed + custom_info_offset);

    // 'Board Type' and 'Features' must match.
    // 'Config' is allowed to differ.
    if (strcmp(JADE_OTA_BOARD_TYPE, custom_info->board_type)) {
        JADE_LOGE("Firmware board type mismatch %s %s", JADE_OTA_BOARD_TYPE, custom_info->board_type);
        return ERROR_INVALIDFW;
    }

    if (strcmp(JADE_OTA_FEATURES, custom_info->features)) {
        JADE_LOGE("Firmware features mismatch");
        return ERROR_INVALIDFW;
    }

    // User to confirm once new firmware version known and all checks passed
    char current_config[sizeof(JADE_OTA_CONFIG)];
    to_lower(current_config, JADE_OTA_CONFIG);
    char current_version[sizeof(running_app_info.version) + sizeof(current_config)];
    int rc = snprintf(current_version, sizeof(current_version), "%s %s", running_app_info.version, current_config);
    JADE_ASSERT(rc > 0 && rc < sizeof(current_version));

    char new_config[sizeof(custom_info->config)];
    to_lower(new_config, custom_info->config);
    char new_version[sizeof(new_app_info->version) + sizeof(new_config)];
    rc = snprintf(new_version, sizeof(new_version), "%s %s", new_app_info->version, new_config);
    JADE_ASSERT(rc > 0 && rc < sizeof(new_version));

    const bool full_fw_hash = joctx->hash_type == HASHTYPE_FULLFWDATA;

    gui_activity_t* ota_activity = NULL;
    make_ota_versions_activity(&ota_activity, current_version, new_version, joctx->expected_hash_hexstr, full_fw_hash);
    JADE_ASSERT(ota_activity);

    gui_activity_t* show_hash_activity = NULL;
    make_show_ota_hash_activity(&show_hash_activity, joctx->expected_hash_hexstr, full_fw_hash);
    JADE_ASSERT(show_hash_activity);

    bool ota_accepted = false;
    gui_activity_t* activity = ota_activity;
    while (!ota_accepted) {
        gui_set_current_activity(activity);

        int32_t ev_id;
        // In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_ACCEPT_OTA;
#endif

        if (ret) {
            switch (ev_id) {
            case BTN_OTA_VIEW_FW_HASH:
                activity = show_hash_activity;
                break;
            case BTN_OTA_HASH_CONFIRMED:
                activity = ota_activity;
                break;
            case BTN_ACCEPT_OTA:
                ota_accepted = true;
                break;
            case BTN_CANCEL_OTA:
                JADE_LOGW("User declined ota firmware version");
                return ERROR_USER_DECLINED;
            }
        }
    }

    // Now user has confirmed, display the progress bar
    display_progress_bar_activity("Firmware Upgrade", "Upload Progress:", &joctx->progress_bar);
    vTaskDelay(50 / portTICK_PERIOD_MS); // time for screen to update

    return SUCCESS;
}
