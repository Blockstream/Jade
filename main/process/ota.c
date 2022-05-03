#include "../keychain.h"
#include "../process.h"
#include "../ui.h"
#include "ota_defines.h"
#include "ota_util.h"

#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"

#include <stdint.h>

#include <esp32/rom/miniz.h>
#include <esp_efuse.h>
#include <esp_ota_ops.h>

#include <mbedtls/sha256.h>
#include <sodium/utils.h>
#include <wally_core.h>

#include "process_utils.h"

// Timeout total 20s (40ms blocking on msg)
#define DEFAULT_TIMEOUT_BEGIN 500

static enum ota_status ota_init(const char* expected_hash_hexstr, const uint8_t* uncompressed,
    esp_partition_t const** update_partition, const size_t firmwaresize, esp_ota_handle_t* update_handle,
    progress_bar_t* progress_bar)
{
    // TODO - uncomment when hash mandatory
    // JADE_ASSERT(expected_hash_hexstr);
    JADE_ASSERT(uncompressed);
    JADE_ASSERT(update_handle);
    JADE_ASSERT(progress_bar);
    JADE_INIT_OUT_PPTR(update_partition);

    const esp_partition_t* running = esp_ota_get_running_partition();
    JADE_LOGI("Running partition ptr: %p", running);

    esp_app_desc_t running_app_info;
    esp_err_t err = esp_ota_get_partition_description(running, &running_app_info);
    if (err != ESP_OK) {
        JADE_LOGE("Failed to get running partition data, error: %d", err);
        return ERROR_BADPARTITION;
    }
    JADE_LOGI("Running firmware version: %s", running_app_info.version);

    const size_t offset = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);
    const esp_app_desc_t* new_app_info = (const esp_app_desc_t*)(uncompressed + offset);

    // Sanity check that the version string is reasonable (ie. length)
    if (strnlen(new_app_info->version, VERSION_STRING_MAX_LENGTH + 1) > VERSION_STRING_MAX_LENGTH) {
        JADE_LOGE("Firmware version string appears invalid - longer than %u characters", VERSION_STRING_MAX_LENGTH);
        return ERROR_INVALIDFW;
    }
    JADE_LOGI("New firmware version: %s", new_app_info->version);

    if (esp_efuse_check_secure_version(new_app_info->secure_version) == false) {
        JADE_LOGE("Secure version downgrade not allowed");
        return ERROR_NODOWNGRADE;
    }

    // Skip checking custom fields for the fw version before that struct was added.
    // This leaves a possibility of flashing an inappropriate (old) fw onto a device,
    // (which could brick it!) but this may be needed should we need to downgrade.
    // FIXME: Remove this fudge in fw 0.1.27+
    if (strcmp(new_app_info->version, "0.1.25")) {
        if (!validate_custom_app_desc(offset, uncompressed)) {
            return ERROR_INVALIDFW;
        }
    }

    // Check partition
    *update_partition = esp_ota_get_next_update_partition(NULL);
    JADE_LOGI("Update partition: %p", *update_partition);

    if (*update_partition == NULL) {
        JADE_LOGE("Failed to get next update partition");
        return ERROR_BADPARTITION;
    }

    if (*update_partition == running) {
        JADE_LOGE("Cannot OTA on running partition: %p", running);
        return ERROR_BADPARTITION;
    }

    // User to confirm once new firmware version known and all checks passed
    gui_activity_t* activity;
    make_ota_versions_activity(&activity, running_app_info.version, new_app_info->version, expected_hash_hexstr);
    JADE_ASSERT(activity);

    gui_set_current_activity(activity);

    int32_t ev_id;
    // In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const bool ret = true;
    ev_id = BTN_ACCEPT_OTA;
#endif

    if (!ret || ev_id != BTN_ACCEPT_OTA) {
        JADE_LOGW("User declined ota firmware version");
        return ERROR_USER_DECLINED;
    }

    // Now user has confirmed, display the progress bar
    display_progress_bar_activity("Firmware Upgrade", "Upload Progress:", progress_bar);
    vTaskDelay(50); // time for screen to update

    // Good to go - initialise the ota
    err = esp_ota_begin(*update_partition, firmwaresize, update_handle);
    if (err != ESP_OK) {
        JADE_LOGE("Failed to begin ota, error: %d", err);
        return ERROR_OTA_INIT;
    }

    return SUCCESS;
}

void ota_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;
    bool uploading = false;
    enum ota_status ota_return_status = ERROR_OTA_SETUP;
    bool prevalidated = false;
    bool ota_end_called = false;

    esp_ota_handle_t update_handle = 0;
    esp_partition_t const* update_partition = NULL;
    esp_err_t err = ESP_FAIL;

    // Context used to compute (compressed) firmware hash - ie. file as uploaded
    mbedtls_sha256_context cmp_sha_ctx;
    mbedtls_sha256_init(&cmp_sha_ctx);

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "ota");
    GET_MSG_PARAMS(process);

    const jade_msg_source_t source = process->ctx.source;

    size_t firmwaresize = 0;
    size_t compressedsize = 0;
    if (!rpc_get_sizet("fwsize", &params, &firmwaresize) || !rpc_get_sizet("cmpsize", &params, &compressedsize)
        || firmwaresize <= compressedsize) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Bad filesize parameters", NULL);
        goto cleanup;
    }

    // TODO: make hash mandatory in a future release
    uint8_t expected_hash[SHA256_LEN];
    size_t expected_hash_len = 0;
    char* expected_hash_hexstr = NULL;
    if (rpc_has_field_data("cmphash", &params)) {
        rpc_get_bytes("cmphash", sizeof(expected_hash), &params, expected_hash, &expected_hash_len);
        if (expected_hash_len != HMAC_SHA256_LEN) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Cannot extract valid fw hash value", NULL);
            goto cleanup;
        }
        JADE_WALLY_VERIFY(wally_hex_from_bytes(expected_hash, expected_hash_len, &expected_hash_hexstr));
        jade_process_wally_free_string_on_exit(process, expected_hash_hexstr);
    }

    int res = mbedtls_sha256_starts_ret(&cmp_sha_ctx, 0); // 0 = SHA256 instead of SHA224
    if (res != 0) {
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Failed to initialise compressed firmware hash", NULL);
        goto cleanup;
    }

    // sizeof(tinfl_decompressor) is just over 10k, no perfs diff vs DRAM
    tinfl_decompressor* decomp = JADE_MALLOC_PREFER_SPIRAM(sizeof(tinfl_decompressor));
    jade_process_free_on_exit(process, decomp);
    tinfl_init(decomp);

    uint32_t remaining_compressed = compressedsize;
    uint32_t remaining = firmwaresize;

    size_t timeout = DEFAULT_TIMEOUT_BEGIN;

    int status = TINFL_STATUS_NEEDS_MORE_INPUT;

    // if uncompressed is in DRAM esp_ota_write performs 2-3X better vs SPIRAM
    uint8_t* uncompressed = JADE_MALLOC_DRAM(UNCOMPRESSED_BUF_SIZE);
    jade_process_free_on_exit(process, uncompressed);

    uint8_t* nout = uncompressed;

    // Send the ok response, which implies now we will get ota_data messages
    jade_process_reply_to_message_ok(process);

    // We will show a progress bar once the user has confirmed and the upload in progress
    // Initially just show a message screen.
    progress_bar_t progress_bar = { .progress_bar = NULL, .pcnt_txt = NULL, .percent_last_value = 0 };
    display_message_activity_two_lines("Preparing for firmware", "update");

    vTaskDelay(200 / portTICK_PERIOD_MS); // sleep a little bit

    struct bin_msg binctx = { .inbound_buf = JADE_MALLOC_PREFER_SPIRAM(JADE_OTA_BUF_SIZE) };
    jade_process_free_on_exit(process, binctx.inbound_buf);
    ota_return_status = SUCCESS;
    while (remaining_compressed) {
        if (!timeout) {
            JADE_LOGE("OTA Timeout");
            ota_return_status = ERROR_TIMEOUT;
            goto cleanup;
        }

        reset_ctx(&binctx, binctx.inbound_buf, source);
        jade_process_get_in_message(&binctx, &handle_in_bin_data, false); // non-blocking, we want to detect timeouts

        if (binctx.error) {
            JADE_LOGE("Error on ota_data message");
            ota_return_status = ERROR_BADDATA;
            goto cleanup;
        }

        if (!binctx.loaded) {
            --timeout;
            JADE_LOGD("OTA message timeout, retries remaining: %u", timeout);
            continue;
        }

        // reset timeouts
        timeout = DEFAULT_TIMEOUT_BEGIN;
        uploading = true;

        JADE_LOGI("Received ota_data msg %s, payload size %u", binctx.id, binctx.len);

        if (binctx.len > remaining_compressed) {
            JADE_LOGE("Received %u bytes when only needed %u", binctx.len, remaining_compressed);
            ota_return_status = ERROR_BADDATA;
            goto cleanup;
        }

        // Add to cmp-file hasher
        if (mbedtls_sha256_update_ret(&cmp_sha_ctx, binctx.inbound_buf, binctx.len) != 0) {
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to build firmware hash", NULL);
            goto cleanup;
        }

        size_t length = binctx.len;
        const uint8_t* data_buf = binctx.inbound_buf;
        while (length > 0 && remaining > 0 && status > TINFL_STATUS_DONE) {
            size_t in_bytes = length;
            size_t out_bytes = uncompressed + UNCOMPRESSED_BUF_SIZE - nout;
            int flags = TINFL_FLAG_PARSE_ZLIB_HEADER;
            if (remaining_compressed > length) {
                flags |= TINFL_FLAG_HAS_MORE_INPUT;
            }

            status = tinfl_decompress(decomp, data_buf, &in_bytes, uncompressed, nout, &out_bytes, flags);

            remaining_compressed -= in_bytes;
            length -= in_bytes;
            data_buf += in_bytes;

            nout += out_bytes;
            const size_t towrite = nout - uncompressed;
            if ((prevalidated && status <= TINFL_STATUS_DONE) || towrite == UNCOMPRESSED_BUF_SIZE) {
                if (!prevalidated) {
                    const enum ota_status res = ota_init(expected_hash_hexstr, uncompressed, &update_partition,
                        firmwaresize, &update_handle, &progress_bar);
                    if (res != SUCCESS) {
                        JADE_LOGE("ota_init() error, %u", res);
                        ota_return_status = res;
                        goto cleanup;
                    }
                    prevalidated = true;
                }

                const esp_err_t res = esp_ota_write(update_handle, (const void*)uncompressed, towrite);
                if (res != ESP_OK) {
                    JADE_LOGE("ota_write() error: %u", res);
                    ota_return_status = ERROR_WRITE;
                    goto cleanup;
                }

                remaining -= towrite;
                nout = uncompressed;
            }
        }

        // Update the progress bar once the user has confirmed and upload is in progress
        if (prevalidated) {
            JADE_ASSERT(progress_bar.progress_bar);
            update_progress_bar(&progress_bar, compressedsize, compressedsize - remaining_compressed);
        }
        JADE_LOGI("compressed:   total = %u, current = %u", compressedsize, compressedsize - remaining_compressed);
        JADE_LOGI("uncompressed: total = %u, current = %u", firmwaresize, firmwaresize - remaining);

        if ((status != TINFL_STATUS_DONE && remaining_compressed == 0) || (status < TINFL_STATUS_DONE)
            || (status == TINFL_STATUS_DONE && remaining_compressed > 0)) {
            JADE_LOGE("Data decompression error");
            ota_return_status = ERROR_DECOMPRESS;
            goto cleanup;
        }

        JADE_LOGI("Sending ok for %s", binctx.id);
        send_ok(binctx.id, source);
    }

    // Uploading complete
    uploading = false;

    // Bail-out if the fw uncompressed to an unexpected size
    if (remaining != 0) {
        JADE_LOGE("Expected uncompressed size: %u, got %u", firmwaresize, firmwaresize - remaining);
        ota_return_status = ERROR_DECOMPRESS;
        goto otacomplete;
    }

    // Verify calculated compressed file hash matches expected
    uint8_t calculated_hash[SHA256_LEN];
    if (mbedtls_sha256_finish_ret(&cmp_sha_ctx, calculated_hash) != 0) {
        JADE_LOGE("Failed to compute fw file hash");
        ota_return_status = ERROR_BAD_HASH;
        goto otacomplete;
    }

    // If we were provided the expected cmpfile hash, check it matches
    // TODO: make hash mandatory in a future release
    if (expected_hash_len) {
        JADE_ASSERT(expected_hash_hexstr);

        if (expected_hash_len != sizeof(calculated_hash)
            || sodium_memcmp(expected_hash, calculated_hash, sizeof(calculated_hash))) {
            char* calc_hash_hexstr = NULL;
            JADE_WALLY_VERIFY(wally_hex_from_bytes(calculated_hash, sizeof(calculated_hash), &calc_hash_hexstr));

            JADE_LOGE("Firmware hash mismatch: expected: %s, got: %s", expected_hash_hexstr, calc_hash_hexstr);
            JADE_WALLY_VERIFY(wally_free_string(calc_hash_hexstr));

            ota_return_status = ERROR_BAD_HASH;
            goto otacomplete;
        }
    }

    // All good, finalise the ota and set the partition to boot
    err = esp_ota_end(update_handle);
    ota_end_called = true;
    if (err != ESP_OK) {
        JADE_LOGE("esp_ota_end() returned %d", err);
        ota_return_status = ERROR_FINISH;
        goto otacomplete;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        JADE_LOGE("esp_ota_set_boot_partition() returned %d", err);
        ota_return_status = ERROR_SETPARTITION;
        goto otacomplete;
    }

    JADE_ASSERT(prevalidated);
    JADE_LOGI("Success");

otacomplete:
    // Expect a complete/request for status
    jade_process_load_in_message(process, true);

    if (!IS_CURRENT_MESSAGE(process, "ota_complete")) {
        // Protocol error
        jade_process_reject_message(
            process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'ota_complete'", NULL);
    } else if (ota_return_status != SUCCESS) {
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Error completing OTA", MESSAGES[ota_return_status]);
    } else {
        jade_process_reply_to_message_ok(process);
    }

cleanup:
    mbedtls_sha256_free(&cmp_sha_ctx);

    // If ota has been successful show message and reboot.
    // If error, show error-message and await user acknowledgement.
    if (ota_return_status == SUCCESS) {
        JADE_LOGW("OTA successful - rebooting");
        display_message_activity("Upgrade successful!");
        vTaskDelay(2500 / portTICK_PERIOD_MS);
        esp_restart();
    } else {
        JADE_LOGW("OTA error %u", ota_return_status);
        if (prevalidated && !ota_end_called) {
            // ota_begin has been called, cleanup
            err = esp_ota_abort(update_handle);
            JADE_ASSERT(err == ESP_OK);
        }

        // If we get here and we have not finished loading the data, send an error message
        if (uploading) {
            uint8_t buf[256];
            jade_process_reject_message_with_id(binctx.id, CBOR_RPC_INTERNAL_ERROR, "Error uploading OTA data",
                (const uint8_t*)MESSAGES[ota_return_status], strlen(MESSAGES[ota_return_status]), buf, sizeof(buf),
                source);
        }

        // If the error is not 'did not start' or 'user declined', show an error screen
        if (ota_return_status != ERROR_OTA_SETUP && ota_return_status != ERROR_USER_DECLINED) {
            await_error_activity(MESSAGES[ota_return_status]);
        }
    }
}
