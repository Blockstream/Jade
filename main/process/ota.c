#ifndef AMALGAMATED_BUILD
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

#include <esp_efuse.h>
#include <esp_ota_ops.h>

#include <deflate.h>
#include <mbedtls/sha256.h>
#include <wally_core.h>

#include "process_utils.h"

/* this is called by the deflate library when it has uncompressed data to write */
static int uncompressed_stream_writer(void* ctx, uint8_t* uncompressed, size_t length)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(uncompressed);
    JADE_ASSERT(length);

    jade_ota_ctx_t* joctx = (jade_ota_ctx_t*)ctx;

    if (!*joctx->validated_confirmed && length >= CUSTOM_HEADER_MIN_WRITE) {
        const enum ota_status res = ota_user_validation(joctx, uncompressed);
        if (res != OTA_SUCCESS) {
            JADE_LOGE("ota_user_validation() error, %u", res);
            *joctx->ota_return_status = res;
            return res;
        }
        *joctx->validated_confirmed = true;
    }

    const esp_err_t res = esp_ota_write(*joctx->ota_handle, (const void*)uncompressed, length);
    if (res != ESP_OK) {
        JADE_LOGE("ota_write() error: %u", res);
        *joctx->ota_return_status = OTA_ERR_WRITE;
        return DEFLATE_ERROR;
    }

    if (joctx->hash_type == HASHTYPE_FULLFWDATA) {
        // Add written to hash calculation
        JADE_ZERO_VERIFY(mbedtls_sha256_update(joctx->sha_ctx, uncompressed, length));
    }

    *joctx->remaining_uncompressed -= length;
    joctx->fwwritten += length;

    // For a full ota, the amount of fw data uncompressed should always be equal to the
    // amount of new firmware we have written, as it should be the same thing.
    JADE_ASSERT(joctx->uncompressedsize - *joctx->remaining_uncompressed == joctx->fwwritten);

    if (joctx->fwwritten > CUSTOM_HEADER_MIN_WRITE && !*joctx->validated_confirmed) {
        return DEFLATE_ERROR;
    }

    /* Update the progress bar once the user has confirmed and upload is in progress */
    if (*joctx->validated_confirmed) {
        JADE_ASSERT(joctx->progress_bar.progress_bar);
        update_progress_bar(&joctx->progress_bar, joctx->uncompressedsize, joctx->fwwritten);
    }

    return DEFLATE_OK;
}

void ota_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());

    jade_process_t* process = process_ptr;
    bool uploading = false;
    enum ota_status ota_return_status = OTA_ERR_SETUP;
    bool validated_confirmed = false;
    bool ota_end_called = false;

    // Context used to compute (compressed) firmware hash - ie. file as uploaded
    mbedtls_sha256_context sha_ctx;
    esp_ota_handle_t ota_handle = 0;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "ota");
    GET_MSG_PARAMS(process);

    const jade_msg_source_t ota_source = process->ctx.source;
    if (keychain_has_pin()) {
        // NOTE: ota from internal source is allowed (eg. QR codes or USB storage)
        JADE_ASSERT(ota_source == (jade_msg_source_t)keychain_get_userdata() || ota_source == SOURCE_INTERNAL);
        JADE_ASSERT(!keychain_has_temporary());
    }

    size_t firmwaresize = 0;
    size_t compressedsize = 0;
    if (!rpc_get_sizet("fwsize", &params, &firmwaresize) || !rpc_get_sizet("cmpsize", &params, &compressedsize)
        || firmwaresize <= compressedsize) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Bad filesize parameters");
        goto cleanup;
    }

    // Optional field indicating preference for rich reply data
    bool extended_replies = false;
    rpc_get_boolean("extended_replies", &params, &extended_replies);

    // Can accept either uploaded file data hash (legacy) or hash of the full/final firmware image (preferred)
    uint8_t expected_hash[SHA256_LEN];
    char* expected_hash_hexstr = NULL;
    hash_type_t hash_type;
    if (rpc_get_n_bytes("fwhash", &params, sizeof(expected_hash), expected_hash)) {
        hash_type = HASHTYPE_FULLFWDATA;
    } else if (rpc_get_n_bytes("cmphash", &params, sizeof(expected_hash), expected_hash)) {
        hash_type = HASHTYPE_FILEDATA;
    } else {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Cannot extract valid fw hash value");
        goto cleanup;
    }
    JADE_WALLY_VERIFY(wally_hex_from_bytes(expected_hash, sizeof(expected_hash), &expected_hash_hexstr));
    jade_process_wally_free_string_on_exit(process, expected_hash_hexstr);

    // We will show a progress bar once the user has confirmed and the upload in progress
    // Initially just show a message screen.
    const char* message[] = { "Preparing for firmware", "", "update" };
    display_message_activity(message, 3);
    vTaskDelay(100 / portTICK_PERIOD_MS); // sleep a little bit to redraw screen

    struct deflate_ctx* dctx = JADE_MALLOC_PREFER_SPIRAM(sizeof(struct deflate_ctx));
    jade_process_free_on_exit(process, dctx);

    size_t remaining_uncompressed = firmwaresize;

    jade_ota_ctx_t joctx = {
        .progress_bar = {},
        .sha_ctx = &sha_ctx,
        .hash_type = hash_type,
        .dctx = dctx,
        .id = { 0 },
        .validated_confirmed = &validated_confirmed,
        .uncompressedsize = firmwaresize,
        .remaining_uncompressed = &remaining_uncompressed,
        .ota_return_status = &ota_return_status,
        .expected_source = &ota_source,
        .remaining_compressed = compressedsize,
        .compressedsize = compressedsize,
        .ota_handle = &ota_handle,
        .firmwaresize = firmwaresize,
        .expected_hash_hexstr = expected_hash_hexstr,
        .expected_hash = expected_hash,
        .extended_replies = extended_replies,
    };

    if (!ota_init(&joctx)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to initialize OTA");
        goto cleanup;
    }

    const int dret = deflate_init_write_compressed(dctx, compressedsize, uncompressed_stream_writer, &joctx);
    JADE_ASSERT(!dret);

    // Send the ok response, which implies now we will get ota_data messages
    jade_process_reply_to_message_ok(process);
    uploading = true;

    ota_return_status = OTA_SUCCESS;
    while (joctx.remaining_compressed) {
        jade_process_get_in_message(&joctx, &handle_in_bin_data, true);

        // NOTE: the ota_return_status can be set via ptr in joctx
        if (ota_return_status != OTA_SUCCESS) {
            JADE_LOGE("Error on ota_data message: %d", ota_return_status);
            goto cleanup;
        }
    }
    JADE_ASSERT(validated_confirmed);

    // Uploading complete
    uploading = false;

    // Bail-out if the fw uncompressed to an unexpected size
    if (remaining_uncompressed != 0) {
        JADE_LOGE("Expected uncompressed size: %u, got %u", firmwaresize, firmwaresize - remaining_uncompressed);
        ota_return_status = OTA_ERR_DECOMPRESS;
    }
    if (joctx.fwwritten != firmwaresize) {
        JADE_LOGE("Expected amountof firmware written: %u, expected %u", joctx.fwwritten, firmwaresize);
        ota_return_status = OTA_ERR_DECOMPRESS;
    }

    // Expect a complete/request for status
    jade_process_load_in_message(process, true);
    if (!IS_CURRENT_MESSAGE(process, "ota_complete")) {
        // Protocol error
        jade_process_reject_message(process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'ota_complete'");
        goto cleanup;
    }

    // If all good with the upload do all final checks and then finalise the ota
    // and set the new boot partition, etc.
    if (ota_return_status == OTA_SUCCESS) {
        ota_return_status = post_ota_check(&joctx, &ota_end_called);
    }

    // Send final message reply with final status
    if (ota_return_status != OTA_SUCCESS) {
        uint8_t buf[256];
        const char* error = ota_get_status_text(ota_return_status);
        jade_process_reject_message_ex(process->ctx, CBOR_RPC_INTERNAL_ERROR, "Error completing OTA",
            (const uint8_t*)error, strlen(error), buf, sizeof(buf));
        goto cleanup;
    }

    JADE_ASSERT(ota_end_called);
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    mbedtls_sha256_free(&sha_ctx);

    // If ota has been successful show message and reboot.
    // If error, show error-message and await user acknowledgement.
    if (ota_return_status == OTA_SUCCESS) {
        JADE_LOGW("OTA successful - rebooting");

        const char* message[] = { "Upgrade successful!" };
        display_message_activity(message, 1);

        vTaskDelay(2500 / portTICK_PERIOD_MS);
        esp_restart();
    } else {
        JADE_LOGE("OTA error %u: %s", ota_return_status, ota_get_status_text(ota_return_status));
        if (validated_confirmed && !ota_end_called) {
            // ota_begin has been called, cleanup
            const esp_err_t err = esp_ota_abort(ota_handle);
            JADE_ASSERT(err == ESP_OK);
        }

        // If we get here and we have not finished loading the data, send an error message
        const char* status_text = ota_get_status_text(ota_return_status);
        if (uploading) {
            JADE_ASSERT(joctx.id[0] != '\0');
            const int error_code
                = ota_return_status == OTA_ERR_USERDECLINED ? CBOR_RPC_USER_CANCELLED : CBOR_RPC_INTERNAL_ERROR;

            uint8_t buf[256];
            jade_process_reject_message_with_id(joctx.id, error_code, "Error uploading OTA data",
                (const uint8_t*)status_text, strlen(status_text), buf, sizeof(buf), ota_source);
        }

        // If the error is not 'did not start' or 'user declined', show an error screen
        if (ota_return_status != OTA_ERR_SETUP && ota_return_status != OTA_ERR_USERDECLINED) {
            await_error_activity(&status_text, 1);
        }
    }
}
#endif // AMALGAMATED_BUILD
