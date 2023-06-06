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

typedef struct {
    bool* prevalidated;
    jade_ota_ctx_t* joctx;
} ota_deflate_ctx_t;

/* this is called by the deflate library when it has uncompressed data to write */
static int uncompressed_stream_writer(void* ctx, uint8_t* uncompressed, size_t towrite)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(uncompressed);
    JADE_ASSERT(towrite);

    ota_deflate_ctx_t* octx = (ota_deflate_ctx_t*)ctx;
    JADE_ASSERT(octx->joctx);

    if (!*octx->prevalidated && towrite >= CUSTOM_HEADER_MIN_WRITE) {
        const enum ota_status res = ota_user_validation(octx->joctx, uncompressed);
        if (res != SUCCESS) {
            JADE_LOGE("ota_user_validation() error, %u", res);
            *octx->joctx->ota_return_status = res;
            return res;
        }
        *octx->prevalidated = true;
    }

    const esp_err_t res = esp_ota_write(*octx->joctx->ota_handle, (const void*)uncompressed, towrite);
    if (res != ESP_OK) {
        JADE_LOGE("ota_write() error: %u", res);
        *octx->joctx->ota_return_status = ERROR_WRITE;
        return DEFLATE_ERROR;
    }

    if (octx->joctx->hash_type == HASHTYPE_FULLFWDATA) {
        // Add written to hash calculation
        mbedtls_sha256_update(octx->joctx->sha_ctx, uncompressed, towrite);
    }

    *octx->joctx->remaining_uncompressed -= towrite;
    const size_t written = octx->joctx->uncompressedsize - *octx->joctx->remaining_uncompressed;

    /* Update the progress bar once the user has confirmed and upload is in progress */
    if (*octx->prevalidated) {
        JADE_ASSERT(octx->joctx->progress_bar.progress_bar);
        update_progress_bar(&octx->joctx->progress_bar, octx->joctx->uncompressedsize, written);
    }

    if (written > CUSTOM_HEADER_MIN_WRITE && !*octx->prevalidated) {
        return DEFLATE_ERROR;
    }

    return DEFLATE_OK;
}

void ota_process(void* process_ptr)
{
    JADE_LOGI("Starting: %lu", xPortGetFreeHeapSize());

    jade_process_t* process = process_ptr;
    bool uploading = false;
    enum ota_status ota_return_status = ERROR_OTA_SETUP;
    bool prevalidated = false;
    bool ota_end_called = false;

    char id[MAXLEN_ID + 1];
    id[0] = '\0';

    // Context used to compute (compressed) firmware hash - ie. file as uploaded
    mbedtls_sha256_context sha_ctx;
    esp_ota_handle_t ota_handle = 0;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "ota");
    GET_MSG_PARAMS(process);
    if (keychain_has_pin()) {
        ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
        JADE_ASSERT(!keychain_has_temporary());
    }

    const jade_msg_source_t source = process->ctx.source;

    size_t firmwaresize = 0;
    size_t compressedsize = 0;
    if (!rpc_get_sizet("fwsize", &params, &firmwaresize) || !rpc_get_sizet("cmpsize", &params, &compressedsize)
        || firmwaresize <= compressedsize) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Bad filesize parameters", NULL);
        goto cleanup;
    }

    // Can accept either uploaded file data hash (legacy) or hash of the full/final firmware image (preferred)
    uint8_t expected_hash[SHA256_LEN];
    char* expected_hash_hexstr = NULL;
    hash_type_t hash_type;
    if (rpc_get_n_bytes("fwhash", &params, sizeof(expected_hash), expected_hash)) {
        hash_type = HASHTYPE_FULLFWDATA;
    } else if (rpc_get_n_bytes("cmphash", &params, sizeof(expected_hash), expected_hash)) {
        hash_type = HASHTYPE_FILEDATA;
    } else {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Cannot extract valid fw hash value", NULL);
        goto cleanup;
    }
    JADE_WALLY_VERIFY(wally_hex_from_bytes(expected_hash, sizeof(expected_hash), &expected_hash_hexstr));
    jade_process_wally_free_string_on_exit(process, expected_hash_hexstr);

    // We will show a progress bar once the user has confirmed and the upload in progress
    // Initially just show a message screen.
    display_message_activity("\n\nPreparing for firmware\n\n            update");
    vTaskDelay(100 / portTICK_PERIOD_MS); // sleep a little bit to redraw screen

    struct deflate_ctx* dctx = JADE_MALLOC_PREFER_SPIRAM(sizeof(struct deflate_ctx));
    jade_process_free_on_exit(process, dctx);

    ota_deflate_ctx_t octx = {
        .prevalidated = &prevalidated,
    };

    size_t remaining_uncompressed = firmwaresize;

    jade_ota_ctx_t joctx = {
        .progress_bar = {},
        .sha_ctx = &sha_ctx,
        .hash_type = hash_type,
        .dctx = dctx,
        .id = id,
        .uncompressedsize = firmwaresize,
        .remaining_uncompressed = &remaining_uncompressed,
        .ota_return_status = &ota_return_status,
        .expected_source = &process->ctx.source,
        .remaining_compressed = compressedsize,
        .compressedsize = compressedsize,
        .ota_handle = &ota_handle,
        .firmwaresize = firmwaresize,
        .expected_hash_hexstr = expected_hash_hexstr,
        .expected_hash = expected_hash,
    };

    octx.joctx = &joctx;

    if (!ota_init(&joctx)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to initialize OTA", NULL);
        goto cleanup;
    }

    const int dret
        = deflate_init_write_compressed(dctx, compressedsize, firmwaresize, uncompressed_stream_writer, &octx);
    JADE_ASSERT(!dret);

    // Send the ok response, which implies now we will get ota_data messages
    jade_process_reply_to_message_ok(process);
    uploading = true;

    ota_return_status = SUCCESS;
    while (joctx.remaining_compressed) {
        jade_process_get_in_message(&joctx, &handle_in_bin_data, true);

        // NOTE: the ota_return_status can be set via ptr in joctx
        if (ota_return_status != SUCCESS) {
            JADE_LOGE("Error on ota_data message: %d", ota_return_status);
            goto cleanup;
        }
    }
    JADE_ASSERT(prevalidated);

    // Uploading complete
    uploading = false;

    // Bail-out if the fw uncompressed to an unexpected size
    if (remaining_uncompressed != 0) {
        JADE_LOGE("Expected uncompressed size: %u, got %u", firmwaresize, firmwaresize - remaining_uncompressed);
        ota_return_status = ERROR_DECOMPRESS;
    }

    // Expect a complete/request for status
    jade_process_load_in_message(process, true);
    if (!IS_CURRENT_MESSAGE(process, "ota_complete")) {
        // Protocol error
        jade_process_reject_message(
            process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'ota_complete'", NULL);
        goto cleanup;
    }

    // If all good with the upload do all final checks and then finalise the ota
    // and set the new boot partition, etc.
    if (ota_return_status == SUCCESS) {
        ota_return_status = post_ota_check(&joctx, &ota_end_called);
    }

    // Send final message reply with final status
    if (ota_return_status != SUCCESS) {
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Error completing OTA", MESSAGES[ota_return_status]);
        goto cleanup;
    }

    JADE_ASSERT(ota_end_called);
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    mbedtls_sha256_free(&sha_ctx);

    // If ota has been successful show message and reboot.
    // If error, show error-message and await user acknowledgement.
    if (ota_return_status == SUCCESS) {
        JADE_LOGW("OTA successful - rebooting");
        display_message_activity("Upgrade successful!");
        vTaskDelay(2500 / portTICK_PERIOD_MS);
        esp_restart();
    } else {
        JADE_LOGE("OTA error %u: %s", ota_return_status, MESSAGES[ota_return_status]);
        if (prevalidated && !ota_end_called) {
            // ota_begin has been called, cleanup
            const esp_err_t err = esp_ota_abort(ota_handle);
            JADE_ASSERT(err == ESP_OK);
        }

        // If we get here and we have not finished loading the data, send an error message
        if (uploading) {
            JADE_ASSERT(id[0] != '\0');
            const int error_code
                = ota_return_status == ERROR_USER_DECLINED ? CBOR_RPC_USER_CANCELLED : CBOR_RPC_INTERNAL_ERROR;

            uint8_t buf[256];
            jade_process_reject_message_with_id(id, error_code, "Error uploading OTA data",
                (const uint8_t*)MESSAGES[ota_return_status], strlen(MESSAGES[ota_return_status]), buf, sizeof(buf),
                source);
        }

        // If the error is not 'did not start' or 'user declined', show an error screen
        if (ota_return_status != ERROR_OTA_SETUP && ota_return_status != ERROR_USER_DECLINED) {
            await_error_activity(MESSAGES[ota_return_status]);
        }
    }
}
