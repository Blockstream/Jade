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

    if (!joctx->validated_confirmed && length >= CUSTOM_HEADER_MIN_WRITE) {
        // We have the header: ask the user to confirm the OTA
        ota_user_validate(joctx, uncompressed);
        if (joctx->ota_return_status != OTA_SUCCESS) {
            return joctx->ota_return_status;
        }
    }

    const esp_err_t res = esp_ota_write(joctx->ota_handle, (const void*)uncompressed, length);
    if (res != ESP_OK) {
        JADE_LOGE("ota_write() error: %u", res);
        joctx->ota_return_status = OTA_ERR_WRITE;
        return DEFLATE_ERROR;
    }

    if (joctx->hash_type == HASHTYPE_FULLFWDATA) {
        // Add written to hash calculation
        JADE_ZERO_VERIFY(mbedtls_sha256_update(&joctx->sha_ctx, uncompressed, length));
    }

    joctx->remaining_uncompressed -= length;
    joctx->fwwritten += length;

    // For a full ota, the amount of fw data uncompressed should always be equal to the
    // amount of new firmware we have written, as it should be the same thing.
    JADE_ASSERT(joctx->uncompressedsize - joctx->remaining_uncompressed == joctx->fwwritten);

    if (joctx->fwwritten > CUSTOM_HEADER_MIN_WRITE && !joctx->validated_confirmed) {
        // It is theoretically possible for the writer to initially write
        // less than the header, which would cause us to skip validation.
        joctx->ota_return_status = OTA_ERR_DECOMPRESS;
        return DEFLATE_ERROR;
    }

    /* Update the progress bar once the user has confirmed and upload is in progress */
    if (joctx->validated_confirmed) {
        update_progress_bar(&joctx->progress_bar, joctx->uncompressedsize, joctx->fwwritten);
    }

    return DEFLATE_OK;
}

void ota_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    const bool is_delta = false;
    jade_ota_ctx_t* joctx = ota_init(process, is_delta);
    if (!joctx) {
        return; // The message has already been rejected
    }

    int ret = deflate_init_write_compressed(&joctx->dctx, joctx->compressedsize, uncompressed_stream_writer, joctx);
    JADE_ASSERT(!ret);

    // Send the ok response, which implies now we will get ota_data messages
    jade_process_reply_to_message_ok(process);
    bool uploading = true;

    joctx->ota_return_status = OTA_SUCCESS;
    while (joctx->remaining_compressed) {
        jade_process_get_in_message(joctx, &handle_in_bin_data, true);

        // NOTE: the ota_return_status can be set via ptr in joctx
        if (joctx->ota_return_status != OTA_SUCCESS) {
            JADE_LOGE("Error on ota_data message: %d", joctx->ota_return_status);
            goto cleanup;
        }
    }
    JADE_ASSERT(joctx->validated_confirmed);

    // Uploading complete
    uploading = false;

    // Bail-out if the fw uncompressed to an unexpected size
    if (joctx->remaining_uncompressed != 0) {
        JADE_LOGE("Expected uncompressed size: %u, got %u", joctx->firmwaresize,
            joctx->firmwaresize - joctx->remaining_uncompressed);
        joctx->ota_return_status = OTA_ERR_DECOMPRESS;
        goto cleanup;
    }
    if (joctx->fwwritten != joctx->firmwaresize) {
        JADE_LOGE("Expected amountof firmware written: %u, expected %u", joctx->fwwritten, joctx->firmwaresize);
        joctx->ota_return_status = OTA_ERR_DECOMPRESS;
        goto cleanup;
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
    ota_finalize(joctx);

    // Send final message reply with final status
    if (joctx->ota_return_status != OTA_SUCCESS) {
        uint8_t buf[256];
        const char* error = ota_get_status_text(joctx->ota_return_status);
        jade_process_reject_message_ex(process->ctx, CBOR_RPC_INTERNAL_ERROR, "Error completing OTA",
            (const uint8_t*)error, strlen(error), buf, sizeof(buf));
        goto cleanup;
    }

    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:

    // If ota has been successful show message and reboot.
    // If error, show error-message and await user acknowledgement.
    if (joctx->ota_return_status == OTA_SUCCESS) {
        JADE_LOGW("OTA successful - rebooting");

        const char* message[] = { "Upgrade successful!" };
        display_message_activity(message, 1);

        vTaskDelay(2500 / portTICK_PERIOD_MS);
        esp_restart();
    } else {
        JADE_LOGE("OTA error %u: %s", joctx->ota_return_status, ota_get_status_text(joctx->ota_return_status));

        // If we get here and we have not finished loading the data, send an error message
        const char* status_text = ota_get_status_text(joctx->ota_return_status);
        if (uploading) {
            JADE_ASSERT(joctx->id[0] != '\0');
            const int error_code
                = joctx->ota_return_status == OTA_ERR_USERDECLINED ? CBOR_RPC_USER_CANCELLED : CBOR_RPC_INTERNAL_ERROR;

            uint8_t buf[256];
            jade_process_reject_message_with_id(joctx->id, error_code, "Error uploading OTA data",
                (const uint8_t*)status_text, strlen(status_text), buf, sizeof(buf), joctx->expected_source);
        }

        // If the error is not 'did not start' or 'user declined', show an error screen
        if (joctx->ota_return_status != OTA_ERR_SETUP && joctx->ota_return_status != OTA_ERR_USERDECLINED) {
            await_error_activity(&status_text, 1);
        }
    }
}
#endif // AMALGAMATED_BUILD
