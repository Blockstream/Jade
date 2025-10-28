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
#include <bspatch.h>

// Error reply in ota_delta is complicated by the fact that we reply 'ok' when we push the received patch data
// into the decompressor, but we carry on copying the base firmware and inflating/applying patch data.
// If an error occurs at this stage - we have no message id to reply to so must cache the error until we do receive
// the next patch-data packet, when we can return the error.

// Cache any error in the context and return immediately.
// If we have an outstanding message we have not yet replied to, return the error now so it is messaged.
// If we do not have a message in hand at this time, just cache the error and return ok - it will be sent
// the next time we receive a message and have the opportunity to reply.
#define HANDLE_NEW_ERROR(joctx, error)                                                                                 \
    do {                                                                                                               \
        joctx->ota_return_status = error;                                                                              \
        return (joctx->id[0] != '\0') ? error : OTA_SUCCESS;                                                           \
    } while (false)

// If carrying an error, return ok immediately
// If we have an outstanding message we have not yet replied to, return the error now so it is messaged.
// If we do not have a message in hand at this time, return ok - the cached error will be sent
// the next time we receive a message and have the opportunity to reply.
#define HANDLE_ANY_CACHED_ERROR(joctx)                                                                                 \
    do {                                                                                                               \
        if (joctx->ota_return_status != OTA_SUCCESS) {                                                                 \
            return (joctx->id[0] != '\0') ? joctx->ota_return_status : OTA_SUCCESS;                                    \
        }                                                                                                              \
    } while (false)

// NOTE: uses macros above so may return error immediately, or may just cache it for later return
static int patch_stream_reader(const struct bspatch_stream* stream, void* buffer, int length)
{
    jade_ota_ctx_t* joctx = (jade_ota_ctx_t*)stream->opaque;
    JADE_ASSERT(joctx);

    if (length <= 0) {
        HANDLE_NEW_ERROR(joctx, OTA_ERR_PATCH);
    }

    // Return any non-zero error code from the read routine
    const int ret = read_uncompressed(&joctx->dctx, buffer, length);
    if (ret) {
        HANDLE_NEW_ERROR(joctx, ret);
    }

    joctx->remaining_uncompressed -= length;

    return OTA_SUCCESS;
}

// NOTE: uses macros above so may return error immediately, or may just cache it for later return
static int base_firmware_stream_reader(const struct bspatch_stream_i* stream, void* buffer, int pos, int length)
{
    jade_ota_ctx_t* joctx = (jade_ota_ctx_t*)stream->opaque;
    JADE_ASSERT(joctx);

    // If currently in error, return immediately without reading anything
    HANDLE_ANY_CACHED_ERROR(joctx);

    if (length <= 0 || pos + length >= joctx->running_partition->size
        || esp_partition_read(joctx->running_partition, pos, buffer, length) != ESP_OK) {
        HANDLE_NEW_ERROR(joctx, OTA_ERR_PATCH);
    }

    return OTA_SUCCESS;
}

// NOTE: uses macros above so may return error immediately, or may just cache it for later return
static int ota_stream_writer(const struct bspatch_stream_n* stream, const void* buffer, int length)
{
    jade_ota_ctx_t* joctx = (jade_ota_ctx_t*)stream->opaque;
    JADE_ASSERT(joctx);

    // If currently in error, return immediately without writing anything
    HANDLE_ANY_CACHED_ERROR(joctx);

    if (length <= 0 || esp_ota_write(joctx->ota_handle, buffer, length) != ESP_OK) {
        HANDLE_NEW_ERROR(joctx, OTA_ERR_PATCH);
    }

    if (!joctx->validated_confirmed && length >= CUSTOM_HEADER_MIN_WRITE) {
        // We have the header: ask the user to confirm the OTA
        ota_user_validate(joctx, (uint8_t*)buffer);
        if (joctx->ota_return_status != OTA_SUCCESS) {
            HANDLE_NEW_ERROR(joctx, joctx->ota_return_status);
        }
    }

    if (joctx->hash_type == HASHTYPE_FULLFWDATA) {
        // Add written to hash calculation
        JADE_ZERO_VERIFY(mbedtls_sha256_update(&joctx->sha_ctx, buffer, length));
    }

    joctx->fwwritten += length;

    // For a patch, the amount of patch data uncompressed should always be more than the
    // amount of new firmware we have written, because of additional patch meta-data.
    JADE_ASSERT(joctx->uncompressedsize - joctx->remaining_uncompressed > joctx->fwwritten);

    if (joctx->fwwritten > CUSTOM_HEADER_MIN_WRITE && !joctx->validated_confirmed) {
        // It is theoretically possible for the writer to initially write
        // less than the header, which would cause us to skip validation.
        HANDLE_NEW_ERROR(joctx, OTA_ERR_PATCH);
    }

    if (joctx->validated_confirmed) {
        update_progress_bar(&joctx->progress_bar, joctx->firmwaresize, joctx->fwwritten);
    }

    return OTA_SUCCESS;
}

static int compressed_stream_reader(void* ctx)
{
    JADE_ASSERT(ctx);

    jade_ota_ctx_t* joctx = (jade_ota_ctx_t*)ctx;

    // NOTE: the ota_return_status can be set via ptr in joctx
    // Return any error here as it can be returned to the caller in the message reply
    jade_process_get_in_message(joctx, &handle_in_bin_data, true);
    return joctx->ota_return_status;
}

void ota_delta_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    const bool is_delta = true;
    jade_ota_ctx_t* joctx = ota_init(process, is_delta);
    if (!joctx) {
        return; // The message has already been rejected
    }

    int ret = deflate_init_read_uncompressed(&joctx->dctx, joctx->compressedsize, compressed_stream_reader, joctx);
    JADE_ASSERT(!ret);

    // Send the ok response, which implies now we will get ota_data messages
    jade_process_reply_to_message_ok(process);
    bool uploading = true;

    struct bspatch_stream_n destination_firmware_stream_writer;
    // new partition
    destination_firmware_stream_writer.write = &ota_stream_writer;
    destination_firmware_stream_writer.opaque = joctx;
    // patch
    struct bspatch_stream stream;
    stream.read = &patch_stream_reader;
    stream.opaque = joctx;
    // old partition / base
    struct bspatch_stream_i basestream;
    basestream.read = &base_firmware_stream_reader;
    basestream.opaque = joctx;

    joctx->ota_return_status = OTA_SUCCESS;
    ret = bspatch(
        &basestream, joctx->running_partition->size, &destination_firmware_stream_writer, joctx->firmwaresize, &stream);

    if (ret != OTA_SUCCESS) {
        JADE_LOGE("Error applying patch: %d", ret);
        joctx->ota_return_status = ret < 0 ? OTA_ERR_PATCH : ret;
        goto cleanup;
    }

    // Uploading complete
    uploading = false;

    if (joctx->fwwritten != joctx->firmwaresize) {
        joctx->ota_return_status = OTA_ERR_PATCH;
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
    if (joctx->ota_return_status == OTA_SUCCESS) {
        joctx->ota_return_status = post_ota_check(joctx);
    }

    // Send final message reply with final status
    if (joctx->ota_return_status != OTA_SUCCESS) {
        uint8_t buf[256];
        const char* error = ota_get_status_text(joctx->ota_return_status);
        jade_process_reject_message_ex(process->ctx, CBOR_RPC_INTERNAL_ERROR, "Error completing OTA delta",
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
            if (joctx->id[0] == '\0') {
                // This should not happen under normal circumstances, but it could occur if the delta
                // uploaded is not appropriate for the base/running firmware (or perhaps is corrupted).
                // In that case bspatch() can fail unexpectedly - default the id.
                strcpy(joctx->id, "00");
            }
            const int error_code
                = joctx->ota_return_status == OTA_ERR_USERDECLINED ? CBOR_RPC_USER_CANCELLED : CBOR_RPC_INTERNAL_ERROR;

            uint8_t buf[256];
            jade_process_reject_message_with_id(joctx->id, error_code, "Error uploading OTA delta data",
                (const uint8_t*)status_text, strlen(status_text), buf, sizeof(buf), joctx->expected_source);
        }

        // If the error is not 'did not start' or 'user declined', show an error screen
        if (joctx->ota_return_status != OTA_ERR_SETUP && joctx->ota_return_status != OTA_ERR_USERDECLINED) {
            await_error_activity(&status_text, 1);
        }
    }
}
#endif // AMALGAMATED_BUILD
