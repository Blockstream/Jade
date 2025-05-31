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
#include <deflate.h>

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
        *joctx->ota_return_status = error;                                                                             \
        return (joctx->id[0] != '\0') ? error : OTA_SUCCESS;                                                           \
    } while (false)

// If carrying an error, return ok immediately
// If we have an outstanding message we have not yet replied to, return the error now so it is messaged.
// If we do not have a message in hand at this time, return ok - the cached error will be sent
// the next time we receive a message and have the opportunity to reply.
#define HANDLE_ANY_CACHED_ERROR(joctx)                                                                                 \
    do {                                                                                                               \
        if (*joctx->ota_return_status != OTA_SUCCESS) {                                                                \
            return (joctx->id[0] != '\0') ? *joctx->ota_return_status : OTA_SUCCESS;                                   \
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
    const int ret = read_uncompressed(joctx->dctx, buffer, length);
    if (ret) {
        HANDLE_NEW_ERROR(joctx, ret);
    }

    *joctx->remaining_uncompressed -= length;

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

    if (length <= 0 || esp_ota_write(*joctx->ota_handle, buffer, length) != ESP_OK) {
        HANDLE_NEW_ERROR(joctx, OTA_ERR_PATCH);
    }

    if (!*joctx->validated_confirmed && length >= CUSTOM_HEADER_MIN_WRITE) {
        const enum ota_status validation = ota_user_validation(joctx, (uint8_t*)buffer);
        if (validation != OTA_SUCCESS) {
            HANDLE_NEW_ERROR(joctx, validation);
        }
        *joctx->validated_confirmed = true;
    }

    if (joctx->hash_type == HASHTYPE_FULLFWDATA) {
        // Add written to hash calculation
        JADE_ZERO_VERIFY(mbedtls_sha256_update(joctx->sha_ctx, buffer, length));
    }

    joctx->fwwritten += length;

    // For a patch, the amount of patch data uncompressed should always be more than the
    // amount of new firmware we have written, because of additional patch meta-data.
    JADE_ASSERT(joctx->uncompressedsize - *joctx->remaining_uncompressed > joctx->fwwritten);

    if (joctx->fwwritten > CUSTOM_HEADER_MIN_WRITE && !*joctx->validated_confirmed) {
        HANDLE_NEW_ERROR(joctx, OTA_ERR_PATCH);
    }

    if (*joctx->validated_confirmed) {
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
    return *joctx->ota_return_status;
}

void ota_delta_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;
    bool uploading = false;
    bool ota_end_called = false;
    bool ota_begin_called = false;

    mbedtls_sha256_context sha_ctx;

    esp_ota_handle_t ota_handle = 0;
    // Context used to compute (compressed) firmware hash - ie. file as uploaded
    enum ota_status ota_return_status = OTA_ERR_SETUP;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "ota_delta");
    GET_MSG_PARAMS(process);

    const jade_msg_source_t ota_source = process->ctx.source;
    if (keychain_has_pin()) {
        // NOTE: ota from internal source is allowed (eg. QR codes or USB storage)
        JADE_ASSERT(ota_source == (jade_msg_source_t)keychain_get_userdata() || ota_source == SOURCE_INTERNAL);
        JADE_ASSERT(!keychain_has_temporary());
    }

    size_t firmwaresize = 0;
    size_t compressedsize = 0;
    size_t uncompressedpatchsize = 0;

    if (!rpc_get_sizet("fwsize", &params, &firmwaresize) || !rpc_get_sizet("cmpsize", &params, &compressedsize)
        || !rpc_get_sizet("patchsize", &params, &uncompressedpatchsize) || firmwaresize <= compressedsize
        || uncompressedpatchsize <= compressedsize) {
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

    bool validated_confirmed = false;
    size_t remaining_uncompressed = uncompressedpatchsize;

    jade_ota_ctx_t joctx = {
        .progress_bar = {},
        .sha_ctx = &sha_ctx,
        .hash_type = hash_type,
        .ota_handle = &ota_handle,
        .dctx = dctx,
        .id = { 0 },
        .validated_confirmed = &validated_confirmed,
        .uncompressedsize = uncompressedpatchsize,
        .remaining_uncompressed = &remaining_uncompressed,
        .ota_return_status = &ota_return_status,
        .expected_source = &ota_source,
        .remaining_compressed = compressedsize,
        .firmwaresize = firmwaresize,
        .compressedsize = compressedsize,
        .expected_hash_hexstr = expected_hash_hexstr,
        .expected_hash = expected_hash,
        .extended_replies = extended_replies,
    };

    int ret = deflate_init_read_uncompressed(dctx, compressedsize, compressed_stream_reader, &joctx);
    JADE_ASSERT(!ret);

    if (!ota_init(&joctx)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to initialize OTA");
        goto cleanup;
    }

    ota_begin_called = true;

    // Send the ok response, which implies now we will get ota_data messages
    jade_process_reply_to_message_ok(process);
    uploading = true;

    struct bspatch_stream_n destination_firmware_stream_writer;
    // new partition
    destination_firmware_stream_writer.write = &ota_stream_writer;
    destination_firmware_stream_writer.opaque = &joctx;
    // patch
    struct bspatch_stream stream;
    stream.read = &patch_stream_reader;
    stream.opaque = &joctx;
    // old partition / base
    struct bspatch_stream_i basestream;
    basestream.read = &base_firmware_stream_reader;
    basestream.opaque = &joctx;

    ota_return_status = OTA_SUCCESS;
    ret = bspatch(
        &basestream, joctx.running_partition->size, &destination_firmware_stream_writer, firmwaresize, &stream);

    if (ret != OTA_SUCCESS) {
        JADE_LOGE("Error applying patch: %d", ret);
        ota_return_status = ret < 0 ? OTA_ERR_PATCH : ret;
        goto cleanup;
    }
    JADE_ASSERT(ota_begin_called);

    // Uploading complete
    uploading = false;

    if (joctx.fwwritten != firmwaresize) {
        ota_return_status = OTA_ERR_PATCH;
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
        jade_process_reject_message_ex(process->ctx, CBOR_RPC_INTERNAL_ERROR, "Error completing OTA delta",
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
        if (ota_begin_called && !ota_end_called) {
            // ota_begin has been called, cleanup
            const esp_err_t err = esp_ota_abort(ota_handle);
            JADE_ASSERT(err == ESP_OK);
        }

        // If we get here and we have not finished loading the data, send an error message
        const char* status_text = ota_get_status_text(ota_return_status);
        if (uploading) {
            if (joctx.id[0] == '\0') {
                // This should not happen under normal circumstances, but it could occur if the delta
                // uploaded is not appropriate for the base/running firmware (or perhaps is corrupted).
                // In that case bspatch() can fail unexpectedly - default the id.
                strcpy(joctx.id, "00");
            }
            const int error_code
                = ota_return_status == OTA_ERR_USERDECLINED ? CBOR_RPC_USER_CANCELLED : CBOR_RPC_INTERNAL_ERROR;

            uint8_t buf[256];
            jade_process_reject_message_with_id(joctx.id, error_code, "Error uploading OTA delta data",
                (const uint8_t*)status_text, strlen(status_text), buf, sizeof(buf), ota_source);
        }

        // If the error is not 'did not start' or 'user declined', show an error screen
        if (ota_return_status != OTA_ERR_SETUP && ota_return_status != OTA_ERR_USERDECLINED) {
            await_error_activity(&status_text, 1);
        }
    }
}
#endif // AMALGAMATED_BUILD
