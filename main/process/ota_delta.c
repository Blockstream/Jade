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

typedef struct {
    jade_ota_ctx_t* joctx;
    char* id;
    struct deflate_ctx* const dctx;
    size_t written;
    bool header_validated;
} bsdiff_ctx_t;

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
        return (joctx->id[0] != '\0') ? error : SUCCESS;                                                               \
    } while (false)

// If carrying an error, return ok immediately
// If we have an outstanding message we have not yet replied to, return the error now so it is messaged.
// If we do not have a message in hand at this time, return ok - the cached error will be sent
// the next time we receive a message and have the opportunity to reply.
#define HANDLE_ANY_CACHED_ERROR(joctx)                                                                                 \
    do {                                                                                                               \
        if (*joctx->ota_return_status != SUCCESS) {                                                                    \
            return (joctx->id[0] != '\0') ? *joctx->ota_return_status : SUCCESS;                                       \
        }                                                                                                              \
    } while (false)

// NOTE: uses macros above so may return error immediately, or may just cache it for later return
static int patch_stream_reader(const struct bspatch_stream* stream, void* buffer, int length)
{
    bsdiff_ctx_t* bctx = (bsdiff_ctx_t*)stream->opaque;
    JADE_ASSERT(bctx);

    if (length <= 0) {
        HANDLE_NEW_ERROR(bctx->joctx, ERROR_PATCH);
    }

    // Return any non-zero error code from the read routine
    const int ret = read_uncompressed(bctx->dctx, buffer, length);
    if (ret) {
        HANDLE_NEW_ERROR(bctx->joctx, ret);
    }

    *bctx->joctx->remaining_uncompressed -= length;

    return SUCCESS;
}

// NOTE: uses macros above so may return error immediately, or may just cache it for later return
static int base_firmware_stream_reader(const struct bspatch_stream_i* stream, void* buffer, int pos, int length)
{
    bsdiff_ctx_t* bctx = (bsdiff_ctx_t*)stream->opaque;
    JADE_ASSERT(bctx);

    // If currently in error, return immediately without reading anything
    HANDLE_ANY_CACHED_ERROR(bctx->joctx);

    if (length <= 0 || pos + length >= bctx->joctx->running_partition->size
        || esp_partition_read(bctx->joctx->running_partition, pos, buffer, length) != ESP_OK) {
        HANDLE_NEW_ERROR(bctx->joctx, ERROR_PATCH);
    }

    return SUCCESS;
}

// NOTE: uses macros above so may return error immediately, or may just cache it for later return
static int ota_stream_writer(const struct bspatch_stream_n* stream, const void* buffer, int length)
{
    bsdiff_ctx_t* bctx = (bsdiff_ctx_t*)stream->opaque;
    JADE_ASSERT(bctx);

    // If currently in error, return immediately without writing anything
    HANDLE_ANY_CACHED_ERROR(bctx->joctx);

    if (length <= 0 || esp_ota_write(*bctx->joctx->ota_handle, buffer, length) != ESP_OK) {
        HANDLE_NEW_ERROR(bctx->joctx, ERROR_PATCH);
    }

    if (!bctx->header_validated && length >= CUSTOM_HEADER_MIN_WRITE) {
        const enum ota_status validation = ota_user_validation(bctx->joctx, (uint8_t*)buffer);
        if (validation != SUCCESS) {
            HANDLE_NEW_ERROR(bctx->joctx, validation);
        }
        bctx->header_validated = true;
    }

    if (bctx->joctx->hash_type == HASHTYPE_FULLFWDATA) {
        // Add written to hash calculation
        JADE_ZERO_VERIFY(mbedtls_sha256_update(bctx->joctx->sha_ctx, buffer, length));
    }

    bctx->written += length;

    if (bctx->written > CUSTOM_HEADER_MIN_WRITE && !bctx->header_validated) {
        HANDLE_NEW_ERROR(bctx->joctx, ERROR_PATCH);
    }

    if (bctx->header_validated) {
        update_progress_bar(&bctx->joctx->progress_bar, bctx->joctx->firmwaresize, bctx->written);
    }

    return SUCCESS;
}

static int compressed_stream_reader(void* ctx)
{
    JADE_ASSERT(ctx);

    bsdiff_ctx_t* bctx = (bsdiff_ctx_t*)ctx;
    JADE_ASSERT(bctx->joctx);

    // NOTE: the ota_return_status can be set via ptr in joctx
    // Return any error here as it can be returned to the caller in the message reply
    jade_process_get_in_message(bctx->joctx, &handle_in_bin_data, true);
    return *bctx->joctx->ota_return_status;
}

void ota_delta_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;
    bool uploading = false;
    bool ota_end_called = false;
    bool ota_begin_called = false;
    char id[MAXLEN_ID + 1];
    id[0] = '\0';

    mbedtls_sha256_context sha_ctx;

    esp_ota_handle_t ota_handle = 0;
    // Context used to compute (compressed) firmware hash - ie. file as uploaded
    enum ota_status ota_return_status = ERROR_OTA_SETUP;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "ota_delta");
    GET_MSG_PARAMS(process);
    if (keychain_has_pin()) {
        ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
        JADE_ASSERT(!keychain_has_temporary());
    }

    size_t firmwaresize = 0;
    size_t compressedsize = 0;
    size_t uncompressedpatchsize = 0;

    if (!rpc_get_sizet("fwsize", &params, &firmwaresize) || !rpc_get_sizet("cmpsize", &params, &compressedsize)
        || !rpc_get_sizet("patchsize", &params, &uncompressedpatchsize) || firmwaresize <= compressedsize
        || uncompressedpatchsize <= compressedsize) {
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
    const char* message[] = { "Preparing for firmware", "", "update" };
    display_message_activity(message, 3);
    vTaskDelay(100 / portTICK_PERIOD_MS); // sleep a little bit to redraw screen

    struct deflate_ctx* dctx = JADE_MALLOC_PREFER_SPIRAM(sizeof(struct deflate_ctx));
    jade_process_free_on_exit(process, dctx);

    bsdiff_ctx_t bctx = {
        .dctx = dctx,
    };

    size_t remaining_uncompressed = uncompressedpatchsize;

    jade_ota_ctx_t joctx = {
        .progress_bar = {},
        .sha_ctx = &sha_ctx,
        .hash_type = hash_type,
        .ota_handle = &ota_handle,
        .dctx = dctx,
        .id = id,
        .uncompressedsize = uncompressedpatchsize,
        .remaining_uncompressed = &remaining_uncompressed,
        .ota_return_status = &ota_return_status,
        .expected_source = &process->ctx.source,
        .remaining_compressed = compressedsize,
        .firmwaresize = firmwaresize,
        .compressedsize = compressedsize,
        .expected_hash_hexstr = expected_hash_hexstr,
        .expected_hash = expected_hash,
    };

    bctx.joctx = &joctx;

    int ret = deflate_init_read_uncompressed(dctx, compressedsize, compressed_stream_reader, &bctx);
    JADE_ASSERT(!ret);

    if (!ota_init(&joctx)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to initialize OTA", NULL);
        goto cleanup;
    }

    ota_begin_called = true;

    // Send the ok response, which implies now we will get ota_data messages
    jade_process_reply_to_message_ok(process);
    uploading = true;

    struct bspatch_stream_n destination_firmware_stream_writer;
    // new partition
    destination_firmware_stream_writer.write = &ota_stream_writer;
    destination_firmware_stream_writer.opaque = &bctx;
    // patch
    struct bspatch_stream stream;
    stream.read = &patch_stream_reader;
    stream.opaque = &bctx;
    // old partition / base
    struct bspatch_stream_i basestream;
    basestream.read = &base_firmware_stream_reader;
    basestream.opaque = &bctx;

    ota_return_status = SUCCESS;
    ret = bspatch(
        &basestream, joctx.running_partition->size, &destination_firmware_stream_writer, firmwaresize, &stream);

    if (ret != SUCCESS) {
        JADE_LOGE("Error applying patch: %d", ret);
        ota_return_status = ret < 0 ? ERROR_PATCH : ret;
        goto cleanup;
    }
    JADE_ASSERT(ota_begin_called);

    // Uploading complete
    uploading = false;

    if (bctx.written != firmwaresize) {
        ota_return_status = ERROR_PATCH;
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
            process, CBOR_RPC_INTERNAL_ERROR, "Error completing OTA delta", MESSAGES[ota_return_status]);
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

        const char* message[] = { "Upgrade successful!" };
        display_message_activity(message, 1);

        vTaskDelay(2500 / portTICK_PERIOD_MS);
        esp_restart();
    } else {
        JADE_LOGE("OTA error %u: %s", ota_return_status, MESSAGES[ota_return_status]);
        if (ota_begin_called && !ota_end_called) {
            // ota_begin has been called, cleanup
            const esp_err_t err = esp_ota_abort(ota_handle);
            JADE_ASSERT(err == ESP_OK);
        }

        // If we get here and we have not finished loading the data, send an error message
        if (uploading) {
            if (id[0] == '\0') {
                // This should not happen under normal circumstances, but it could occur if the delta
                // uploaded is not appropriate for the base/running firmware (or perhaps is corrupted).
                // In that case bspatch() can fail unexpectedly - default the id.
                strcpy(id, "00");
            }
            const int error_code
                = ota_return_status == ERROR_USER_DECLINED ? CBOR_RPC_USER_CANCELLED : CBOR_RPC_INTERNAL_ERROR;

            uint8_t buf[256];
            jade_process_reject_message_with_id(id, error_code, "Error uploading OTA delta data",
                (const uint8_t*)MESSAGES[ota_return_status], strlen(MESSAGES[ota_return_status]), buf, sizeof(buf),
                process->ctx.source);
        }

        // If the error is not 'did not start' or 'user declined', show an error screen
        if (ota_return_status != ERROR_OTA_SETUP && ota_return_status != ERROR_USER_DECLINED) {
            const char* message[] = { MESSAGES[ota_return_status] };
            await_error_activity(message, 1);
        }
    }
}
