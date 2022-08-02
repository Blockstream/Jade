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

static int patch_stream_reader(const struct bspatch_stream* stream, void* buffer, int length)
{
    bsdiff_ctx_t* bctx = (bsdiff_ctx_t*)stream->opaque;
    JADE_ASSERT(bctx);

    if (length <= 0) {
        return ERROR_PATCH;
    }

    // Return any non-zero error code from the read routine
    const int ret = read_uncompressed(bctx->dctx, buffer, length);
    if (ret) {
        return ret;
    }

    *bctx->joctx->remaining_uncompressed -= length;

    return SUCCESS;
}

static int base_firmware_stream_reader(const struct bspatch_stream_i* stream, void* buffer, int pos, int length)
{
    bsdiff_ctx_t* bctx = (bsdiff_ctx_t*)stream->opaque;
    JADE_ASSERT(bctx);

    if (length <= 0 || pos + length >= bctx->joctx->running_partition->size
        || esp_partition_read(bctx->joctx->running_partition, pos, buffer, length) != ESP_OK) {
        return ERROR_PATCH;
    }

    return SUCCESS;
}

static int ota_stream_writer(const struct bspatch_stream_n* stream, const void* buffer, int length)
{
    bsdiff_ctx_t* bctx = (bsdiff_ctx_t*)stream->opaque;
    JADE_ASSERT(bctx);

    if (length <= 0 || esp_ota_write(*bctx->joctx->ota_handle, buffer, length) != ESP_OK) {
        return ERROR_PATCH;
    }

    if (!bctx->header_validated && length >= CUSTOM_HEADER_MIN_WRITE) {
        const enum ota_status validation = ota_user_validation(bctx->joctx, (uint8_t*)buffer);
        if (validation != SUCCESS) {
            return validation;
        }
        bctx->header_validated = true;
    }

    bctx->written += length;

    if (bctx->written > CUSTOM_HEADER_MIN_WRITE && !bctx->header_validated) {
        return ERROR_PATCH;
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
    jade_process_get_in_message(bctx->joctx, &handle_in_bin_data, true);
    return *bctx->joctx->ota_return_status;
}

void ota_delta_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;
    bool uploading = false;
    bool ota_end_called = false;
    bool ota_begin_called = false;
    char id[MAXLEN_ID + 1];
    mbedtls_sha256_context cmp_sha_ctx;

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

    uint8_t expected_hash[SHA256_LEN];
    char* expected_hash_hexstr = NULL;
    if (!rpc_get_n_bytes("cmphash", &params, sizeof(expected_hash), expected_hash)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Cannot extract valid fw hash value", NULL);
        goto cleanup;
    }
    JADE_WALLY_VERIFY(wally_hex_from_bytes(expected_hash, sizeof(expected_hash), &expected_hash_hexstr));
    jade_process_wally_free_string_on_exit(process, expected_hash_hexstr);

    // We will show a progress bar once the user has confirmed and the upload in progress
    // Initially just show a message screen.
    display_message_activity_two_lines("Preparing for firmware", "update");
    vTaskDelay(100 / portTICK_PERIOD_MS); // sleep a little bit to redraw screen

    struct deflate_ctx* dctx = JADE_MALLOC_PREFER_SPIRAM(sizeof(struct deflate_ctx));
    jade_process_free_on_exit(process, dctx);

    bsdiff_ctx_t bctx = {
        .dctx = dctx,
    };

    size_t remaining_uncompressed = uncompressedpatchsize;

    jade_ota_ctx_t joctx = {
        .progress_bar = {},
        .cmp_sha_ctx = &cmp_sha_ctx,
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

    int ret
        = deflate_init_read_uncompressed(dctx, compressedsize, uncompressedpatchsize, compressed_stream_reader, &bctx);
    JADE_ASSERT(!ret);

    if (!ota_init(&joctx)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to initialise OTA", NULL);
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
    mbedtls_sha256_free(&cmp_sha_ctx);

    // If ota has been successful show message and reboot.
    // If error, show error-message and await user acknowledgement.
    if (ota_return_status == SUCCESS) {
        JADE_LOGW("OTA successful - rebooting");
        display_message_activity("Upgrade successful!");
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
            uint8_t buf[256];
            jade_process_reject_message_with_id(id, CBOR_RPC_INTERNAL_ERROR, "Error uploading OTA delta data",
                (const uint8_t*)MESSAGES[ota_return_status], strlen(MESSAGES[ota_return_status]), buf, sizeof(buf),
                process->ctx.source);
        }

        // If the error is not 'did not start' or 'user declined', show an error screen
        if (ota_return_status != ERROR_OTA_SETUP && ota_return_status != ERROR_USER_DECLINED) {
            await_error_activity(MESSAGES[ota_return_status]);
        }
    }
}
