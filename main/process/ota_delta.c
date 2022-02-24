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

#include "bspatch.h"
#include "process_utils.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define BSDIFF_ERROR -1
#define BSDIFF_OK 0

typedef struct {
    esp_app_desc_t running_app_info;
    progress_bar_t progress_bar;
    mbedtls_sha256_context* const cmp_sha_ctx;
    struct bin_msg* const binctx;
    jade_process_t* const process;
    esp_ota_handle_t* const ota_handle;
    const esp_partition_t* const src;
    const esp_partition_t* const dest;
    char* const expected_hash_hexstr;
    uint8_t* const uncompressed;
    uint8_t* deflate_nout;
    uint8_t* msg_buf;
    tinfl_decompressor* const deflate_decomp;
    const size_t patch_size;
    size_t patch_offset;
    size_t written;
    size_t deflate_remaining_compressed;
    const size_t deflate_compressedsize;
    size_t uncompressed_ready_to_write;
    size_t uncompressed_ready_wrote;
    const size_t firmwaresize;
    uint32_t deflate_remaining;
    int deflate_status;
    bool header_validated;
} bsdiff_ctx_t;

static int patch_stream_reader(const struct bspatch_stream* stream, void* buffer, int length)
{
    bsdiff_ctx_t* bctx = (bsdiff_ctx_t*)stream->opaque;
    JADE_ASSERT(bctx);

    if (length <= 0 || bctx->patch_offset + length > bctx->patch_size) {
        return BSDIFF_ERROR;
    }

    size_t remaining = length;
    while (remaining) {
        if (bctx->uncompressed_ready_to_write > 0) {
            // we have some uncompressed data left over ready to provide to the caller
            const size_t towrite = MIN(bctx->uncompressed_ready_to_write, remaining);
            memcpy(buffer + (length - remaining), bctx->uncompressed + bctx->uncompressed_ready_wrote, towrite);

            remaining -= towrite;
            bctx->uncompressed_ready_to_write -= towrite;
            bctx->uncompressed_ready_wrote += towrite;
            bctx->deflate_nout = bctx->uncompressed;
        }

        if (!remaining) {
            // we served all the caller's need
            break;
        }

        // if we get here it means we didn't serve all the caller needs
        // thus we expect we have nothing left to write
        if (bctx->uncompressed_ready_to_write) {
            return BSDIFF_ERROR;
        }

        // if we are here is because we don't have anything ready to write
        bctx->uncompressed_ready_wrote = 0;
        while (bctx->binctx->loaded && bctx->binctx->len > 0 && bctx->deflate_remaining > 0
            && bctx->deflate_status > TINFL_STATUS_DONE) {
            // decompress some data
            size_t in_bytes = bctx->binctx->len;
            size_t out_bytes = bctx->uncompressed + UNCOMPRESSED_BUF_SIZE - bctx->deflate_nout;
            int flags = TINFL_FLAG_PARSE_ZLIB_HEADER;
            if (bctx->deflate_remaining_compressed > bctx->binctx->len) {
                flags |= TINFL_FLAG_HAS_MORE_INPUT;
            }

            bctx->deflate_status = tinfl_decompress(bctx->deflate_decomp, bctx->binctx->inbound_buf, &in_bytes,
                bctx->uncompressed, bctx->deflate_nout, &out_bytes, flags);

            bctx->deflate_remaining_compressed -= in_bytes;
            bctx->binctx->len -= in_bytes;
            bctx->binctx->inbound_buf += in_bytes;

            bctx->deflate_nout += out_bytes;
            const size_t towrite = bctx->deflate_nout - bctx->uncompressed;
            if (bctx->deflate_status == TINFL_STATUS_DONE || towrite == UNCOMPRESSED_BUF_SIZE) {
                // we finally have some data from uncompressed up to towrite
                bctx->uncompressed_ready_to_write = towrite;
                bctx->uncompressed_ready_wrote = 0;
                break;
            }
        }

        if (bctx->binctx->loaded && bctx->binctx->len == 0) {
            // if we are here is because we don't have any compressed data remaining
            // ie. we have consumed the input ota-data message entirely
            send_ok(bctx->binctx->id, bctx->process->ctx.source);
            bctx->binctx->loaded = false;
            JADE_LOGI("compressed:   total = %u, current = %u", bctx->deflate_compressedsize,
                bctx->deflate_compressedsize - bctx->deflate_remaining_compressed);
            JADE_LOGI("uncompressed: total = %u, current = %u", bctx->firmwaresize,
                bctx->firmwaresize - bctx->deflate_remaining);
        }

        if (bctx->uncompressed_ready_to_write) {
            // we still have uncompressed data to write so we don't need to read new messages
            continue;
        }

        // if we get here it is because we have exhausted all input data and still require more
        // and so counters should be reset ready to start handling a new ota-data message
        if (bctx->uncompressed_ready_to_write || bctx->uncompressed_ready_wrote) {
            return BSDIFF_ERROR;
        }

        // if we got here it means we don't have data to read nor decompress
        // so we expect/handle an ota-data message
        reset_ctx(bctx->binctx, bctx->msg_buf, bctx->process->ctx.source);
        jade_process_get_in_message(bctx->binctx, &handle_in_bin_data, true);

        if (bctx->binctx->error || !bctx->binctx->loaded) {
            JADE_LOGE("Error on ota_data message");
            return BSDIFF_ERROR;
        }

        if (bctx->binctx->len > bctx->deflate_remaining_compressed) {
            JADE_LOGE("Received %u bytes when only needed %u", bctx->binctx->len, bctx->deflate_remaining_compressed);
            return BSDIFF_ERROR;
        }

        JADE_LOGI("Received ota_data msg %s, payload size %u", bctx->binctx->id, bctx->binctx->len);

        // Add to cmp-file hasher
        if (mbedtls_sha256_update_ret(bctx->cmp_sha_ctx, bctx->binctx->inbound_buf, bctx->binctx->len) != 0) {
            jade_process_reject_message(bctx->process, CBOR_RPC_INTERNAL_ERROR, "Failed to build firmware hash", NULL);
            return BSDIFF_ERROR;
        }
        // loop to start uncompressing newly received data
    }

    bctx->patch_offset += length;

    return BSDIFF_OK;
}

static int base_firmware_stream_reader(const struct bspatch_stream_i* stream, void* buffer, int pos, int length)
{
    bsdiff_ctx_t* bctx = (bsdiff_ctx_t*)stream->opaque;
    JADE_ASSERT(bctx);
    if (length <= 0 || pos + length >= bctx->src->size) {
        return BSDIFF_ERROR;
    }

    if (esp_partition_read(bctx->src, pos, buffer, length) != ESP_OK) {
        return BSDIFF_ERROR;
    }

    return BSDIFF_OK;
}

static enum ota_status validate_header(esp_app_desc_t* running_app_info, const void* buffer, char* expected_hash_hexstr)
{
    const size_t offset = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);
    const esp_app_desc_t* new_app_info = (esp_app_desc_t*)(buffer + offset);

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

    if (!validate_custom_app_desc(0, buffer + offset)) {
        return ERROR_INVALIDFW;
    }

    // User to confirm once new firmware version known and all checks passed
    gui_activity_t* activity;
    make_ota_versions_activity(&activity, running_app_info->version, new_app_info->version, expected_hash_hexstr);
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
    return SUCCESS;
}

const size_t CUSTOM_HEADER_MIN_WRITE = sizeof(esp_app_desc_t) + sizeof(esp_custom_app_desc_t)
    + sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);

static int ota_stream_writer(const struct bspatch_stream_n* stream, const void* buffer, int length)
{
    bsdiff_ctx_t* bctx = (bsdiff_ctx_t*)stream->opaque;
    JADE_ASSERT(bctx);

    if (length <= 0 || esp_ota_write(*bctx->ota_handle, buffer, length) != ESP_OK) {
        return BSDIFF_ERROR;
    }

    if (!bctx->header_validated && !bctx->written && length >= CUSTOM_HEADER_MIN_WRITE) {
        const enum ota_status validation = validate_header(&bctx->running_app_info, buffer, bctx->expected_hash_hexstr);
        if (validation != SUCCESS) {
            return BSDIFF_ERROR;
        }
        bctx->header_validated = true;
        display_progress_bar_activity("Firmware Upgrade", "Upload Progress:", &bctx->progress_bar);
    }

    bctx->written += length;

    if (bctx->written > CUSTOM_HEADER_MIN_WRITE && !bctx->header_validated) {
        return BSDIFF_ERROR;
    }

    if (bctx->header_validated) {
        JADE_ASSERT(&bctx->progress_bar);
        update_progress_bar(&bctx->progress_bar, bctx->firmwaresize, bctx->written);
    }
    bctx->deflate_remaining -= length;

    return BSDIFF_OK;
}

void ota_delta_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;
    bool uploading = false;
    bool ota_end_called = false;
    bool ota_begin_called = false;
    mbedtls_sha256_context cmp_sha_ctx;
    struct bin_msg binctx = { .inbound_buf = JADE_MALLOC_PREFER_SPIRAM(JADE_OTA_BUF_SIZE) };
    jade_process_free_on_exit(process, binctx.inbound_buf);
    esp_ota_handle_t ota_handle = 0;
    // Context used to compute (compressed) firmware hash - ie. file as uploaded
    mbedtls_sha256_init(&cmp_sha_ctx);
    enum ota_status ota_return_status = ERROR_OTA_SETUP;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "ota_delta");
    GET_MSG_PARAMS(process);

    size_t firmwaresize = 0;
    size_t compressedsize = 0;
    size_t uncompressedpatchsize = 0;

    // if uncompressed is in DRAM esp_ota_write performs 2-3X better vs SPIRAM
    uint8_t* uncompressed = JADE_MALLOC_DRAM(UNCOMPRESSED_BUF_SIZE);
    jade_process_free_on_exit(process, uncompressed);

    if (!rpc_get_sizet("fwsize", &params, &firmwaresize) || !rpc_get_sizet("cmpsize", &params, &compressedsize)
        || !rpc_get_sizet("patchsize", &params, &uncompressedpatchsize) || firmwaresize <= compressedsize
        || uncompressedpatchsize <= compressedsize) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Bad filesize parameters", NULL);
        goto cleanup;
    }

    uint8_t expected_hash[SHA256_LEN];
    size_t expected_hash_len = 0;
    char* expected_hash_hexstr = NULL;
    rpc_get_bytes("cmphash", sizeof(expected_hash), &params, expected_hash, &expected_hash_len);
    if (expected_hash_len != HMAC_SHA256_LEN) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Cannot extract valid fw hash value", NULL);
        goto cleanup;
    }
    JADE_WALLY_VERIFY(wally_hex_from_bytes(expected_hash, expected_hash_len, &expected_hash_hexstr));
    jade_process_wally_free_string_on_exit(process, expected_hash_hexstr);

    // We will show a progress bar once the user has confirmed and the upload in progress
    // Initially just show a message screen.
    display_message_activity_two_lines("Preparing for firmware", "update");

    esp_partition_t const* update_partition = NULL;
    update_partition = esp_ota_get_next_update_partition(NULL);
    JADE_LOGI("Update partition: %p", update_partition);
    if (update_partition == NULL) {
        JADE_LOGE("Failed to get next update partition");
        ota_return_status = ERROR_BADPARTITION;
        goto cleanup;
    }

    const esp_partition_t* running = esp_ota_get_running_partition();
    JADE_LOGI("Running partition: %p", running);
    if (update_partition == running) {
        JADE_LOGE("Cannot OTA on running partition: %p", running);
        ota_return_status = ERROR_BADPARTITION;
        goto cleanup;
    }

    // sizeof(tinfl_decompressor) is just over 10k, no perfs diff vs DRAM
    tinfl_decompressor* decomp = JADE_MALLOC_PREFER_SPIRAM(sizeof(tinfl_decompressor));
    jade_process_free_on_exit(process, decomp);
    tinfl_init(decomp);

    bsdiff_ctx_t bctx = {
        .cmp_sha_ctx = &cmp_sha_ctx,
        .binctx = &binctx,
        .src = running,
        .dest = update_partition,
        .patch_size = uncompressedpatchsize,
        .expected_hash_hexstr = expected_hash_hexstr,
        .process = process,
        .uncompressed = uncompressed,
        .deflate_status = TINFL_STATUS_NEEDS_MORE_INPUT,
        .deflate_nout = uncompressed,
        .deflate_remaining_compressed = compressedsize,
        .deflate_compressedsize = compressedsize,
        .deflate_decomp = decomp,
        .deflate_remaining = firmwaresize,
        .firmwaresize = firmwaresize,
        .ota_handle = &ota_handle,
        .msg_buf = binctx.inbound_buf,
        .progress_bar = { .progress_bar = NULL, .pcnt_txt = NULL, .percent_last_value = 0 },
    };

    esp_err_t err = esp_ota_get_partition_description(running, &bctx.running_app_info);
    if (err != ESP_OK) {
        JADE_LOGE("Failed to get running partition data, error: %d", err);
        ota_return_status = ERROR_BADPARTITION;
        goto cleanup;
    }
    JADE_LOGI("Running firmware version: %s", bctx.running_app_info.version);

    int res = mbedtls_sha256_starts_ret(&cmp_sha_ctx, 0); // 0 = SHA256 instead of SHA224
    if (res != 0) {
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Failed to initialise compressed firmware hash", NULL);
        goto cleanup;
    }

    err = esp_ota_begin(update_partition, firmwaresize, &ota_handle);
    if (err != ESP_OK) {
        JADE_LOGE("Error: esp_ota_being failed %d", err);
        ota_return_status = ERROR_OTA_INIT;
        goto cleanup;
    }
    ota_begin_called = true;

    // Send the ok response, which implies now we will get ota_data messages
    jade_process_reply_to_message_ok(process);
    struct bspatch_stream_n destionation_firmware_stream_writer;
    // new partition
    destionation_firmware_stream_writer.write = ota_stream_writer;
    destionation_firmware_stream_writer.opaque = &bctx;
    // patch
    struct bspatch_stream stream;
    stream.read = patch_stream_reader;
    stream.opaque = &bctx;
    // old partition / base
    struct bspatch_stream_i basestream;
    basestream.read = base_firmware_stream_reader;
    basestream.opaque = &bctx;
    const int ret = bspatch(&basestream, running->size, &destionation_firmware_stream_writer, firmwaresize, &stream);
    if (ret != BSDIFF_OK) {
        JADE_LOGE("Error: bsdiff %d", ret);
        ota_return_status = ERROR_BADDATA;
        goto cleanup;
    }

    // Verify calculated compressed file hash matches expected
    uint8_t calculated_hash[SHA256_LEN];
    if (mbedtls_sha256_finish_ret(&cmp_sha_ctx, calculated_hash) != 0) {
        JADE_LOGE("Failed to compute fw file hash");
        ota_return_status = ERROR_BAD_HASH;
        goto otacomplete;
    }

    // we were provided the expected cmpfile hash, check it matches
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

    if (bctx.patch_offset != uncompressedpatchsize || bctx.written != firmwaresize || bctx.deflate_remaining_compressed
        || bctx.deflate_remaining) {
        ota_return_status = ERROR_BADDATA;
        goto otacomplete;
    }

    // All good, finalise the ota and set the partition to boot
    // NOTE: even if esp_ota_end() returns an error code, it should have done any
    // necessary cleanup, and there is no need to call esp_ota_abort() - so we can
    // set the 'ota_end_called' flag regardless.
    err = esp_ota_end(ota_handle);
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
    ota_return_status = SUCCESS;

    JADE_ASSERT(ota_begin_called);
    JADE_ASSERT(ota_end_called);
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
            process, CBOR_RPC_INTERNAL_ERROR, "Error completing OTA delta", MESSAGES[ota_return_status]);
    } else {
        jade_process_reply_to_message_ok(process);
    }

cleanup:
    mbedtls_sha256_free(&cmp_sha_ctx);

    // If ota has been successful show message and reboot.
    // If error, show error-message and await user acknowledgement.
    if (ota_return_status == SUCCESS) {
        JADE_LOGW("OTA delta successful - rebooting");
        display_message_activity("Upgrade successful!");
        vTaskDelay(2500 / portTICK_PERIOD_MS);
        esp_restart();
    } else {
        JADE_LOGW("OTA delta error %u", ota_return_status);
        if (ota_begin_called && !ota_end_called) {
            // ota_begin has been called, cleanup
            err = esp_ota_abort(ota_handle);
            JADE_LOGE("OTA delta failed %d", err);
            JADE_ASSERT(err == ESP_OK);
        }

        // If we get here and we have not finished loading the data, send an error message
        if (uploading) {
            uint8_t buf[256];
            jade_process_reject_message_with_id(binctx.id, CBOR_RPC_INTERNAL_ERROR, "Error uploading OTA delta data",
                (const uint8_t*)MESSAGES[ota_return_status], strlen(MESSAGES[ota_return_status]), buf, sizeof(buf),
                process->ctx.source);
        }

        // If the error is not 'did not start' or 'user declined', show an error screen
        if (ota_return_status != ERROR_OTA_SETUP && ota_return_status != ERROR_USER_DECLINED) {
            await_error_activity(MESSAGES[ota_return_status]);
        }
    }
}
