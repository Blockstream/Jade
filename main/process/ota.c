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

    // Send the ok response. The caller should then send ota_data messages
    jade_process_reply_to_message_ok(process);

    // Uncompress, verify and write data from incoming ota_data messages
    joctx->ota_return_status = OTA_SUCCESS;
    while (joctx->remaining_compressed && joctx->ota_return_status == OTA_SUCCESS) {
        jade_process_get_in_message(joctx, &handle_in_bin_data, true);
    }

    // Finalise the ota and reboot, or send an error and return
    ota_finalize(process, joctx, is_delta);
}
#endif // AMALGAMATED_BUILD
