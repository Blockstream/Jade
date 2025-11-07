#ifndef AMALGAMATED_BUILD
#include "ota_util.h"
#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../qrmode.h"
#include "../utils/malloc_ext.h"
#include "ota_defines.h"
#include "process_utils.h"

#include <ctype.h>
#include <esp_efuse.h>
#include <sodium/utils.h>
#include <string.h>

bool show_ota_versions_activity(
    const char* current_version, const char* new_version, const char* hashhex, const bool full_fw_hash);

// The running firmware info, loaded at startup
extern esp_app_desc_t running_app_info;

const __attribute__((section(".rodata_custom_desc"))) esp_custom_app_desc_t custom_app_desc
    = { .version = 1, .board_type = JADE_OTA_BOARD_TYPE, .features = JADE_OTA_FEATURES, .config = JADE_OTA_CONFIG };

static const char* ota_get_status_text(const ota_status_t status)
{
    switch (status) {
    case OTA_SUCCESS:
        return "OK";
    case OTA_ERR_SETUP:
        return "OTA_ERR_SETUP";
    case OTA_ERR_INIT:
        return "OTA_ERR_INIT";
    case OTA_ERR_BADPARTITION:
        return "OTA_ERR_BADPARTITION";
    case OTA_ERR_DECOMPRESS:
        return "OTA_ERR_DECOMPRESS";
    case OTA_ERR_WRITE:
        return "OTA_ERR_WRITE";
    case OTA_ERR_FINISH:
        return "OTA_ERR_FINISH";
    case OTA_ERR_SETPARTITION:
        return "OTA_ERR_SETPARTITION";
    case OTA_ERR_BADDATA:
        return "OTA_ERR_BADDATA";
    case OTA_ERR_NODOWNGRADE:
        return "OTA_ERR_NODOWNGRADE";
    case OTA_ERR_INVALIDFW:
        return "OTA_ERR_INVALIDFW";
    case OTA_ERR_USERDECLINED:
        return "OTA_ERR_USERDECLINED";
    case OTA_ERR_BADHASH:
        return "OTA_ERR_BADHASH";
    case OTA_ERR_PATCH:
        return "OTA_ERR_PATCH";
    case OTA_ERR_PROTOCOL:
        return "OTA_ERR_PROTOCOL";
    default:
        return "OTA_ERR_UNKNOWN";
    }
}

static void reply_ok(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);

    const jade_ota_ctx_t* joctx = (const jade_ota_ctx_t*)ctx;

    if (joctx->extended_replies) {
        // Extended/structured response
        JADE_LOGI("Sending extended reply ok for %s", joctx->id);
        CborEncoder map_encoder; // result data
        CborError cberr = cbor_encoder_create_map(container, &map_encoder, 2);
        JADE_ASSERT(cberr == CborNoError);

        add_boolean_to_map(&map_encoder, "confirmed", joctx->validated_confirmed);
        add_uint_to_map(&map_encoder, "progress", joctx->progress_bar.percent_last_value);

        cberr = cbor_encoder_close_container(container, &map_encoder);
        JADE_ASSERT(cberr == CborNoError);
    } else {
        // Simple 'true' response
        JADE_LOGI("Sending simple ok for %s", joctx->id);
        const CborError cberr = cbor_encode_boolean(container, true);
        JADE_ASSERT(cberr == CborNoError);
    }
}

void handle_in_bin_data(void* ctx, uint8_t* data, const size_t rawsize)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(data);
    JADE_ASSERT(rawsize >= 2);

    CborParser parser;
    CborValue value;
    const CborError cberr = cbor_parser_init(data + 1, rawsize - 1, CborValidateBasic, &parser, &value);
    JADE_ASSERT(cberr == CborNoError);
    JADE_ASSERT(rpc_request_valid(&value));

    jade_ota_ctx_t* joctx = (jade_ota_ctx_t*)ctx;

    size_t written = 0;
    JADE_ASSERT(joctx->id[0] == '\0');
    rpc_get_id(&value, joctx->id, sizeof(joctx->id), &written);
    JADE_ASSERT(written != 0);

    // If we are carrying a cached error abandon immediately
    // (the error will be returned with this id)
    if (joctx->ota_return_status != OTA_SUCCESS) {
        return;
    }

    if (!rpc_is_method(&value, "ota_data")) {
        JADE_LOGE("handle_in_bin_data: message is not ota_data");
        joctx->ota_return_status = OTA_ERR_BADDATA;
        return;
    }

    written = 0;
    const uint8_t* inbound_buf = NULL;

    rpc_get_bytes_ptr("params", &value, &inbound_buf, &written);

    if (written == 0 || data[0] != joctx->expected_source || written > JADE_OTA_BUF_SIZE || !inbound_buf) {
        JADE_LOGE("handle_in_bin_data: invalid written or source");
        joctx->ota_return_status = OTA_ERR_BADDATA;
        return;
    }

    if (written > joctx->remaining_compressed) {
        JADE_LOGE("Received %u bytes when only needed %u", written, joctx->remaining_compressed);
        joctx->ota_return_status = OTA_ERR_BADDATA;
        return;
    }

    // Ideally we would send 'ok' message here, so we are decompressing this packet while the client
    // sends us the next.  However this seems to cause some data to be missed and some random OTA failures.
    // For the time being, send ok *after* the processing/decompression steps.

    // Return any non-zero error code from the decompress routine
    const int ret = joctx->dctx.write_compressed(&joctx->dctx, (uint8_t* const)inbound_buf, written);
    if (ret) {
        joctx->ota_return_status = ret < 0 ? OTA_ERR_DECOMPRESS : ret;
        return;
    }

    if (joctx->hash_type == HASHTYPE_FILEDATA) {
        // Add received file data to hasher
        JADE_ZERO_VERIFY(mbedtls_sha256_update(&joctx->sha_ctx, inbound_buf, written));
    }

    joctx->remaining_compressed -= written;

    // Send ack after all processing - see comment above.
    {
        uint8_t reply_msg[64];
        jade_process_reply_to_message_result_with_id(
            joctx->id, reply_msg, sizeof(reply_msg), joctx->expected_source, joctx, reply_ok);
    }

    JADE_LOGI("sent ok for ota_data %s(%u), %u/%u->%u/%u", joctx->id, written,
        joctx->compressedsize - joctx->remaining_compressed, joctx->compressedsize,
        joctx->uncompressedsize - joctx->remaining_uncompressed, joctx->uncompressedsize);

    // Blank out the current msg id once 'ok' is sent for it
    joctx->id[0] = '\0';
}

static void ota_free(void* ctx)
{
    jade_ota_ctx_t* joctx = (jade_ota_ctx_t*)ctx;
    if (joctx) {
        mbedtls_sha256_free(&joctx->sha_ctx);
        wally_free_string(joctx->expected_hash_hexstr); // Ignore return value
        if (joctx->ota_handle) {
            // ota was started but not cleanly shutdown: abort it
            const esp_err_t err = esp_ota_abort(joctx->ota_handle);
            JADE_ASSERT(err == ESP_OK);
            joctx->ota_handle = 0;
        }
    }
}

jade_ota_ctx_t* ota_init(jade_process_t* process, const bool is_delta)
{
    JADE_ASSERT(process);
    jade_ota_ctx_t* joctx = NULL;
    const char* errmsg = NULL;
    int errcode = CBOR_RPC_BAD_PARAMETERS;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, is_delta ? "ota_delta" : "ota");
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
        || firmwaresize <= compressedsize) {
        errmsg = "Bad filesize parameters";
        goto cleanup;
    }
    if (is_delta
        && (!rpc_get_sizet("patchsize", &params, &uncompressedpatchsize) || uncompressedpatchsize <= compressedsize)) {
        errmsg = "Bad delta filesize parameters";
        goto cleanup;
    }

    // Optional field indicating preference for rich reply data
    bool extended_replies = false;
    rpc_get_boolean("extended_replies", &params, &extended_replies);

    // Can accept either uploaded file data hash (legacy) or hash of the full/final firmware image (preferred)
    uint8_t expected_hash[SHA256_LEN];
    hash_type_t hash_type;
    if (rpc_get_n_bytes("fwhash", &params, sizeof(expected_hash), expected_hash)) {
        hash_type = HASHTYPE_FULLFWDATA;
    } else if (rpc_get_n_bytes("cmphash", &params, sizeof(expected_hash), expected_hash)) {
        hash_type = HASHTYPE_FILEDATA;
    } else {
        errmsg = "Cannot extract valid fw hash value";
        goto cleanup;
    }
    errcode = CBOR_RPC_INTERNAL_ERROR; // From this point all errors are internal

    // We will show a progress bar once the user has confirmed and the upload in progress
    // Initially just show a message screen.
    const char* message[] = { "Preparing for firmware", "", "update" };
    display_message_activity(message, 3);
    vTaskDelay(100 / portTICK_PERIOD_MS); // sleep a little bit to redraw screen

    joctx = JADE_CALLOC_PREFER_SPIRAM(1, sizeof(jade_ota_ctx_t));
    jade_process_call_on_exit(process, ota_free, joctx);

    mbedtls_sha256_init(&joctx->sha_ctx);
    JADE_ZERO_VERIFY(mbedtls_sha256_starts(&joctx->sha_ctx, 0));
    joctx->hash_type = hash_type;
    JADE_STATIC_ASSERT(sizeof(joctx->expected_hash) == sizeof(expected_hash));
    memcpy(joctx->expected_hash, expected_hash, sizeof(expected_hash));
    JADE_WALLY_VERIFY(wally_hex_from_bytes(expected_hash, sizeof(expected_hash), &joctx->expected_hash_hexstr));
    joctx->ota_return_status = OTA_ERR_SETUP;
    joctx->expected_source = ota_source;
    joctx->compressedsize = compressedsize;
    joctx->remaining_compressed = joctx->compressedsize;
    joctx->uncompressedsize = is_delta ? uncompressedpatchsize : firmwaresize;
    joctx->remaining_uncompressed = joctx->uncompressedsize;
    joctx->firmwaresize = firmwaresize;
    joctx->fwwritten = 0;
    joctx->extended_replies = extended_replies;
    joctx->validated_confirmed = false;

    joctx->running_partition = esp_ota_get_running_partition();
    joctx->update_partition = esp_ota_get_next_update_partition(NULL);

    // Check partitions
    if (joctx->running_partition == NULL) {
        errmsg = "Failed to get running partition";
        goto cleanup;
    } else if (joctx->update_partition == NULL) {
        errmsg = "Failed to get next update partition";
        goto cleanup;
    } else if (joctx->update_partition == joctx->running_partition) {
        errmsg = "Cannot OTA on running partition";
        goto cleanup;
    } else {
        const esp_err_t err = esp_ota_begin(joctx->update_partition, joctx->firmwaresize, &joctx->ota_handle);
        if (err != ESP_OK) {
            errmsg = "Failed to begin ota";
            goto cleanup;
        }
    }

cleanup:
    if (errmsg) {
        JADE_LOGE("%s", errmsg);
        jade_process_reject_message(process, errcode, errmsg);
        joctx = NULL;
    }
    return joctx;
}

void ota_finalize(jade_process_t* process, jade_ota_ctx_t* joctx, const bool is_delta)
{
    JADE_ASSERT(joctx);

    if (joctx->ota_return_status != OTA_SUCCESS) {
        goto error; // An error has already occured, return it
    }

    // To reach this far without error, the user must have confirmed
    JADE_ASSERT(joctx->validated_confirmed);

    // Expect an ota_complete message
    jade_process_load_in_message(process, true);
    if (!IS_CURRENT_MESSAGE(process, "ota_complete")) {
        joctx->ota_return_status = OTA_ERR_PROTOCOL; // Protocol error
        goto error;
    }

    if (joctx->fwwritten != joctx->firmwaresize) {
        JADE_LOGE("OTA checks failed: written: %u/%u", joctx->fwwritten, joctx->firmwaresize);
        joctx->ota_return_status = is_delta ? OTA_ERR_PATCH : OTA_ERR_DECOMPRESS;
        goto error;
    }
    if (joctx->remaining_compressed || joctx->remaining_uncompressed || !joctx->compressedsize
        || !joctx->uncompressedsize) {
        JADE_LOGE("OTA checks failed: uncompressed: %u/%u, compressed: %u/%u", joctx->uncompressedsize,
            joctx->remaining_uncompressed, joctx->compressedsize, joctx->remaining_compressed);
        joctx->ota_return_status = OTA_ERR_INIT;
        goto error;
    }

    // Verify calculated compressed file hash matches expected
    uint8_t calculated_hash[SHA256_LEN];
    JADE_ZERO_VERIFY(mbedtls_sha256_finish(&joctx->sha_ctx, calculated_hash));

    JADE_ASSERT(joctx->expected_hash);
    JADE_ASSERT(joctx->expected_hash_hexstr);

    if (sodium_memcmp(joctx->expected_hash, calculated_hash, sizeof(calculated_hash))) {
        char* calc_hash_hexstr = NULL;
        JADE_WALLY_VERIFY(wally_hex_from_bytes(calculated_hash, sizeof(calculated_hash), &calc_hash_hexstr));

        JADE_LOGE("Firmware hash mismatch: expected: %s, got: %s", joctx->expected_hash_hexstr, calc_hash_hexstr);
        JADE_WALLY_VERIFY(wally_free_string(calc_hash_hexstr));

        joctx->ota_return_status = OTA_ERR_BADHASH;
        goto error;
    }

    // All good, finalise the ota and set the partition to boot
    esp_err_t err = esp_ota_end(joctx->ota_handle);
    joctx->ota_handle = 0;

    if (err != ESP_OK) {
        JADE_LOGE("esp_ota_end() returned %d", err);
        joctx->ota_return_status = OTA_ERR_FINISH;
        goto error;
    }

    err = esp_ota_set_boot_partition(joctx->update_partition);
    if (err != ESP_OK) {
        JADE_LOGE("esp_ota_set_boot_partition() returned %d", err);
        joctx->ota_return_status = OTA_ERR_SETPARTITION;
        goto error;
    }

    // OTA completed without errors. send an ok and reboot
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");
    JADE_LOGW("OTA successful - rebooting");

    const char* message[] = { "Upgrade successful!" };
    display_message_activity(message, 1);

    vTaskDelay(2500 / portTICK_PERIOD_MS);
    esp_restart(); // Does not return
    return; // Unreachable

error:
    // We have an error, send an error response.
    const char* status_text = ota_get_status_text(joctx->ota_return_status);
    JADE_LOGE("OTA error: %s", status_text);

    int errcode = CBOR_RPC_INTERNAL_ERROR;
    if (joctx->ota_return_status == OTA_ERR_USERDECLINED) {
        errcode = CBOR_RPC_USER_CANCELLED;
    } else if (joctx->ota_return_status == OTA_ERR_PROTOCOL) {
        errcode = CBOR_RPC_PROTOCOL_ERROR;
    }

    uint8_t buf[256];
    if (joctx->id[0] != '\0') {
        // Send error response to the ota_data message we were processing.
        jade_process_reject_message_with_id(joctx->id, errcode, "Error uploading OTA data", (const uint8_t*)status_text,
            strlen(status_text), buf, sizeof(buf), joctx->expected_source);
    } else {
        // Send error response to the ota_complete message.
        // If we didn't get an ota_complete, sets the reply id as "00".
        jade_process_reject_message_ex(process->ctx, errcode, "Error completing OTA", (const uint8_t*)status_text,
            strlen(status_text), buf, sizeof(buf));
    }

    // If the error is not 'did not start' or 'user declined', show an error screen
    if (joctx->ota_return_status != OTA_ERR_SETUP && joctx->ota_return_status != OTA_ERR_USERDECLINED) {
        await_error_activity(&status_text, 1);
    }
}

// NOTE: 'dest' is assumed to be at least as long as 'strlen(src)'
static void to_lower(char* dest, const char* src)
{
    while (*src) {
        *dest++ = tolower(*src++);
    }
    *dest = '\0';
}

void ota_user_validate(jade_ota_ctx_t* joctx, const uint8_t* uncompressed)
{
    JADE_ASSERT(joctx);
    JADE_ASSERT(uncompressed);

    JADE_ASSERT(joctx->expected_hash);
    JADE_ASSERT(joctx->expected_hash_hexstr);
    JADE_ASSERT(joctx->update_partition);
    JADE_ASSERT(joctx->running_partition);
    JADE_ASSERT(joctx->ota_handle);
    JADE_ASSERT(joctx->ota_return_status == OTA_SUCCESS);

    JADE_LOGI("Running firmware version: %s", running_app_info.version);

    // Check chip
    const esp_image_header_t* header = (esp_image_header_t*)uncompressed;
    if (header->chip_id != CONFIG_IDF_FIRMWARE_CHIP_ID) {
        JADE_LOGE("Mismatch chip id, expected %d, found %d", CONFIG_IDF_FIRMWARE_CHIP_ID, header->chip_id);
        joctx->ota_return_status = OTA_ERR_INVALIDFW;
        return;
    }

    const size_t app_info_offset = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);
    const esp_app_desc_t* new_app_info = (esp_app_desc_t*)(uncompressed + app_info_offset);

    JADE_LOGI("New firmware version: %s", new_app_info->version);

    if (esp_efuse_check_secure_version(new_app_info->secure_version) == false) {
        JADE_LOGE("Secure version downgrade not allowed");
        joctx->ota_return_status = OTA_ERR_NODOWNGRADE;
        return;
    }

    const size_t custom_info_offset = app_info_offset + sizeof(esp_app_desc_t);
    const esp_custom_app_desc_t* custom_info = (esp_custom_app_desc_t*)(uncompressed + custom_info_offset);

    // 'Board Type' and 'Features' must match.
    // 'Config' is allowed to differ.
    if (strcmp(JADE_OTA_BOARD_TYPE, custom_info->board_type)) {
        JADE_LOGE("Firmware board type mismatch %s %s", JADE_OTA_BOARD_TYPE, custom_info->board_type);
        joctx->ota_return_status = OTA_ERR_INVALIDFW;
        return;
    }

    if (strcmp(JADE_OTA_FEATURES, custom_info->features)) {
        JADE_LOGE("Firmware features mismatch");
        joctx->ota_return_status = OTA_ERR_INVALIDFW;
        return;
    }

    // User to confirm once new firmware version known and all checks passed
    char current_config[sizeof(JADE_OTA_CONFIG)];
    to_lower(current_config, JADE_OTA_CONFIG);
    char current_version[sizeof(running_app_info.version) + sizeof(current_config) + 2];
    int rc = snprintf(current_version, sizeof(current_version), "%s %s", running_app_info.version, current_config);
    JADE_ASSERT(rc > 0 && rc < sizeof(current_version));

    char new_config[sizeof(custom_info->config)];
    to_lower(new_config, custom_info->config);
    char new_version[sizeof(new_app_info->version) + sizeof(new_config) + 2];
    rc = snprintf(new_version, sizeof(new_version), "%s %s", new_app_info->version, new_config);
    JADE_ASSERT(rc > 0 && rc < sizeof(new_version));

    const bool full_fw_hash = joctx->hash_type == HASHTYPE_FULLFWDATA;

    // Ask user to confirm
    if (!show_ota_versions_activity(current_version, new_version, joctx->expected_hash_hexstr, full_fw_hash)) {
        JADE_LOGW("User declined ota firmware version");
        joctx->ota_return_status = OTA_ERR_USERDECLINED;
        return;
    }

    // Now user has confirmed, display the progress bar
    gui_activity_t* const act
        = make_progress_bar_activity("Firmware Upgrade", "Upload Progress:", &joctx->progress_bar);
    gui_set_current_activity_ex(act, true); // free prior activities
    vTaskDelay(100 / portTICK_PERIOD_MS); // time for screen to update

    // Mark the OTA as validated/user confirmed
    joctx->validated_confirmed = true;
}

#endif // AMALGAMATED_BUILD
