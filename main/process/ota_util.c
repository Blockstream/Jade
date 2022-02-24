#include "ota_util.h"
#include "../jade_assert.h"
#include "ota_defines.h"
#include <esp_ota_ops.h>
#include <string.h>

const __attribute__((section(".rodata_custom_desc"))) esp_custom_app_desc_t custom_app_desc
    = { .version = 1, .board_type = JADE_OTA_BOARD_TYPE, .features = JADE_OTA_FEATURES, .config = JADE_OTA_CONFIG };

bool validate_custom_app_desc(const size_t offset, const uint8_t* uncompressed)
{
    // Check our custom fields
    const size_t custom_offset = offset + sizeof(esp_app_desc_t);
    const esp_custom_app_desc_t* custom_info = (esp_custom_app_desc_t*)(uncompressed + custom_offset);

    // 'Board Type' and 'Features' must match.
    // 'Config' is allowed to differ.
    if (strcmp(JADE_OTA_BOARD_TYPE, custom_info->board_type)) {
        JADE_LOGE("Firmware board type mismatch %s %s", JADE_OTA_BOARD_TYPE, custom_info->board_type);
        return false;
    }

    if (strcmp(JADE_OTA_FEATURES, custom_info->features)) {
        JADE_LOGE("Firmware features mismatch");
        return false;
    }
    return true;
}

void send_ok(const char* id, const jade_msg_source_t source)
{
    uint8_t ok_msg[MAXLEN_ID + 10];
    bool ok = true;
    jade_process_reply_to_message_result_with_id(id, ok_msg, sizeof(ok_msg), source, &ok, cbor_result_boolean_cb);
}

// Helper to read a chunk of binary data
void reset_ctx(struct bin_msg* bctx, uint8_t* const inbound_buf, const jade_msg_source_t expected_source)
{
    JADE_ASSERT(bctx);

    bctx->id[0] = '\0';
    bctx->inbound_buf = inbound_buf;
    bctx->len = 0;
    bctx->expected_source = expected_source;
    bctx->loaded = false;
    bctx->error = false;
}

void handle_in_bin_data(void* ctx, uint8_t* data, size_t rawsize)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(data);
    JADE_ASSERT(rawsize >= 2);

    CborParser parser;
    CborValue value;
    const CborError cberr = cbor_parser_init(data + 1, rawsize - 1, CborValidateBasic, &parser, &value);
    JADE_ASSERT(cberr == CborNoError);
    JADE_ASSERT(rpc_request_valid(&value));

    struct bin_msg* bctx = ctx;

    size_t written = 0;
    rpc_get_id(&value, bctx->id, sizeof(bctx->id), &written);
    JADE_ASSERT(written != 0);

    if (!rpc_is_method(&value, "ota_data")) {
        bctx->error = true;
        return;
    }

    written = 0;
    rpc_get_bytes("params", JADE_OTA_BUF_SIZE, &value, bctx->inbound_buf, &written);

    if (written == 0 || data[0] != bctx->expected_source || written > JADE_OTA_BUF_SIZE) {
        bctx->error = true;
        return;
    }

    bctx->len = written;
    bctx->loaded = true;
}
