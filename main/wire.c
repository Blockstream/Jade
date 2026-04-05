#ifndef AMALGAMATED_BUILD
#include "wire.h"

#include <ctype.h>
#include <string.h>

#include <cbor.h>
#include <esp_ota_ops.h>
#include <esp_system.h>

#include "idletimer.h"
#include "jade_assert.h"
#include "keychain.h"
#include "process.h"
#include "random.h"
#include "utils/cbor_rpc.h"

// Version info reply
void build_version_info_reply(const void* ctx, CborEncoder* container);

// Flag set when main thread is busy processing a message or awaiting user menu navigation
extern uint32_t main_thread_action;

#ifdef CONFIG_BOARD_TYPE_JADE_V1_ANY
// v1.x: Use a 3s 'no activity' stale message timeout on slower HW
static const TickType_t TIMEOUT_TICKS = 3000 / portTICK_PERIOD_MS;
#else
// v2.x: Use a 2s 'no activity' stale message timeout on faster HW
static const TickType_t TIMEOUT_TICKS = 2000 / portTICK_PERIOD_MS;
#endif

// Attempt to parse a valid CBOR message from data_in.
// Returns its length if valid, 0 if invalid.
static size_t get_msg_len(cbor_msg_t* ctx, const uint8_t* const data_in, const size_t read_len)
{
    const int flags = CborValidateCompleteData;
    const CborError cberr = cbor_parser_init(data_in, read_len, flags, &ctx->parser, &ctx->value);
    if (cberr == CborNoError) {
        // If we can parse the value, and it may be an RPC message, return its length
        CborValue tmp_value = ctx->value;
        if (cbor_value_advance(&tmp_value) == CborNoError && cbor_value_is_map(&ctx->value)) {
            return tmp_value.source.ptr - data_in;
        }
    }
    return 0;
}

static void reject_data(const cbor_msg_t* const ctx, const char* msg, size_t rejected_len)
{
    uint8_t len_str[16], out[112]; // sufficient
    JADE_LOGW("%s, length %u", msg, rejected_len);
    const int ret = snprintf((char*)len_str, sizeof(len_str), "%u", rejected_len);
    JADE_ASSERT(ret > 0 && ret < sizeof(len_str));
    jade_process_reject_message_ex(ctx, CBOR_RPC_INVALID_REQUEST, msg, len_str, ret, out, sizeof(out));
}

// Some messages we handle immediately in this task
static const char PING[] = { 'p', 'i', 'n', 'g' };
static const char VERINFO[] = { 'g', 'e', 't', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', '_', 'i', 'n', 'f', 'o' };

static bool handle_immediate_message(const cbor_msg_t* const ctx)
{
    JADE_ASSERT(ctx);

    size_t method_len = 0;
    const char* method = NULL;
    rpc_get_method(&ctx->value, &method, &method_len);

    if (method) {
        if (method_len == sizeof(PING) && !strncmp(method, PING, method_len)) {
            // Simple ping message
            JADE_LOGI("Ping message, replying immediately");
            uint8_t buf[64];
            const uint64_t jade_task_current_action = main_thread_action;
            jade_process_reply_to_message_result(
                ctx, buf, sizeof(buf), &jade_task_current_action, cbor_result_uint64_cb);
            return true;
        } else if (method_len == sizeof(VERINFO) && !strncmp(method, VERINFO, method_len)) {
            // Version-info message - reply immediately if it contains the 'nonblocking' flag
            CborValue params;
            bool nonblocking;
            if (rpc_get_map("params", &ctx->value, &params) && rpc_get_boolean("nonblocking", &params, &nonblocking)
                && nonblocking) {
                JADE_LOGI("VerInfoEx message, replying immediately");
                uint8_t buf[1024];
                jade_process_reply_to_message_result(ctx, buf, sizeof(buf), &ctx->source, build_version_info_reply);
                return true;
            }
        }
    }
    return false;
}

void handle_data(uint8_t* full_data_in, size_t* read_ptr, const size_t new_data_len, TickType_t* last_processing_time)
{
    JADE_ASSERT(full_data_in);
    JADE_ASSERT(read_ptr && *read_ptr <= MAX_INPUT_MSG_SIZE && *read_ptr + new_data_len <= MAX_INPUT_MSG_SIZE);
    JADE_ASSERT(last_processing_time);

    // Get current message processing time
    const TickType_t now = xTaskGetTickCount();
    JADE_ASSERT(now >= *last_processing_time);

    uint8_t* const data_in = full_data_in + 1;
    cbor_msg_t ctx = { .source = full_data_in[0] };

    // Buffer is stale if we had bytes already and the timeout has expired
    bool have_stale = *read_ptr && now > *last_processing_time + TIMEOUT_TICKS;
    JADE_LOGI("%u new of %u total %sbytes at tick %lu (prev %lu) from %d", new_data_len, *read_ptr + new_data_len,
        have_stale ? "stale " : "", now, *last_processing_time, ctx.source);

    while (true) {
        // Try parsing an RPC message from the buffer plus the new data
        const size_t parse_len = *read_ptr + new_data_len;
        size_t msg_len = get_msg_len(&ctx, data_in, parse_len);

        if (msg_len == 0) {
            // We could not parse a message from the buffer
            if (parse_len == MAX_INPUT_MSG_SIZE) {
                // Can't possibly be a valid message since there
                // is no more room to complete it: Reject the whole buffer
                msg_len = parse_len; // Whole buffer
                reject_data(&ctx, "Invalid RPC Request message", msg_len);
            } else if (have_stale) {
                // We have stale data - Throw it away and try any new data
                msg_len = *read_ptr; // Just the existing stale bytes
                reject_data(&ctx, "Invalid RPC Request message", msg_len);
            } else {
                // Continue to wait for more data to complete the message
                JADE_LOGD("Incomplete RPC Request of length %u - awaiting more data...", parse_len);
                *read_ptr = parse_len; // Include the new data in the buffer
                *last_processing_time = now; // New data received
                return;
            }
        } else if (!rpc_request_valid(&ctx.value)) {
            // We have a valid CBOR map, but it is not a valid RPC message:
            // reject it and try any following bytes in the buffer.
            reject_data(&ctx, "Invalid RPC Request message", msg_len);
        } else {
            // We have a valid looking RPC message in ctx.value:
            // Handle it immediately, or give it to the main task queue to handle
            if (handle_immediate_message(&ctx) || jade_process_push_in_message(full_data_in, msg_len + 1)) {
                const bool is_ui = false; // Not UI activity
                idletimer_register_activity(is_ui); // Message handled
            } else {
                // Rejected by the main task queue: only happens if too large
                reject_data(&ctx, "Input message too large", msg_len);
            }
        }

        if (msg_len == parse_len) {
            // We have consumed all the provided data
            *read_ptr = 0; // Discard entire buffer contents
            *last_processing_time = now; // Update caller's 'last processing time'
            return;
        }

        // We have unprocessed data left in the buffer:
        // Move it to the start of the buffer and loop to process it
        memmove(data_in, data_in + msg_len, parse_len - msg_len);
        *read_ptr -= msg_len;
        have_stale = false;
    }
}
#endif // AMALGAMATED_BUILD
