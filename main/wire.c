#ifndef AMALGAMATED_BUILD
#include "wire.h"

#include <ctype.h>
#include <string.h>

#include <cbor.h>
#include <esp_ota_ops.h>
#include <esp_system.h>
#if defined(CONFIG_IDF_TARGET_ESP32S3) && defined(CONFIG_DEBUG_MODE) && defined(CONFIG_APPTRACE_GCOV_ENABLE)
#include <esp_app_trace.h>
#endif

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

// 2s 'no activity' stale message timeout
static const TickType_t TIMEOUT_TICKS = 2000 / portTICK_PERIOD_MS;

// Macros for use in handle_data() as always called with fixed params
#define SEND_REJECT_MSG(code, msg, rejectedlen)                                                                        \
    do {                                                                                                               \
        char lenstr[8];                                                                                                \
        const int ret = snprintf(lenstr, sizeof(lenstr), "%u", rejectedlen);                                           \
        JADE_ASSERT(ret > 0 && ret < sizeof(lenstr));                                                                  \
        jade_process_reject_message_ex(ctx, code, msg, (uint8_t*)lenstr, ret, data_out, MAX_OUTPUT_MSG_SIZE);          \
    } while (false)

// Some messages we handle immediately in this task
static const char PING[] = { 'p', 'i', 'n', 'g' };
static const char VERINFO[] = { 'g', 'e', 't', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', '_', 'i', 'n', 'f', 'o' };
#if defined(CONFIG_IDF_TARGET_ESP32S3) && defined(CONFIG_DEBUG_MODE) && defined(CONFIG_APPTRACE_GCOV_ENABLE)
static const char DEBUG_GCOV_DUMP[] = { 'd', 'e', 'b', 'u', 'g', '_', 'g', 'c', 'o', 'v', '_', 'd', 'u', 'm', 'p' };
#endif

static bool handleImmediateMessage(cbor_msg_t* ctx)
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
                *ctx, buf, sizeof(buf), &jade_task_current_action, cbor_result_uint64_cb);
            return true;
        } else if (method_len == sizeof(VERINFO) && !strncmp(method, VERINFO, method_len)) {
            // Version-info message - reply immediately if it contains the 'nonblocking' flag
            CborValue params;
            bool nonblocking;
            if (rpc_get_map("params", &ctx->value, &params) && rpc_get_boolean("nonblocking", &params, &nonblocking)
                && nonblocking) {
                JADE_LOGI("VerInfoEx message, replying immediately");
                uint8_t buf[1024];
                jade_process_reply_to_message_result(*ctx, buf, sizeof(buf), &ctx->source, build_version_info_reply);
                return true;
            }
#if defined(CONFIG_IDF_TARGET_ESP32S3) && defined(CONFIG_DEBUG_MODE) && defined(CONFIG_APPTRACE_GCOV_ENABLE)
        } else if (method_len == sizeof(DEBUG_GCOV_DUMP) && !strncmp(method, DEBUG_GCOV_DUMP, method_len)) {
            uint8_t buf[64];
            const bool ok = true;
            jade_process_reply_to_message_result(*ctx, buf, sizeof(buf), &ok, cbor_result_boolean_cb);
            esp_gcov_dump();
            return true;
#endif
        }
    }
    return false;
}

// Handle bytes in receive buffer
// NOTE: assumes sizes of input and output buffers - could be passed sizes if preferred
static void handle_data_impl(uint8_t* full_data_in, size_t* read_ptr, bool reject_if_no_msg, uint8_t* data_out)
{
    JADE_ASSERT(full_data_in);
    JADE_ASSERT(read_ptr);
    JADE_ASSERT(*read_ptr <= MAX_INPUT_MSG_SIZE);
    JADE_ASSERT(data_out);

    const jade_msg_source_t source = full_data_in[0];
    uint8_t* const data_in = full_data_in + 1;

    while (true) {

        cbor_msg_t ctx = { .source = source, .cbor = NULL, .cbor_len = 0 };
        const size_t read = *read_ptr;
        size_t msg_len = 0;

        const CborError cberr = cbor_parser_init(data_in, read, CborValidateCompleteData, &ctx.parser, &ctx.value);
        if (cberr == CborNoError) {
            // Attempt to fetch the next single cbor object from the stream and store the relevant message length
            // Will carry out basic structure validation - see: cbor_value_validate_basic()
            CborValue tmp_value = ctx.value;
            if (cbor_value_advance(&tmp_value) == CborNoError) {
                msg_len = tmp_value.source.ptr - data_in;
            }
        }

        // If we could not fetch a message from the buffer..
        if (msg_len == 0) {
            if (!reject_if_no_msg) {
                // Not a complete cbor message, but we are allowed to await more data to complete the message
                JADE_LOGD("Got incomplete CBOR message, length %u - awaiting more data...", read);
                return;
            }

            // Not a complete/valid cbor message, and we are not allowed to await more, so reject what we have.
            // Break to reset the read-ptr to the start and lose all the data.
            JADE_LOGW("Got incomplete CBOR message, length %u but not awaiting more data - rejecting", read);
            SEND_REJECT_MSG(CBOR_RPC_INVALID_REQUEST, "Invalid RPC Request message", read);
            break;
        }

        if (!rpc_request_valid(&ctx.value)) {
            // bad message - expect all inputs to be cbor with a root map with an id and a method strings keys values
            JADE_LOGW("Invalid request, length %u", msg_len);
            SEND_REJECT_MSG(CBOR_RPC_INVALID_REQUEST, "Invalid RPC Request message (malformed)", msg_len);
        } else if (handleImmediateMessage(&ctx)) {
            JADE_LOGI("Message handled, not passing to main task");
            idletimer_register_activity(false);
        } else {
            // Push to task queue for main task to handle
            if (jade_process_push_in_message(full_data_in, msg_len + 1)) {
                // Valid message arrival counts as 'activity' against idle timeout
                // (but not as 'UI' activity - ie. keep jade on but do not stop the screen from turning off)
                idletimer_register_activity(false);
            } else {
                SEND_REJECT_MSG(CBOR_RPC_INVALID_REQUEST, "Input message too large to handle", msg_len);
            }
        }

        // If we have consumed all the data, break to reset the read-ptr and return
        if (msg_len == read) {
            break;
        }

        // Otherwise we have some data left in the buffer - move the unhandled data down to the start of the buffer
        // (overwriting what we've handled)
        // Also set 'reject_if_no_msg' to false, as we have now read a message.
        memmove(data_in, data_in + msg_len, read - msg_len);
        *read_ptr -= msg_len;
        reject_if_no_msg = false;
    }

    // Discard the entire buffer by resetting the read-ptr
    *read_ptr = 0;
}

// Handle new bytes received
// NOTE: assumes sizes of input and output buffers - could be passed sizes if preferred
void handle_data(uint8_t* full_data_in, size_t* read_ptr, const size_t new_data_len, TickType_t* last_processing_time,
    const bool force_reject_if_no_msg, uint8_t* data_out)
{
    JADE_ASSERT(full_data_in);
    JADE_ASSERT(read_ptr);
    JADE_ASSERT(*read_ptr + new_data_len <= MAX_INPUT_MSG_SIZE);
    JADE_ASSERT(last_processing_time);
    JADE_ASSERT(data_out);

    // Get current message processing time
    const TickType_t time_now = xTaskGetTickCount();
    JADE_ASSERT(time_now >= *last_processing_time);

    // Handle any stale bytes in the buffer
    if (*read_ptr > 0 && time_now > *last_processing_time + TIMEOUT_TICKS) {
        // Have stale bytes resting in buffer - reject them
        const bool reject_if_no_msg = true;
        const size_t initial_offset = *read_ptr;
        JADE_LOGW("Timing out %u bytes in buffer", *read_ptr);
        handle_data_impl(full_data_in, read_ptr, reject_if_no_msg, data_out);
        JADE_ASSERT(*read_ptr == 0);

        // Copy newly recevied bytes down to start of buffer
        uint8_t* const data_in = full_data_in + 1;
        memmove(data_in, data_in + initial_offset, new_data_len);
    }

    // Append new bytes, and try to parse
    *read_ptr += new_data_len;
    JADE_LOGD("Passing %u bytes to common handler", *read_ptr);
    const bool reject_if_no_msg = force_reject_if_no_msg || (*read_ptr == MAX_INPUT_MSG_SIZE);
    handle_data_impl(full_data_in, read_ptr, reject_if_no_msg, data_out);

    // Update caller's 'last processing time'
    *last_processing_time = time_now;
}
#endif // AMALGAMATED_BUILD
