#include "wire.h"

#include <ctype.h>
#include <string.h>

#include <cbor.h>
#include <esp_ota_ops.h>
#include <esp_system.h>

#include <wally_core.h>

#include "idletimer.h"
#include "jade_assert.h"
#include "keychain.h"
#include "process/ota.h"
#include "random.h"
#include "utils/cbor_rpc.h"

// Macros for use in handle_data() as always called with fixed params
#define SEND_REJECT_MSG(code, msg, data, datalen)                                                                      \
    jade_process_reject_message_ex(ctx, code, msg, data, datalen, data_out, MAX_OUTPUT_MSG_SIZE)

// Handle bytes received
void handle_data(uint8_t* full_data_in, size_t* read_ptr, uint8_t* data_out, jade_msg_source_t source)
{
    uint8_t* data_in = full_data_in + 1;
    const size_t read = *read_ptr;

    cbor_msg_t ctx = { .source = source, .cbor = NULL, .cbor_len = 0 };
    CborError cberr = cbor_parser_init(data_in, read, CborValidateBasic, &ctx.parser, &ctx.value);

    if (cberr != CborNoError || cbor_value_validate_basic(&ctx.value) != CborNoError) {
        JADE_LOGD("Got incomplete CBOR message, length %d - awaiting more data...", read);
        return;
    }

    // Message arrival counts as 'activity' against idle timeout
    idletimer_register_activity();

    if (!rpc_request_valid(&ctx.value)) {
        // bad message - expect all inputs to be cbor with a root map with an id and a method strings keys values
        JADE_LOGW("Invalid request, length %u", read);
        SEND_REJECT_MSG(CBOR_RPC_INVALID_REQUEST, "Invalid RPC Request message", data_in, read);
    } else {
        // Push to task queue for dashboard to handle
        if (!jade_process_push_in_message(full_data_in, read + 1)) {
            char read_data[5];
            const int ret = snprintf(read_data, sizeof(read_data), "%d", read);
            JADE_ASSERT(ret > 0 && ret < sizeof(read_data));
            SEND_REJECT_MSG(
                CBOR_RPC_INVALID_REQUEST, "Input message too large to handle", (uint8_t*)read_data, sizeof(read_data));
        }
    }

    *read_ptr = 0;
}
