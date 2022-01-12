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
#include "random.h"
#include "utils/cbor_rpc.h"

// Macros for use in handle_data() as always called with fixed params
#define SEND_REJECT_MSG(code, msg, data, datalen)                                                                      \
    jade_process_reject_message_ex(ctx, code, msg, data, datalen, data_out, MAX_OUTPUT_MSG_SIZE)

// Handle bytes received
void handle_data(
    uint8_t* full_data_in, const size_t initial_offset, size_t* read_ptr, uint8_t* data_out, jade_msg_source_t source)
{
    JADE_ASSERT(full_data_in);
    JADE_ASSERT(read_ptr);
    JADE_ASSERT(*read_ptr > initial_offset);
    JADE_ASSERT(data_out);

    uint8_t* data_in = full_data_in + 1;

    while (true) {
        cbor_msg_t ctx = { .source = source, .cbor = NULL, .cbor_len = 0 };
        const size_t read = *read_ptr;

        size_t msg_size = 0;

        // Start validating from 'initial_offset' as we can assume we have validated up to that point in a previous
        // call (ie. with the previous data chunk).  Validating one byte at a time is painful enough, without repeating
        // validation from the start with each chunk of additional message data received.
        for (size_t i = initial_offset; i <= read; ++i) {
            const CborError cberr = cbor_parser_init(data_in, i, CborValidateCompleteData, &ctx.parser, &ctx.value);
            if (cberr == CborNoError && cbor_value_validate_basic(&ctx.value) == CborNoError) {
                msg_size = i;
                break;
            }
        }

        if (msg_size == 0) {
            JADE_LOGD("Got incomplete CBOR message, length %d - awaiting more data...", read);
            return;
        }

        // Message arrival counts as 'activity' against idle timeout
        idletimer_register_activity();

        if (!rpc_request_valid(&ctx.value)) {
            // bad message - expect all inputs to be cbor with a root map with an id and a method strings keys values
            JADE_LOGW("Invalid request, length %u", msg_size);
            SEND_REJECT_MSG(CBOR_RPC_INVALID_REQUEST, "Invalid RPC Request message", data_in, read);
            break;
        } else {
            // Push to task queue for dashboard to handle
            if (!jade_process_push_in_message(full_data_in, msg_size + 1)) {
                char read_data[5];
                const int ret = snprintf(read_data, sizeof(read_data), "%d", msg_size);
                JADE_ASSERT(ret > 0 && ret < sizeof(read_data));
                SEND_REJECT_MSG(CBOR_RPC_INVALID_REQUEST, "Input message too large to handle", (uint8_t*)read_data,
                    sizeof(read_data));
            }
        }

        if (msg_size == read) {
            break;
        }

        memmove(data_in, data_in + msg_size, read - msg_size);
        *read_ptr -= msg_size;
    }

    *read_ptr = 0;
}
