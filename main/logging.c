#include "jade_assert.h"
#include "process.h"
#include "utils/cbor_rpc.h"
#include <esp_log.h>
#include <stdio.h>
#include <string.h>

static size_t BUFFER_SIZE = 256;
static size_t CBOR_OVERHEAD = 8;
static const char* TRUNCATE_TAIL = "...";

// Writes logging messages to the serial interface output buffer, ensuring
// that logging messages are not interleaved on the serial interface with
// application protocol messages
int serial_logger(const char* message, va_list fmt)
{
    char buff[BUFFER_SIZE];
    int written = vsnprintf(buff, sizeof(buff), message, fmt);

    if (written >= sizeof(buff)) {
        // The message has been truncated, write "...\n" to the end
        char* tail_begin = buff + sizeof(buff) - strlen(TRUNCATE_TAIL) - 1;
        memcpy(tail_begin, TRUNCATE_TAIL, strlen(TRUNCATE_TAIL));
        written = sizeof(buff) - 1;
    }

    CborEncoder root_encoder;
    uint8_t cbor_buff[BUFFER_SIZE + CBOR_OVERHEAD];
    cbor_encoder_init(&root_encoder, cbor_buff, sizeof(cbor_buff), 0);
    CborEncoder root_map_encoder; // LOG
    CborError cberr = cbor_encoder_create_map(&root_encoder, &root_map_encoder, 1);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&root_map_encoder, "log", (uint8_t*)buff, written);

    cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    const size_t towrite = cbor_encoder_get_buffer_size(&root_encoder, cbor_buff);

    jade_process_push_out_message((unsigned char*)cbor_buff, towrite, SOURCE_SERIAL);
#if defined(CONFIG_FREERTOS_UNICORE) && defined(CONFIG_ETH_USE_OPENETH)
    jade_process_push_out_message((unsigned char*)cbor_buff, towrite, SOURCE_QEMU_TCP);
#endif

    return written;
}
