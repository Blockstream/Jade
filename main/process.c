#ifndef AMALGAMATED_BUILD
#include "process.h"
#include "ble/ble.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "power.h"
#include "process/process_utils.h"
#include "utils/cbor_rpc.h"
#include "utils/malloc_ext.h"

#include <esp_mac.h>
#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

#include <ctype.h>
#include <stdlib.h>

static TaskHandle_t gui_handle = NULL;
static RingbufHandle_t shared_in = NULL;

static TaskHandle_t serial_handle = NULL;
static RingbufHandle_t serial_out = NULL;
static RingbufHandle_t ble_out = NULL;
static RingbufHandle_t qemu_tcp_out = NULL;
static TaskHandle_t internal_handle = NULL;
static RingbufHandle_t internal_out = NULL;
static jade_msg_source_t last_message_source = SOURCE_NONE;

#ifdef CONFIG_BT_ENABLED
static TaskHandle_t ble_handle;
#endif

#if defined(CONFIG_FREERTOS_UNICORE) && defined(CONFIG_ETH_USE_OPENETH)
static TaskHandle_t qemu_tcp_handle;
#endif

// The mac-id, loaded at startup in main.c
extern uint8_t macid[6];

// The 'id' we make using that mac-id
static char jade_id[16];

#define JADE_MSG_REPLY_LEN 256
#define JADE_MSG_REPLY_OVERHEAD 64

#ifdef CONFIG_HEAP_TRACING

#include <esp_heap_trace.h>

#define HEAP_TRACING_NUM_RECORDS 256
static heap_trace_record_t trace_record[HEAP_TRACING_NUM_RECORDS];
#endif /* CONFIG_HEAP_TRACING */

// Deferred void(*)(void*) function
struct _jade_deferred_fn_t {
    void_fn_t fn;
    void* param;

    jade_deferred_fn_t* next;
};

// Function to make a deferred-(void)function holder, and push it onto the top
// of the existing stack of deferred functions (ie. most recent at top).
static void add_deferred_function(jade_deferred_fn_t** existing, void_fn_t fn, void* param)
{
    JADE_ASSERT(existing);
    JADE_ASSERT(fn);

    jade_deferred_fn_t* fn_deferred = JADE_MALLOC(sizeof(jade_deferred_fn_t));

    fn_deferred->fn = fn;
    fn_deferred->param = param;
    fn_deferred->next = *existing;
    *existing = fn_deferred;
}

// Function to pop deferred functions from the stack, (optionally) call
// each one, and free/discard them (ie. last added, first called/freed).
static void cleanup_deferred_functions(jade_deferred_fn_t** p_fns, bool call)
{
    JADE_ASSERT(p_fns);

    while (*p_fns) {
        jade_deferred_fn_t* deferred = *p_fns;
        *p_fns = deferred->next;
        JADE_ASSERT(deferred->fn);

        // Maybe call the function on the param, then free the function-holder
        if (call) {
            (*deferred->fn)(deferred->param);
        }
        free(deferred);
    }
}

// Allocate ring buffer storage areas into SPIRAM if available
// NOTE: only suitable for global long-lasting buffers as we don't return
// the storage pointers so can't free them.
// NOTE: the ringsize *must be* 32-byte aligned (ie. a multiple of 4-bytes)
static RingbufHandle_t create_ringbuffer(const uint32_t ringsize)
{
    // Allocate into SPIRAM if available
    JADE_ASSERT(ringsize % 4 == 0); // 32bit == 4byte aligned size
    uint8_t* buffer_storage = JADE_MALLOC_PREFER_SPIRAM(ringsize);
    StaticRingbuffer_t* buffer_struct = JADE_MALLOC_PREFER_SPIRAM(sizeof(StaticRingbuffer_t));
    return xRingbufferCreateStatic(ringsize, RINGBUF_TYPE_NOSPLIT, buffer_storage, buffer_struct);
}

// Deduce and cache a serial name/number for the device based on mac-address  - eg: 'Jade ABCDEF'
static void deduce_jade_id(void)
{
    JADE_ASSERT(sizeof(jade_id) > 12);

    char* hexout = NULL;
    JADE_WALLY_VERIFY(wally_hex_from_bytes(macid, 6, &hexout));

    jade_id[0] = 'J';
    jade_id[1] = 'a';
    jade_id[2] = 'd';
    jade_id[3] = 'e';
    jade_id[4] = ' ';
    jade_id[5] = toupper((int)hexout[6]);
    jade_id[6] = toupper((int)hexout[7]);
    jade_id[7] = toupper((int)hexout[8]);
    jade_id[8] = toupper((int)hexout[9]);
    jade_id[9] = toupper((int)hexout[10]);
    jade_id[10] = toupper((int)hexout[11]);
    jade_id[11] = '\0';

    JADE_WALLY_VERIFY(wally_free_string(hexout));
}

// Get the Jade's serial number - eg: 'Jade ABCDEF'
const char* get_jade_id(void) { return jade_id; }

bool jade_process_init(TaskHandle_t** serial_h, TaskHandle_t** ble_h, TaskHandle_t** qemu_tcp_h, TaskHandle_t** gui_h)
{
    JADE_INIT_OUT_PPTR(serial_h);
    JADE_INIT_OUT_PPTR(ble_h);
    JADE_INIT_OUT_PPTR(qemu_tcp_h);

    if (shared_in || serial_out || ble_out || qemu_tcp_out || internal_out) {
        return false;
    }

    // Deduce jade-id from mac address
    deduce_jade_id();

    // Allocate ring buffer main storage areas into SPIRAM if available

    // NOTE: The inbound ring buffer should be twice the size of the largest
    // valid input message, as the largest item the buffer will hold is just
    // under half its size.
    shared_in = create_ringbuffer(2 * MAX_INPUT_MSG_SIZE + 32);
    JADE_ASSERT(shared_in);

    *gui_h = &gui_handle;
    // The ring buffers are quite generous because at startup, especially with
    // debug logging on, logging messages accumulate in the buffer before the
    // serial writer task starts running to clear them down.

    // Serial/ble/qemu_tcp task handles
    *serial_h = &serial_handle;
    serial_out = create_ringbuffer(2 * MAX_OUTPUT_MSG_SIZE + 32);
    JADE_ASSERT(serial_out);
#if defined(CONFIG_FREERTOS_UNICORE) && defined(CONFIG_ETH_USE_OPENETH)
    *qemu_tcp_h = &qemu_tcp_handle;
    qemu_tcp_out = create_ringbuffer(2 * MAX_OUTPUT_MSG_SIZE + 32);
    JADE_ASSERT(qemu_tcp_out);
#endif
#ifdef CONFIG_BT_ENABLED
    *ble_h = &ble_handle;
    ble_out = create_ringbuffer(2 * MAX_OUTPUT_MSG_SIZE + 32);
    JADE_ASSERT(ble_out);
#endif

#if defined(CONFIG_HAS_CAMERA) || defined(CONFIG_IDF_TARGET_ESP32S3)
    internal_handle = xTaskGetCurrentTaskHandle();
    internal_out = create_ringbuffer(2 * MAX_OUTPUT_MSG_SIZE + 32);
    JADE_ASSERT(internal_out);
#endif

#ifdef CONFIG_HEAP_TRACING
    const esp_err_t err = heap_trace_init_standalone(trace_record, HEAP_TRACING_NUM_RECORDS);
    JADE_LOGW("Failed to initialise heap tracing");
    if (err != ESP_OK) {
        JADE_LOGW("Failed to initialise heap tracing");
    }
#endif /* CONFIG_HEAP_TRACING */
    return true;
}

void init_jade_process(jade_process_t* process)
{
    JADE_ASSERT(process);

    // No 'current' message when intially created
    process->ctx.cbor = NULL;
    process->ctx.cbor_len = 0;
    process->ctx.source = SOURCE_NONE;

    // No at-exit hooks initially
    process->on_exit = NULL;
}

void jade_process_transfer_current_message(jade_process_t* process, jade_process_t* new_process)
{
    jade_process_free_current_message(new_process);
    if (process->ctx.cbor) {
        new_process->ctx = process->ctx;
        process->ctx.cbor = NULL;
        process->ctx.cbor_len = 0;
        process->ctx.source = SOURCE_NONE;
    }
}

void jade_process_free_current_message(jade_process_t* process)
{
    if (process->ctx.cbor) {
        free(process->ctx.cbor);
        process->ctx.cbor = NULL;
    }
    process->ctx.cbor_len = 0;
    process->ctx.source = SOURCE_NONE;
}

void cleanup_jade_process(jade_process_t* process)
{
    JADE_ASSERT(process);
    cleanup_deferred_functions(&process->on_exit, true); // call and discard
    jade_process_free_current_message(process);
}

// On-exit handlers - register functions to be called when process is freed

static void jade_wally_free_string_wrapper(void* str) { JADE_WALLY_VERIFY(wally_free_string((char*)str)); }

void jade_process_wally_free_string_on_exit(jade_process_t* process, char* str)
{
    jade_process_call_on_exit(process, jade_wally_free_string_wrapper, str);
}

void jade_process_free_on_exit(jade_process_t* process, void* param)
{
    jade_process_call_on_exit(process, free, param);
}

void jade_process_call_on_exit(jade_process_t* process, void_fn_t fn, void* param)
{
    JADE_ASSERT(process);
    add_deferred_function(&process->on_exit, fn, param);
}

bool jade_process_push_in_message(const uint8_t* data, const size_t size)
{
    JADE_ASSERT(data);

    // Input message too large - probably return error message
    if (size > xRingbufferGetMaxItemSize(shared_in)) {
        JADE_LOGE("Message of size %u too large for input queue (max: %u)", size, xRingbufferGetMaxItemSize(shared_in));
        return false;
    }
    while (xRingbufferSend(shared_in, data, size, 500 / portTICK_PERIOD_MS) != pdTRUE) {
        // wait for a spot in the ringbuffer
        JADE_LOGW("Failed to send input message using shared input ringbuffer");
    }

    return true;
}

bool jade_process_push_in_message_ex(const uint8_t* data, const size_t size, const jade_msg_source_t source)
{
    JADE_ASSERT(data);
    JADE_ASSERT(size);
    // Post as message into Jade with msg-source prefix
    const size_t fullsize = size + 1;
    uint8_t* const fullmsg = JADE_MALLOC(fullsize);
    fullmsg[0] = source;
    memcpy(fullmsg + 1, data, size);
    const bool ret = jade_process_push_in_message(fullmsg, fullsize);
    free(fullmsg);
    return ret;
}

void jade_process_push_out_message(const uint8_t* data, const size_t size, const jade_msg_source_t source)
{
#if defined(CONFIG_FREERTOS_UNICORE) && defined(CONFIG_ETH_USE_OPENETH)
    JADE_ASSERT(source == SOURCE_QEMU_TCP || source == SOURCE_SERIAL || source == SOURCE_INTERNAL);
#elif !defined(CONFIG_BT_ENABLED)
    JADE_ASSERT(source == SOURCE_SERIAL || source == SOURCE_INTERNAL);
#else
    JADE_ASSERT(source == SOURCE_SERIAL || source == SOURCE_BLE || source == SOURCE_INTERNAL);
#endif
    RingbufHandle_t ring = NULL;
    TaskHandle_t handle = NULL;
    switch (source) {
    case SOURCE_SERIAL:
        ring = serial_out;
        handle = serial_handle;
        break;
    case SOURCE_INTERNAL:
        ring = internal_out;
        handle = internal_handle;
        break;
#ifdef CONFIG_BT_ENABLED
    case SOURCE_BLE:
        ring = ble_out;
        handle = ble_handle;
        break;
#endif
#if defined(CONFIG_FREERTOS_UNICORE) && defined(CONFIG_ETH_USE_OPENETH)
    case SOURCE_QEMU_TCP:
        ring = qemu_tcp_out;
        handle = qemu_tcp_handle;
        break;
#endif
    default:
        JADE_ABORT();
    }

    JADE_ASSERT(ring);

    // Output message too large - internal/logic error - abort
    if (size > xRingbufferGetMaxItemSize(ring)) {
        JADE_LOGE("Message of size %u too large for output queue (max: %u)", size, xRingbufferGetMaxItemSize(ring));
        JADE_ABORT();
    }
    while (xRingbufferSend(ring, data, size, 10 / portTICK_PERIOD_MS) != pdTRUE) {

        // If the ring buffer is full and the sink process (handle) is not yet running
        // discard an item from the buffer to make space
        // This scenario should only apply to logging messages at startup when handle may
        // still be null
        if (!handle) {
            size_t sz;
            void* item = xRingbufferReceive(ring, &sz, 0);
            vRingbufferReturnItem(ring, item);
        }
    }

    if (handle) {
        xTaskNotify(handle, 0, eNoAction);
    }
}

#ifdef CONFIG_HEAP_TRACING
static void dump_mem_report(void)
{
    size_t count = heap_trace_get_count();
    heap_trace_record_t record;

    JADE_LOGD(
        "Total free: %u, max block: %u", xPortGetFreeHeapSize(), heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    JADE_LOGD("Analyzing %u records", count);

    char trace[CONFIG_HEAP_TRACING_STACK_DEPTH * 11 + 1];
    for (size_t i = 0; i < count; ++i) {
        heap_trace_get(i, &record);

        if (!record.freed_by[0]) {
            size_t pos = 0;

            for (size_t s = 0; s < CONFIG_HEAP_TRACING_STACK_DEPTH; ++s) {
                pos += snprintf(trace + pos, 12, "%p:", record.alloced_by[s]);
            }
            JADE_LOGE("Leaked memory @%p, size %u", record.address, record.size);
            JADE_LOGE("Trace: %s", trace);
        }
    }
}
#endif /* CONFIG_HEAP_TRACING */

void jade_process_get_in_message(void* ctx, inbound_message_reader_fn_t reader, bool blocking)
{
    // reader can be null to just discard messages
    // ctx is optional (but must be null if no reader callback)
    JADE_ASSERT(!ctx || reader);

    const TickType_t delay = 40 / portTICK_PERIOD_MS;
    do {
        size_t item_size = 0;
        void* item = xRingbufferReceive(shared_in, &item_size, delay);

        if (item != NULL) {
            // Got item from queue
            if (reader) {
                reader(ctx, (uint8_t*)item, item_size);
            }
            vRingbufferReturnItem(shared_in, item);
            return;
        }

        // Check connection - if the last used source is disconnected then return with 'no message'.
        // (NOTE: we can't detect the QR source as 'disconnected' - so only consider this when
        // the last message was over serial or ble, and now that interface is not connected.
        // NOTE: this check only really affects 'blocking' calls, as a non-blocking call is going
        // to return 'no message' here in any case.
        if (blocking && last_message_source != SOURCE_NONE) {
            const bool lost_usb_connection = (last_message_source == SOURCE_SERIAL) && !usb_connected();
            const bool lost_ble_connection = (last_message_source == SOURCE_BLE) && !ble_connected();
            if (lost_usb_connection || lost_ble_connection) {
                JADE_LOGE("Lost connection, returning from blocking wait without fetching message");
                last_message_source = SOURCE_NONE;
                return;
            }
        }
    } while (blocking);
}

static void process_cbor_msg(void* ctx, uint8_t* data, size_t size)
{
    JADE_ASSERT(size > 2); // 1 for source and 1 for data
    cbor_msg_t* cbor_msg = ctx;
    cbor_msg->source = (jade_msg_source_t)data[0];
    cbor_msg->cbor = JADE_MALLOC(size - 1);
    memcpy(cbor_msg->cbor, data + 1, size - 1);
    cbor_msg->cbor_len = size - 1;
    CborError cberr
        = cbor_parser_init(cbor_msg->cbor, cbor_msg->cbor_len, CborValidateBasic, &cbor_msg->parser, &cbor_msg->value);
    JADE_ASSERT(cberr == CborNoError);

    // Set a flag to cache the last received message source
    last_message_source = (jade_msg_source_t)data[0];
}

// Fetch the next input cbor message into the process 'current message'
void jade_process_load_in_message(jade_process_t* process, bool blocking)
{
    // Free the current message and fetch the next
    jade_process_free_current_message(process);
    jade_process_get_in_message(&process->ctx, process_cbor_msg, blocking);
}

// NOTE: the return here indicates whether a message was taken and passed to the writer callback
// which could handle it in some way - *NOT* that the processing was logically 'successful' - if
// this needs or other data needs to be returned to the caller the opaque context 'ctx' should be used.
bool jade_process_get_out_message(outbound_message_writer_fn_t writer, const jade_msg_source_t source, void* ctx)
{
    // writer can be null to just discard messages
    // ctx is optional (but must be null if no writer callback)
    JADE_ASSERT(!ctx || writer);

    RingbufHandle_t ring = NULL;
    switch (source) {
    case SOURCE_SERIAL:
        ring = serial_out;
        break;
    case SOURCE_INTERNAL:
        ring = internal_out;
        break;
#ifdef CONFIG_BT_ENABLED
    case SOURCE_BLE:
        ring = ble_out;
        break;
#endif
#if defined(CONFIG_FREERTOS_UNICORE) && defined(CONFIG_ETH_USE_OPENETH)
    case SOURCE_QEMU_TCP:
        ring = qemu_tcp_out;
        break;
#endif
    default:
        JADE_ABORT();
    }
    JADE_ASSERT(ring);

    size_t item_size = 0;
    void* item = xRingbufferReceive(ring, &item_size, 20 / portTICK_PERIOD_MS);
    if (!item) {
        // No message available
        return false;
    }

    bool res = true; // default for simple discard
    if (writer) {
        res = writer((const uint8_t*)item, item_size, ctx);
    }
    vRingbufferReturnItem(ring, item);

    // FIXME: currently false signals that there isn't anything on the buffer
    // to process but this is not distinguished from a failure to write.
    // If there is a failure to write we currently drop the message
    // NOTE: the passed context object should be used by the writer to return
    // any richer information regards message processing.
    return res; // message was handled, whether 'successfully' or not
}

void jade_process_reply_to_message_ex(jade_msg_source_t source, const uint8_t* reply_payload, const size_t payload_len)
{
    JADE_LOGD("jade_process_reply_to_message_ex %u", payload_len);
    jade_process_push_out_message(reply_payload, payload_len, source);
}

void jade_process_reply_to_message_result_with_id(const char* id, uint8_t* output, const size_t output_size,
    const jade_msg_source_t source, const void* cbctx, cbor_encoder_fn_t cb)
{
    JADE_ASSERT(id);
    JADE_ASSERT(output);
    JADE_ASSERT(cb);
    CborEncoder root_encoder;

    cbor_encoder_init(&root_encoder, output, output_size, 0);

    CborEncoder root_map_encoder; // id, result

    CborError cberr = cbor_encoder_create_map(&root_encoder, &root_map_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);
    rpc_init_cbor(&root_map_encoder, id, strlen(id));

    cb(cbctx, &root_map_encoder);

    cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);
    const size_t cbor_size = cbor_encoder_get_buffer_size(&root_encoder, output);

    jade_process_reply_to_message_ex(source, output, cbor_size);
}

void cbor_result_bytes_cb(const void* ctx, CborEncoder* container)
{
    const bytes_info_t* bytes_info = (const bytes_info_t*)ctx;
    const CborError cberr = cbor_encode_byte_string(container, bytes_info->data, bytes_info->size);
    JADE_ASSERT(cberr == CborNoError);
}

void cbor_result_string_cb(const void* ctx, CborEncoder* container)
{
    const CborError cberr = cbor_encode_text_stringz(container, (const char*)ctx);
    JADE_ASSERT(cberr == CborNoError);
}

void cbor_result_boolean_cb(const void* ctx, CborEncoder* container)
{
    const bool val = *(const bool*)ctx;
    const CborError cberr = cbor_encode_boolean(container, val);
    JADE_ASSERT(cberr == CborNoError);
}

void cbor_result_uint64_cb(const void* ctx, CborEncoder* container)
{
    const uint64_t val = *(const uint64_t*)ctx;
    const CborError cberr = cbor_encode_uint(container, val);
    JADE_ASSERT(cberr == CborNoError);
}

void jade_process_reply_to_message_result(
    const cbor_msg_t ctx, uint8_t* output, size_t output_size, const void* cbctx, cbor_encoder_fn_t cb)
{
    JADE_ASSERT(cb);
    JADE_ASSERT(output);
    JADE_ASSERT(output_size);

    char id[MAXLEN_ID + 1];
    size_t written = 0;
    rpc_get_id(&ctx.value, id, sizeof(id), &written);
    JADE_ASSERT(written != 0);

    jade_process_reply_to_message_result_with_id(id, output, output_size, ctx.source, cbctx, cb);
}

void jade_process_reply_to_message_ok(jade_process_t* process)
{
    uint8_t buf[64];
    const bool ok = true;
    jade_process_reply_to_message_result(process->ctx, buf, sizeof(buf), &ok, cbor_result_boolean_cb);
}

void jade_process_reply_to_message_fail(jade_process_t* process)
{
    uint8_t buf[64];
    const bool ok = false;
    jade_process_reply_to_message_result(process->ctx, buf, sizeof(buf), &ok, cbor_result_boolean_cb);
}

void jade_process_reject_message_with_id(const char* id, int code, const char* message, const uint8_t* data,
    const size_t datalen, uint8_t* buffer, const size_t buffer_len, const jade_msg_source_t source)
{
    JADE_ASSERT(message);
    JADE_ASSERT(data || datalen == 0);
    JADE_ASSERT(buffer);
    JADE_ASSERT(buffer_len > 0);

    size_t towrite = 0;
    if (cbor_print_error_for(id, code, message, data, datalen, buffer, buffer_len, &towrite)
        || cbor_print_error_for(id, code, message, NULL, 0, buffer, buffer_len, &towrite)) {
        JADE_LOGI("jade_pushing out reject");
        jade_process_push_out_message(buffer, towrite, source);
    } else {
        // Can't flatten message to buffer?
        JADE_LOGE("Failed to flatten error message to buffer of size %u", buffer_len);
        JADE_ABORT();
    }
}

void jade_process_reject_message_ex(const cbor_msg_t ctx, int code, const char* message, const uint8_t* data,
    const size_t datalen, uint8_t* buffer, const size_t buffer_len)
{
    char id[MAXLEN_ID + 1];
    size_t written = 0;
    rpc_get_id(&ctx.value, id, sizeof(id), &written);
    jade_process_reject_message_with_id(
        written > 0 ? id : "00", code, message, data, datalen, buffer, buffer_len, ctx.source);
}

void jade_process_reject_message(jade_process_t* process, int code, const char* message)
{
    if (HAS_CURRENT_MESSAGE(process)) {
        uint8_t buf[JADE_MSG_REPLY_LEN];
        jade_process_reject_message_ex(process->ctx, code, message, NULL, 0, buf, sizeof(buf));
    } else {
        JADE_LOGW("Ignoring attempt to reject 'no-message'");
    }
}

void jade_process_reply_to_message_bytes(const cbor_msg_t ctx, const uint8_t* data, const size_t datalen)
{
    // Avoid allocating for small replies
    uint8_t buf[JADE_MSG_REPLY_LEN];
    uint8_t* buffer = buf;
    size_t buflen = sizeof(buf);

    if (datalen > JADE_MSG_REPLY_LEN - JADE_MSG_REPLY_OVERHEAD) {
        buflen = datalen + JADE_MSG_REPLY_OVERHEAD;
        JADE_ASSERT(buflen > sizeof(buf));
        buffer = JADE_MALLOC(buflen);
    }

    CborEncoder root_encoder;
    cbor_encoder_init(&root_encoder, buffer, buflen, 0);

    CborEncoder root_map_encoder; // id, result

    CborError cberr = cbor_encoder_create_map(&root_encoder, &root_map_encoder, 2);

    JADE_ASSERT(cberr == CborNoError);
    const char* id = NULL;
    size_t written = 0;
    rpc_get_id_ptr(&ctx.value, &id, &written);
    JADE_ASSERT(written != 0);
    rpc_init_cbor(&root_map_encoder, id, written);
    cberr = cbor_encode_byte_string(&root_map_encoder, data, datalen);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);
    jade_process_push_out_message(buffer, cbor_encoder_get_buffer_size(&root_encoder, buffer), ctx.source);

    if (buffer != buf) {
        // Allocated buffer
        free(buffer);
    }
}

void jade_process_reply_to_message_bytes_sequence(const cbor_msg_t ctx, const size_t seqnum, const size_t seqlen,
    const uint8_t* data, const size_t datalen, uint8_t* buffer, const size_t buflen)
{
    CborEncoder root_encoder;
    cbor_encoder_init(&root_encoder, buffer, buflen, 0);

    CborEncoder root_map_encoder; // id, result

    // NOTE: bytes additional sequence numbers in the message header
    CborError cberr = cbor_encoder_create_map(&root_encoder, &root_map_encoder, 4);

    JADE_ASSERT(cberr == CborNoError);
    const char* id = NULL;
    size_t written = 0;
    rpc_get_id_ptr(&ctx.value, &id, &written);
    JADE_ASSERT(written != 0);
    rpc_init_cbor_with_sequence(&root_map_encoder, id, written, seqnum, seqlen);
    cberr = cbor_encode_byte_string(&root_map_encoder, data, datalen);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);
    jade_process_push_out_message(buffer, cbor_encoder_get_buffer_size(&root_encoder, buffer), ctx.source);
}
#endif // AMALGAMATED_BUILD
