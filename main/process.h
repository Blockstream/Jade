#ifndef PROCESS_H_
#define PROCESS_H_

#include <esp_event.h>
#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <sdkconfig.h>
#include <stdbool.h>
#include <stddef.h>

#include <cbor.h>

// This should be the size of the largest valid input message.
// Used by ble and serial when reading data in. (sign-liquid-txn)
// NOTE: limited to 17k when SPIRAM not enabled.
#ifndef CONFIG_SPIRAM
#define MAX_INPUT_MSG_SIZE (1024 * 17)
#else
#define MAX_INPUT_MSG_SIZE (1024 * 401)
#endif

// This should be the size of the largest valid output message.
// Used by ble and serial when sending messages. (pinserver handshake)
// NOTE: if CONFIG_RETURN_CAMERA_IMAGES is defined we allocate a larger
// buffer as image sizes are much larger than standard messges.
#define MAX_STANDARD_OUTPUT_MSG_SIZE (1024 * 3)
#ifdef CONFIG_RETURN_CAMERA_IMAGES
#ifdef CONFIG_IDF_TARGET_ESP32S3
#define MAX_OUTPUT_MSG_SIZE (MAX_STANDARD_OUTPUT_MSG_SIZE * 100)
#else
#define MAX_OUTPUT_MSG_SIZE (MAX_STANDARD_OUTPUT_MSG_SIZE * 30)
#endif // CONFIG_IDF_TARGET_ESP32S3
#else
#define MAX_OUTPUT_MSG_SIZE MAX_STANDARD_OUTPUT_MSG_SIZE
#endif // CONFIG_RETURN_CAMERA_IMAGES

// Cbor encoding function prototype
typedef void (*cbor_encoder_fn_t)(const void*, CborEncoder*);

// Deferred functions (called at process exit)
typedef void (*void_fn_t)(void*);
typedef struct _jade_deferred_fn_t jade_deferred_fn_t;

// Callback to read inbound messages from the inbound queue
typedef void (*inbound_message_reader_fn_t)(void*, uint8_t*, size_t);

// Callback to write messages to the outbound destination
typedef bool (*outbound_message_writer_fn_t)(const uint8_t*, size_t, void*);

typedef enum { SOURCE_NONE, SOURCE_INTERNAL, SOURCE_SERIAL, SOURCE_QEMU_TCP, SOURCE_BLE } jade_msg_source_t;

typedef struct {
    CborValue value;
    CborParser parser;
    uint8_t* cbor;
    size_t cbor_len;
    jade_msg_source_t source;
} cbor_msg_t;

typedef struct {
    cbor_msg_t ctx;
    jade_deferred_fn_t* on_exit;
} jade_process_t;

typedef struct {
    const uint8_t* data;
    size_t size;
} bytes_info_t;

const char* get_jade_id(void);
bool jade_process_init(
    TaskHandle_t** serial_handle, TaskHandle_t** ble_handle, TaskHandle_t** qemu_tcp_handle, TaskHandle_t** gui_handle);

// Intialise and cleanup jade process structs
void init_jade_process(jade_process_t* process_ptr);
void cleanup_jade_process(jade_process_t* process);

// On-exit handlers - register functions to be called when process is freed
void jade_process_free_on_exit(jade_process_t* process, void* param);
void jade_process_wally_free_string_on_exit(jade_process_t* process, char* str);
void jade_process_call_on_exit(jade_process_t* process, void_fn_t fn, void* param);

// A process can have a 'current' input message for processing
void jade_process_load_in_message(jade_process_t* process, bool blocking);
void jade_process_transfer_current_message(jade_process_t* process, jade_process_t* new_process);
void jade_process_free_current_message(jade_process_t* process);

// Push messages to/from a process
bool jade_process_push_in_message(const uint8_t* data, size_t size);
bool jade_process_push_in_message_ex(const uint8_t* data, size_t size, jade_msg_source_t source);
void jade_process_push_out_message(const uint8_t* data, size_t length, jade_msg_source_t source);

// Send message replies
void jade_process_reply_to_message_result_with_id(const char* id, uint8_t* output, size_t output_size,
    jade_msg_source_t source, const void* cbctx, cbor_encoder_fn_t cb);
void jade_process_reply_to_message_result(
    const cbor_msg_t ctx, uint8_t* output, size_t output_size, const void* cbctx, cbor_encoder_fn_t cb);
void jade_process_reply_to_message_ok(jade_process_t* process);
void jade_process_reply_to_message_fail(jade_process_t* process);
void jade_process_reply_to_message_ex(jade_msg_source_t source, const uint8_t* reply_payload, size_t payload_len);
void jade_process_reject_message(jade_process_t* process, int code, const char* message);
void jade_process_reject_message_with_id(const char* id, int code, const char* message, const uint8_t* data,
    size_t datalen, uint8_t* buffer, size_t buffer_len, jade_msg_source_t source);
void jade_process_reject_message_ex(cbor_msg_t ctx, int code, const char* message, const uint8_t* data, size_t datalen,
    uint8_t* buffer, size_t buffer_len);

// Get in/out messages from the queues/ring-buffers
void jade_process_get_in_message(void* ctx, inbound_message_reader_fn_t reader, bool blocking);
bool jade_process_get_out_message(outbound_message_writer_fn_t writer, jade_msg_source_t source, void* ctx);

// The inbound message mode
void cbor_result_bytes_cb(const void* ctx, CborEncoder* container);
void cbor_result_string_cb(const void* ctx, CborEncoder* container);
void cbor_result_boolean_cb(const void* ctx, CborEncoder* container);
void cbor_result_uint64_cb(const void* ctx, CborEncoder* container);

void jade_process_reply_to_message_bytes(
    cbor_msg_t ctx, const uint8_t* data, size_t datalen, uint8_t* buffer, size_t buflen);
void jade_process_reply_to_message_bytes_sequence(cbor_msg_t ctx, const size_t seqnum, const size_t seqlen,
    const uint8_t* data, const size_t datalen, uint8_t* buffer, const size_t buflen);

#endif /* PROCESS_H_ */
