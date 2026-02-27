// A single source file containing a local implementation of the Jade Firmware
//
// This hack is designed for local development, debugging and testing.
//
// WARNING: THIS CODE IS NOT SUITABLE FOR PROCESSING REAL DATA.
//          DO NOT USE THIS CODE FOR ANY PURPOSE WITH NON-TEST DATA.
//          DOING SO IS INSECURE AND MAY RESULT IN THE LOSS OF FUNDS!
//
// Includes the entire Jade firmware code, replacing the GUI and most
// of the OS support code.
// This file can be compiled to a shared library which implements an
// in-processes software Jade emulator/virtual Jade device.
// The exposed API allows passing and fetching messages using the same
// binary format that would be passed to a real device by serial/bluetooth.
//
#define _GNU_SOURCE 1 // FIXME: needed for strcasestr in qrmode.c
#include <string.h>
#undef _GNU_SOURCE
#include "sdkconfig.h"

#include "libjade.h"

#include "icons.inc"

// Prevent secp symbols being externally visible in our final shared library
#define SECP256K1_API

// Address sanitizer doesn't like calling sha256 into a non-aligned
// buffer, even though its technically legal (but slower). Force
// wally to handle unaligned destination buffers internally to work
// around this.
#define HAVE_UNALIGNED_ACCESS 0

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/time.h> // Must be included before we redefine settimeofday()

// Include the tinycbor sources we need for CBOR processing
#include "managed_components/espressif__cbor/tinycbor/src/cborencoder.c"
#include "managed_components/espressif__cbor/tinycbor/src/cborparser.c"
#include "managed_components/espressif__cbor/tinycbor/src/cborparser_dup_string.c"
#include "managed_components/espressif__cbor/tinycbor/src/cborpretty.c"
#include "managed_components/espressif__cbor/tinycbor/src/cborpretty_stdio.c"
#include "managed_components/espressif__cbor/tinycbor/src/cbortojson.c"
// Include the asset snapshot component sources
#include "components/assets/assets_snapshot.c"
// Include the miniz compression code.
// This is a manually shortened version of the amalgamation from
// https://github.com/richgel999/miniz with a couple of additional
// patches for memory safety.
#include "miniz.c"
// Include the emulation of the o/s task/event/camera functions
#include "esp_camera.c"
#include "esp_event.c"
#include "task.c"
// Include the esp32_deflate component
#define ESP_PLATFORM 1
#define ESP_IDF_VERSION 1
#define ESP_IDF_VERSION_VAL(x, y, z) 1
#include "components/esp32_deflate/deflate.h"
#undef ESP_IDF_VERSION_VAL
#undef ESP_IDF_VERSION
#undef ESP_PLATFORM
#include "components/esp32_deflate/deflate.c"
// qrCode encoding/decoding
#include "components/esp32-quirc/lib/decode.c"
#include "components/esp32-quirc/lib/identify.c"
#include "components/esp32-quirc/lib/quirc.c"
#include "components/esp32-quirc/lib/version_db.c"
#include "components/esp32-quirc/openmv/collections.c"
// bspatch
#include "components/esp32_bsdiff/bspatch.c"

// abort is mapped to __wrap_abort in the firmware. This calls jade_abort,
// which calls __real_abort, which we implement as calling (the real) abort
static void __real_abort(void) { abort(); }

// Make time setting a no-op.
// We are in the same process as the caller, so anything that depends on the
// current time will automatically match the callers time.
static int settimeofday_no_op(const void* yv, const void* tz) { return 0; }
#define settimeofday settimeofday_no_op

#include "main/camera.h"
#include "main/display.h"
#include "main/gui.h"

typedef void* locale_multilang_string_t;
const locale_multilang_string_t* locale_get(const char* key) { return NULL; }
const char* locale_lang_with_fallback(const locale_multilang_string_t* str, jlocale_t lang) { return NULL; }

// Include the core Jade firmware core, including wally/secp.
#define AMALGAMATED_BUILD
#include "main/amalgamated.c"
#undef settimeofday

// Include the NVS emulation code
#include "nvs_flash.c"

//
// Stubs for code that does not apply to libjade or is not yet implemented
//

// main/idletimer.c
void idletimer_init(void) {}
bool idletimer_register_activity(const bool is_ui) { return false; }
void idletimer_set_min_timeout_secs(uint16_t min_timeout_secs) {};

// main/logging.c
#ifndef CONFIG_LOG_DEFAULT_LEVEL_NONE
esp_log_level_t _libjade_log_level = ESP_LOG_NONE;
#endif

// main/selfcheck.c
bool debug_selfcheck(jade_process_t* process) { return true; }

esp_app_desc_t running_app_info = { "123456789012345678901" };
esp_chip_info_t chip_info = { 0 };

void esp_restart() { abort(); }

const char* esp_get_idf_version(void) { return "9.9.99-99-fake_hack"; }

void esp_chip_info(esp_chip_info_t* out)
{
    out->features = 0; // FIXME
}

esp_err_t esp_efuse_mac_get_default(uint8_t* out)
{
    memset(out, 0, 6);
    return ESP_OK;
}

void esp_deep_sleep_start(void) { abort(); }

// No physical buttons
void input_init(void) {}

// Serial
bool serial_init(TaskHandle_t* task) { return true; }

// main/ui/keyboard.c
void make_keyboard_entry_activity(keyboard_entry_t* kb_entry, const char* title) {}

void run_keyboard_entry_loop(keyboard_entry_t* kb_entry) {}

const uint8_t _binary_pinserver_public_key_pub_start[33]
    = { 0x03, 0x32, 0xb7, 0xb1, 0x34, 0x8b, 0xde, 0x8c, 0xa4, 0xb4, 0x6b, 0x9d, 0xcc, 0x30, 0x32, 0x0e, 0x14, 0x0c,
          0xa2, 0x64, 0x28, 0x16, 0x0a, 0x27, 0xbd, 0xbf, 0xc3, 0x0b, 0x34, 0xec, 0x87, 0xc5, 0x47 };

// Events
volatile bool _libjade_stop_requested = false; // Used to stop the firmware

// HW: Task API
bool run_on_temporary_stack(size_t stack_size, temporary_stack_function_t fn, void* ctx) { return fn(ctx); }

bool run_in_temporary_task(const size_t stack_size, temporary_stack_function_t fn, void* ctx) { return fn(ctx); }

void temp_stack_init(void) {}

void sensitive_init(void) {}

void sensitive_push(const char* file, int line, void* addr, size_t size) {}

void sensitive_pop(const char* file, int line, void* addr) {}

void sensitive_assert_empty(void) {}

void sensitive_clear_stack(void) {}

// HW: Random
void get_random(void* bytes_out, size_t len)
{
    if (!bytes_out || !len) {
        abort();
    }

    uint8_t* current_ptr = (uint8_t*)bytes_out;
    size_t remaining = len;
    int getrandom_enosys = 0;

    while (remaining > 0) {
        const ssize_t bytes_read = getrandom(current_ptr, remaining, 0);

        if (bytes_read == -1) {
            if (errno == EINTR) {
                continue;
            } else if (errno == ENOSYS) {
                getrandom_enosys = 1;
                break;
            } else {
                abort();
            }
        } else if (bytes_read == 0) {
            abort();
        } else {
            current_ptr += bytes_read;
            remaining -= bytes_read;
        }
    }

    if (remaining == 0 && !getrandom_enosys) {
        // happy path
        return;
    }

    if (getrandom_enosys) {
        // FIXME: find another source of entropy of cryptographic strength or abort()
    }
    abort();
}

void refeed_entropy(const void* additional, size_t len)
{
    // Unused since our get_random has no state.
    // FIXME: change main/random.c to use getrandom, pids etc for libjade, then use it
}

uint8_t get_uniform_random_byte(uint8_t upper_bound)
{
    uint8_t ret;
    get_random(&ret, sizeof(ret));
    return ret % upper_bound; // Not used for crypto, so return a biased byte
}

void random_start_collecting(void) {}

void random_full_initialization(void) {}

int random_mbedtls_cb(void* ctx, uint8_t* buf, const size_t len)
{
    // ctx is ignored (should be NULL)
    get_random(buf, len);
    return 0;
}

static void* jade_fw_thread_fn(void* arg)
{
    start_dashboard();
    return NULL; // Never reached
}

// External API:
static pthread_t _libjade_thread_id = 0; // Thread ID of the FW thread

void libjade_start(void)
{
    ensure_boot_flags();
    random_start_collecting();
    validate_running_image();
    boot_process();
    sensitive_assert_empty();
    pthread_create(&_libjade_thread_id, NULL, &jade_fw_thread_fn, NULL);
    pthread_setname_np(_libjade_thread_id, "libjade_fw");
}

void libjade_stop(void)
{
    // stop camera task (if running)
    camera_stop();
    // Request the firmware to stop
    // the main firmware thread branches down various code paths depending on what activity the user
    // is doing, and in some of those code paths it may be waiting for an event with no timeout.
    _libjade_stop_requested = true;
    _trigger_last_wait_handle();
    pthread_join(_libjade_thread_id, NULL);
    _libjade_thread_id = 0;
    _libjade_stop_requested = false;
    // stop the gui task
    gui_stop();
    // clean up remaining resources
    esp_event_loop_delete_default();
    vRingbufferDelete(shared_in);
    shared_in = NULL;
    vRingbufferDelete(serial_out);
    serial_out = NULL;
    vRingbufferDelete(internal_out);
    internal_out = NULL;
    // clear keychain
    keychain_clear();
}

static uint8_t _libjade_serial_data_in[MAX_INPUT_MSG_SIZE + 1] = { 0 };
static size_t _libjade_serial_read_ptr = 0;
static TickType_t _libjade_last_processing_time = 0;

bool libjade_send(const uint8_t* data, size_t len)
{
    // Pass messages as though they come from the serial interface
    _libjade_serial_data_in[0] = SOURCE_SERIAL;
    while (len) {
        const size_t remaining_bytes = MAX_INPUT_MSG_SIZE - _libjade_serial_read_ptr;
        const size_t copy_len = len > remaining_bytes ? remaining_bytes : len;

        JADE_ASSERT(_libjade_serial_read_ptr + copy_len <= MAX_INPUT_MSG_SIZE);
        memcpy(_libjade_serial_data_in + 1 + _libjade_serial_read_ptr, data, copy_len);

        // Pass data through to the common handler
        handle_data(_libjade_serial_data_in, &_libjade_serial_read_ptr, copy_len, &_libjade_last_processing_time);
        data += copy_len;
        len -= copy_len;
    }
    return true;
}

uint8_t* libjade_receive(const unsigned int timeout, size_t* len_out)
{
    // timeout is in seconds, convert to milliseconds
    const unsigned int ms = timeout * 1000;
    void* item = xRingbufferReceive(serial_out, len_out, ms / portTICK_PERIOD_MS);
    if (!item) {
        // No message available
        *len_out = 0;
    }
    return item;
}

void libjade_release(uint8_t* data) { vRingbufferReturnItem(serial_out, (void*)data); }

void libjade_set_log_level(int level)
{
#ifndef CONFIG_LOG_DEFAULT_LEVEL_NONE
    // Note we don't bother about thread safety for _libjade_log_level
    if (level < 0) {
        _libjade_log_level = ESP_LOG_VERBOSE;
    } else if (level >= ESP_LOG_NONE) {
        _libjade_log_level = ESP_LOG_NONE;
    } else {
        _libjade_log_level = (esp_log_level_t)level;
    }
#endif
}

static void build_display_size_reply(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx && container);
    CborEncoder map_encoder;
    JADE_ASSERT(cbor_encoder_create_map(container, &map_encoder, 2) == CborNoError);
    add_uint_to_map(&map_encoder, "width", CONFIG_DISPLAY_WIDTH);
    add_uint_to_map(&map_encoder, "height", CONFIG_DISPLAY_HEIGHT);
    JADE_ASSERT(cbor_encoder_close_container(container, &map_encoder) == CborNoError);
}

// libjade RPC handlers
#define CONST_STRNCMP(str, str_len, cmp_to) str_len == sizeof(cmp_to) - 1 && !strncmp(str, cmp_to, str_len)
#define IS_JADE_REQUEST(name) CONST_STRNCMP(request, request_len, name)

void process_libjade_request(const cbor_msg_t* const ctx)
{
    CborValue params;
    if (!rpc_get_map("params", &ctx->value, &params)) {
        goto cleanup;
    }

    const char* request;
    size_t request_len = 0;
    rpc_get_string_ptr("request", &params, &request, &request_len);
    JADE_ASSERT(request_len != 0);

    if (IS_JADE_REQUEST("send_input")) {
        const char* event;
        size_t event_len = 0;
        rpc_get_string_ptr("event", &params, &event, &event_len);
        if (CONST_STRNCMP(event, event_len, "left")) {
            jade_process_reply_to_message_ok_ex(ctx);
            gui_prev();
        } else if (CONST_STRNCMP(event, event_len, "right")) {
            jade_process_reply_to_message_ok_ex(ctx);
            gui_next();
        } else if (CONST_STRNCMP(event, event_len, "click")) {
            jade_process_reply_to_message_ok_ex(ctx);
            gui_front_click();
        } else {
            goto cleanup;
        }
        return;
    } else if (IS_JADE_REQUEST("get_display_bytes")) {
        const uint8_t* output = (uint8_t*)display_hw_get_buffer();
        const size_t output_len = CONFIG_DISPLAY_WIDTH * CONFIG_DISPLAY_HEIGHT * sizeof(color_t);
        jade_process_reply_to_message_bytes(ctx, output, output_len);
        return;
    } else if (IS_JADE_REQUEST("get_display_size")) {
        uint8_t buf[128]; // sufficient
        jade_process_reply_to_message_result(ctx, buf, sizeof(buf), &ctx->source, build_display_size_reply);
        return;
    } else if (IS_JADE_REQUEST("set_camera_bytes")) {
        const uint8_t* bytes = NULL;
        size_t bytes_len = 0;
        rpc_get_bytes_ptr("bytes", &params, &bytes, &bytes_len);
        if (libjade_push_camera_frame(bytes, bytes_len)) {
            jade_process_reply_to_message_ok_ex(ctx);
            return;
        }
    } else if (IS_JADE_REQUEST("get_nvs")) {
        uint8_t* output;
        size_t output_len;
        if (libjade_save_nvs(&output, &output_len) == ESP_OK) {
            jade_process_reply_to_message_bytes(ctx, output, output_len);
            JADE_WALLY_VERIFY(wally_bzero(output, output_len));
            free(output);
            return;
        }
    } else if (IS_JADE_REQUEST("set_nvs")) {
        const uint8_t* bytes = NULL;
        size_t bytes_len = 0;
        rpc_get_bytes_ptr("bytes", &params, &bytes, &bytes_len);
        if (bytes_len && libjade_load_nvs(bytes, bytes_len) == ESP_OK) {
            jade_process_reply_to_message_ok_ex(ctx);
            return;
        }
    }

cleanup:
    uint8_t buf[JADE_MSG_REPLY_LEN];
    jade_process_reject_message_ex(ctx, CBOR_RPC_BAD_PARAMETERS, "Unhandled error", NULL, 0, buf, sizeof(buf));
}
