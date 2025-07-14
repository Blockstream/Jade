#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../gui.h"
#include "../jade_assert.h"
#include "../jade_tasks.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../power.h"
#include "../process.h"
#include "../serial.h"
#include "../ui.h"
#include "../utils/malloc_ext.h"
#include "../utils/network.h"
#include "usbhmsc.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <wally_psbt.h>

gui_activity_t* make_usb_connect_activity(const char* title);
void await_qr_help_activity(const char* url);

// PSBT serialisation functions
bool deserialise_psbt(const uint8_t* bytes, size_t bytes_len, struct wally_psbt** psbt_out);
bool serialise_psbt(const struct wally_psbt* psbt, uint8_t** output, size_t* output_len);
network_t network_from_psbt_type(struct wally_psbt* psbt);
int sign_psbt(
    jade_process_t* process, CborValue* params, network_t network_id, struct wally_psbt* psbt, const char** errmsg);

// xpub helpers
script_variant_t xpub_script_variant_from_flags(uint32_t qr_flags);
bool handle_xpub_options(uint32_t* qr_flags, bool for_descriptor);

#define MAX_FILENAME_SIZE 256
#define MAX_FILE_ENTRIES 64

#define MIN_PSBT_FILE_SIZE 32
#define MAX_PSBT_FILE_SIZE MAX_INPUT_MSG_SIZE

static const char FW_SUFFIX[] = "_fw.bin";
static const char HASH_SUFFIX[] = ".hash";

static const char PSBT_SUFFIX[] = ".psbt";
static const char SIGNED_PSBT_SUFFIX[] = "_signed.psbt";

#define STR_ENDSWITH(str, str_len, suffix, suffix_len)                                                                 \
    (str && str_len > suffix_len && str[str_len] == '\0' && !memcmp(str + str_len - suffix_len, suffix, suffix_len))

// Function predicate to filter filenames available for a particular action
typedef bool (*filename_filter_fn_t)(const char* path, const char* filename, const size_t filename_len);

// Context object passed through to action callbacks
typedef struct {
    const char* extra_path;
    void* ctx;
} usbstorage_action_context_t;

// Function/action to call on a usb-storage directory
typedef bool (*usbstorage_action_fn_t)(const usbstorage_action_context_t* ctx);

static bool file_exists(const char* file_path)
{
    JADE_ASSERT(file_path);

    struct stat buffer;
    return !stat(file_path, &buffer);
}

static size_t get_file_size(const char* filename)
{
    JADE_ASSERT(filename);

    struct stat st;
    return !stat(filename, &st) ? st.st_size : 0;
}

static size_t read_file_to_buffer(const char* filename, uint8_t* buffer, size_t buf_len)
{
    JADE_ASSERT(filename);
    JADE_ASSERT(buffer);
    JADE_ASSERT(buf_len);

    const size_t file_size = get_file_size(filename);
    JADE_ASSERT(buf_len >= file_size);

    FILE* const fp = fopen(filename, "rb");
    if (!fp) {
        return 0;
    }

    size_t bytes_read = 0;
    while (bytes_read < file_size) {
        bytes_read += fread(buffer + bytes_read, 1, buf_len - bytes_read, fp);
    }
    fclose(fp);

    return bytes_read;
}

static size_t write_buffer_to_file(const char* filename, const uint8_t* buffer, size_t buf_len)
{
    JADE_ASSERT(filename);
    JADE_ASSERT(buffer);
    JADE_ASSERT(buf_len);

    FILE* const fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }

    size_t bytes_written = 0;
    while (bytes_written < buf_len) {
        bytes_written += fwrite(buffer + bytes_written, 1, buf_len - bytes_written, fp);
    }
    fclose(fp);

    return bytes_written;
}

// Display list of files, and return if user selects one
// Must be passed predicate to filter filenames
// NOTE: 'extra_path' (input) is relative to the mount point, but 'filename' (output) will be the full path including
// the path to the mount point.  eg. path: "/fws" -> filename: "/usb/fws/1.0.31-beta2_ble_1356784_fw.bin"
static bool select_file_from_filtered_list(const char* title, const char* const extra_path, filename_filter_fn_t filter,
    char* filename, const size_t filename_len)
{
    JADE_ASSERT(title);
    // extra_path is optional
    JADE_ASSERT(filter);
    JADE_ASSERT(filename);
    JADE_ASSERT(filename_len == MAX_FILENAME_SIZE);

    char path[MAX_FILENAME_SIZE];
    int ret = snprintf(path, sizeof(path), "%s%s", USBSTORAGE_MOUNT_POINT, extra_path ? extra_path : "");
    JADE_ASSERT(ret > 0 && ret < sizeof(path));
    const size_t path_len = strlen(path);

    DIR* const dir = opendir(path);
    if (!dir) {
        const char* message[] = { "Error opening USB storage" };
        await_message_activity(message, 1);
        return false;
    }

    char* filenames[MAX_FILE_ENTRIES] = {};
    size_t num_files = 0;

    while (num_files < MAX_FILE_ENTRIES) {
        errno = 0;
        const struct dirent* const entry = readdir(dir);
        if (errno || !entry) {
            break;
        }

        // DT_REG: regular file
        if (entry->d_type == DT_REG) {
            JADE_ASSERT(entry->d_name);
            const size_t d_name_len = strlen(entry->d_name);
            if (path_len + 1 + d_name_len + 1 > MAX_FILENAME_SIZE) {
                // We don't support overlong filenames - skip
                continue;
            }

            // Skip files where the name begins with a '.'
            if (entry->d_name[0] == '.') {
                // Treat as a hidden file and do not show
                continue;
            }

            // Offer to filter function
            if (!filter(path, entry->d_name, d_name_len)) {
                // Does not pass filter - skip
                continue;
            }

            // Add to list of candidate files
            filenames[num_files] = strdup(entry->d_name);
            JADE_ASSERT(filenames[num_files]);
            ++num_files;
        }
    }

    if (closedir(dir)) {
        JADE_LOGE("Error closing directory");
    }

    if (!num_files) {
        // No candidate files
        const char* message[] = { "No matching files found" };
        await_message_activity(message, 1);
        return false;
    }

    // Display as carousel
    gui_view_node_t* label_item = NULL;
    gui_view_node_t* filename_item = NULL;
    gui_activity_t* const act = make_carousel_activity(title, &label_item, &filename_item);
    JADE_ASSERT(filename_item);
    JADE_ASSERT(label_item);

    uint8_t selected = 0;
    gui_update_text(filename_item, filenames[selected]);
    gui_set_current_activity(act);
    int32_t ev_id;

    char label[32];
    const size_t limit = num_files + 1;
    bool done = false;
    while (!done) {
        JADE_ASSERT(selected <= num_files);
        if (selected < num_files) {
            // File item
            ret = snprintf(label, sizeof(label), "Candidate file %u/%u :", selected + 1, num_files);
            JADE_ASSERT(ret > 0 && ret < sizeof(label));
            gui_update_text(label_item, label);
            gui_update_text(filename_item, filenames[selected]);
        } else {
            // 'Cancel' sentinel
            gui_update_text(label_item, "");
            gui_update_text(filename_item, "[Cancel]");
        }

        if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            switch (ev_id) {
            case GUI_WHEEL_LEFT_EVENT:
                selected = (selected + limit - 1) % limit;
                break;

            case GUI_WHEEL_RIGHT_EVENT:
                selected = (selected + 1) % limit;
                break;

            default:
                if (ev_id == gui_get_click_event()) {
                    done = true;
                    break;
                }
            }

            if (ev_id == BTN_SETTINGS_USBSTORAGE_HELP) {
                await_qr_help_activity("blkstrm.com/jadeusbstorage");
                gui_set_current_activity(act);
            }
        }
    }

    if (selected < num_files) {
        // Copy the selected filename (including fullpath) to output
        JADE_ASSERT(filenames[selected]);
        ret = snprintf(filename, filename_len, "%s/%s", path, filenames[selected]);
        JADE_ASSERT(ret > 0 && ret < filename_len);
    } else {
        done = false; // ie. cancelled, no filename copied
    }

    // Free the duplicated filename strings
    for (size_t i = 0; i < num_files; ++i) {
        free(filenames[i]);
    }

    return done;
}

// Generic handler to run usb storage actions
static bool handle_usbstorage_action(const char* title, usbstorage_action_fn_t usbstorage_action,
    const usbstorage_action_context_t* ctx, const bool async_action)
{
    JADE_ASSERT(title);
    JADE_ASSERT(usbstorage_action);
    JADE_ASSERT(ctx);

    while (usb_is_powered()) {
        const char* message[] = { "Disconnect USB power and", "connect a storage device" };
        if (!await_continueback_activity(title, message, 2, true, "blkstrm.com/jadeusbstorage")) {
            return false;
        }
    }

    // Stop normal serial usb and start usbstorage
    display_processing_message_activity();
    serial_stop();

    EventGroupHandle_t usbstorage_handle = usbstorage_start();
    if (!usbstorage_handle) {
        JADE_LOGE("Failed to start USB storage!");
        const char* message[] = { "Failed to start", "usb storage!" };
        await_error_activity(message, 2);
        // Jade may require restart to use usb storage or serial at this point ...
        return false;
    }

    // We should only do this if within 0.4 seconds or so we don't detect a usb device already plugged

    // Now wait for either the state to change or for back button on the activity
    gui_activity_t* const prior_activity = gui_current_activity();
    gui_activity_t* act_prompt = NULL;
    int counter = 0;
    bool action_initiated = false;
    EventBits_t usbstorage_events;

    while (true) {
        // Fetch the current state set by handle_usbstorage_event()
        usbstorage_events = xEventGroupWaitBits(
            usbstorage_handle, USBSTORAGE_AVAILABLE | USBSTORAGE_ERROR, pdFALSE, pdFALSE, 100 / portTICK_PERIOD_MS);

        if (usbstorage_events & USBSTORAGE_ERROR) {
            // Error accessing USB storage: Show error and exit
            const char* message[] = { "Error accessing usb", "storage. Note: only", "FAT32 is supported." };
            await_error_activity(message, 3);
            break;
        } else if (usbstorage_events == USBSTORAGE_AVAILABLE) {
            // USB storage is mounted: run the action
            if (act_prompt) {
                gui_set_current_activity(prior_activity);
            }
            JADE_LOGI("starting usbstorage_action");
            action_initiated = usbstorage_action(ctx);
            break;
        }
        // At this point, USB storage is not yet mounted

        if (!act_prompt) {
            if (++counter < 50) {
                // Wait up to 50x100 ms = ~5s before prompting user
                vTaskDelay(100 / portTICK_PERIOD_MS);
                continue;
            }

            // Prompt user to connect USB storage
            act_prompt = make_usb_connect_activity(title);
            gui_set_current_activity(act_prompt);
        }

        if (act_prompt) {
            // Handle any events from connect USB storage screen
            int32_t ev_id;
            if (gui_activity_wait_event(
                    act_prompt, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 100 / portTICK_PERIOD_MS)) {

                if (ev_id == BTN_SETTINGS_USBSTORAGE_BACK) {
                    // when the user goes back we go through here
                    // then the device hasn't started any action, but has disk detected
                    break;
                }
                if (ev_id == BTN_SETTINGS_USBSTORAGE_HELP) {
                    await_qr_help_activity("blkstrm.com/jadeusbstorage");
                    gui_set_current_activity(act_prompt);
                }
            }
        }
    }

    // If the action was not an async action (ie. it has already completed) or
    // the action was never properly started, we stop/unmount usbstorage now.
    if (!async_action || !action_initiated) {
        JADE_LOGI("stopping usb");
        usbstorage_stop();
        serial_start();
    }

    return action_initiated;
}

// OTA

static void prepare_common_msg(CborEncoder* root_map_encoder, CborEncoder* root_encoder, const jade_msg_source_t source,
    const char* method, uint8_t* buffer, const size_t buffer_len, const bool has_params, const int msg_id)
{
    JADE_ASSERT(root_map_encoder);
    JADE_ASSERT(root_encoder);
    JADE_ASSERT(method);
    JADE_ASSERT(buffer);
    JADE_ASSERT(buffer_len);

    cbor_encoder_init(root_encoder, buffer, buffer_len, 0);
    const CborError cberr = cbor_encoder_create_map(root_encoder, root_map_encoder, has_params ? 3 : 2);
    JADE_ASSERT(cberr == CborNoError);

    {
        char buf[8];
        int rc = snprintf(buf, sizeof(buf), "%d", msg_id);
        JADE_ASSERT(rc > 0 && rc < sizeof(buf));
        add_string_to_map(root_map_encoder, "id", buf);
    }
    add_string_to_map(root_map_encoder, "method", method);
}

static bool post_ota_message(const jade_msg_source_t source, const size_t fwsize, const size_t cmpsize,
    const uint8_t* hash, const size_t hash_len)
{
    JADE_ASSERT(hash);
    JADE_ASSERT(hash_len == SHA256_LEN);

    CborEncoder root_encoder;
    CborEncoder root_map_encoder;

    uint8_t buf[256]; // sufficient
    uint8_t* cbor_buf = buf + 1;
    const bool has_params = true;
    prepare_common_msg(&root_map_encoder, &root_encoder, source, "ota", cbor_buf, sizeof(buf) - 1, has_params, 0);

    CborError cberr = cbor_encode_text_stringz(&root_map_encoder, "params");
    JADE_ASSERT(cberr == CborNoError);

    CborEncoder params_encoder; // fwsize/cmpsize/fwhash
    cberr = cbor_encoder_create_map(&root_map_encoder, &params_encoder, 3);
    JADE_ASSERT(cberr == CborNoError);
    add_uint_to_map(&params_encoder, "fwsize", fwsize);
    add_uint_to_map(&params_encoder, "cmpsize", cmpsize);
    add_bytes_to_map(&params_encoder, "fwhash", hash, hash_len);

    cberr = cbor_encoder_close_container(&root_map_encoder, &params_encoder);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    buf[0] = source;
    const size_t cbor_len = cbor_encoder_get_buffer_size(&root_encoder, cbor_buf);
    JADE_ASSERT(cbor_len + 1 <= sizeof(buf));

    return jade_process_push_in_message(buf, cbor_len + 1);
}

static bool post_ota_data_message(const jade_msg_source_t source, uint8_t* data, size_t data_len, const int msg_id)
{
    JADE_ASSERT(data);
    JADE_ASSERT(data_len);

    uint8_t buf[JADE_OTA_BUF_SIZE + 128]; // sufficient
    uint8_t* cbor_buf = buf + 1;
    CborEncoder root_encoder;
    CborEncoder root_map_encoder;

    const bool has_params = true;
    prepare_common_msg(
        &root_map_encoder, &root_encoder, source, "ota_data", cbor_buf, sizeof(buf) - 1, has_params, msg_id);
    add_bytes_to_map(&root_map_encoder, "params", data, data_len);

    const CborError cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    buf[0] = source;
    const size_t cbor_len = cbor_encoder_get_buffer_size(&root_encoder, cbor_buf);
    JADE_ASSERT(cbor_len + 1 <= sizeof(buf));
    return jade_process_push_in_message(buf, cbor_len + 1);
}

static bool post_ota_complete_message(const jade_msg_source_t source)
{
    uint8_t buf[64]; // sufficient
    uint8_t* cbor_buf = buf + 1;
    CborEncoder root_encoder;
    CborEncoder root_map_encoder; // id, method
    const bool has_params = false;
    prepare_common_msg(
        &root_map_encoder, &root_encoder, source, "ota_complete", cbor_buf, sizeof(buf) - 1, has_params, 0);
    const CborError cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    buf[0] = source;
    const size_t cbor_len = cbor_encoder_get_buffer_size(&root_encoder, cbor_buf);
    JADE_ASSERT(cbor_len + 1 <= sizeof(buf));
    return jade_process_push_in_message(buf, cbor_len + 1);
}

#define MAX_FW_SIZE_DIGITS 7

static size_t read_fwsize(const char* str)
{
    JADE_ASSERT(str);

    const char* last_underscore = strrchr(str, '_');
    if (!last_underscore || *(last_underscore + 1) == '\0') {
        return 0;
    }

    const char* second_last_underscore = last_underscore - 1;
    while (second_last_underscore >= str) {
        if (*second_last_underscore == '_') {
            break;
        }
        --second_last_underscore;
    }

    if (second_last_underscore < str) {
        return 0;
    }

    const char* start = second_last_underscore + 1;
    const char* end = last_underscore;
    if (end == start || (end - start) > MAX_FW_SIZE_DIGITS) {
        return 0;
    }

    char temp[MAX_FW_SIZE_DIGITS + 1]; // Maximum digits plus null terminator
    strncpy(temp, start, end - start);
    temp[end - start] = '\0';

    return strtoul(temp, NULL, 10);
}

static bool read_hash_file_to_buffer(const char* filename, uint8_t* buffer, size_t buf_size)
{
    JADE_ASSERT(filename);
    JADE_ASSERT(buffer);
    JADE_ASSERT(buf_size == SHA256_LEN);

    char hash_hex[SHA256_LEN * 2];
    struct stat st;
    if (stat(filename, &st) != 0 || st.st_size != 64) {
        return false;
    }

    const size_t bytes_read = read_file_to_buffer(filename, (uint8_t*)hash_hex, sizeof(hash_hex));
    if (bytes_read != 64) {
        return false;
    }

    size_t written = 0;
    const int wally_res = wally_hex_n_to_bytes(hash_hex, sizeof(hash_hex), buffer, buf_size, &written);
    JADE_ASSERT(written == SHA256_LEN);
    JADE_ASSERT(wally_res == WALLY_OK);
    return true;
}

static bool handle_ota_reply(const uint8_t* msg, const size_t len, void* ctx)
{
    JADE_ASSERT(msg);
    JADE_ASSERT(len);
    JADE_ASSERT(ctx);

    bool* const ok = (bool*)ctx;
    *ok = false;

    CborParser parser;
    CborValue message;
    const CborError cberr = cbor_parser_init(msg, len, CborValidateBasic, &parser, &message);
    if (cberr != CborNoError || !rpc_message_valid(&message)) {
        JADE_LOGE("Invalid cbor message");
    } else {
        rpc_get_boolean("result", &message, ok);
    }

    // We return true in all cases to indicate that a message was received
    // and we should stop waiting - whether the message was processed 'successfully'
    // is indicated by the 'ok' flag in the passed context object.
    return true;
}

static bool wait_for_ota_replies(size_t num_replies, const bool wait_forever, bool* is_ok)
{
    JADE_ASSERT(is_ok);
    bool any_failed = false;
    *is_ok = false;
    for (size_t i = 0; i < num_replies; ++i) {
        // Wait for a reply message from the OTA process
        int num_waits = 0;
        while (!jade_process_get_out_message(handle_ota_reply, SOURCE_INTERNAL, is_ok)) {
            // No reply yet: Keep waiting for our message to be processed.
            // Wait forever while waiting for user confirmation, and 10
            // seconds once data has begun being transferred.
            // Note jade_process_get_out_message() waits up to 20ms for messages.
            const int max_waits = 10000 / 20;
            if (!wait_forever && ++num_waits > max_waits) {
                JADE_LOGE("wait_for_ota_replies timeout");
                return false; // Timed out waiting
            }
        }
        any_failed |= !*is_ok;
    }
    if (any_failed) {
        *is_ok = false;
    }
    JADE_LOGD("wait_for_ota_replies: %d replies, OK=%d", (int)num_replies, *is_ok ? 1 : 0);
    return true; // Successfully waited for all messages
}

struct usbmode_ota_worker_data {
    char* file_to_flash;
    size_t data_to_send;
};

static void usbmode_ota_worker(void* ctx)
{
    struct usbmode_ota_worker_data* ctx_data = (struct usbmode_ota_worker_data*)ctx;
    JADE_ASSERT(ctx_data && ctx_data->file_to_flash && ctx_data->data_to_send != 0);

    uint8_t buffer[JADE_OTA_BUF_SIZE];
    int msgs_sent = 1; // Initially just an "ota" message sent
    int msgs_waited = 0;
    const int fd = open(ctx_data->file_to_flash, O_RDONLY, 0);
    free(ctx_data->file_to_flash);
    ctx_data->file_to_flash = NULL;

    // Loop passing our ota data to the ota task
    bool failed_wait = false;
    while (ctx_data->data_to_send) {
        if (msgs_sent > 1) {
            // Wait for the n-1th message that we sent. This allows this task to stay
            // ahead of the ota task so that both can work in parallel.
            const bool wait_forever = msgs_sent <= 4;
            bool ok = false;
            failed_wait = !wait_for_ota_replies(1, wait_forever, &ok);
            if (failed_wait) {
                // Failed to get a reply: The ota task is dead/not responding
                break;
            }
            ++msgs_waited;
            if (!ok) {
                // Either: the user rejected the ota (msgs_waited == 1), or
                // one of our data packets was invalid and the ota failed.
                break;
            }
        }

        // Read, encode and send a chunk of data to the ota task
        const ssize_t bytes_read = fd < 0 ? 0 : read(fd, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            // Failed to read from the USB storage file.
            // e.g. the device was unplugged or is unreliable.
            break;
        }
        const bool res = post_ota_data_message(SOURCE_INTERNAL, buffer, bytes_read, msgs_sent);
        JADE_ASSERT(res);
        JADE_LOGD("posted ota_data message %d", msgs_sent);
        ++msgs_sent;
        ctx_data->data_to_send -= bytes_read;
    }

    if (fd >= 0) {
        close(fd);
    }

    /* const bool all_data_sent = ctx_data->data_to_send == 0; */
    free(ctx_data);

    if (!failed_wait) {
        // Either all data was sent or an error occurred. Send "ota_complete"
        // for both cases.
        // TODO: add support for "ota_cancel" for the failure case.
        post_ota_complete_message(SOURCE_INTERNAL);
        ++msgs_sent;
        bool ok = false;
        // Wait for any outstanding ota replies
        const bool wait_forever = false;
        failed_wait = !wait_for_ota_replies(msgs_sent - msgs_waited, wait_forever, &ok);
    }

    // If the ota succeeded the device will be rebooted soon.
    // If the ota failed, the user can try again, unless we failed to
    // wait in which case the main task is probably stuck and the device
    // will need to be rebooted.
    // TODO: Notify the user in the failed_wait == true case.

    // After ota try to unmount usbstorage and restart normal serial comms
    JADE_LOGI("OTA complete: stopping usb");
    usbstorage_stop();
    serial_start();
    vTaskDelete(NULL);
}

static void start_usb_ota_task(char* str, size_t fwsize, size_t cmpsize, uint8_t* hash, const size_t hash_len)
{
    JADE_ASSERT(str);
    JADE_ASSERT(fwsize);
    JADE_ASSERT(cmpsize);
    JADE_ASSERT(hash);
    JADE_ASSERT(hash_len == SHA256_LEN);

    const bool res = post_ota_message(SOURCE_INTERNAL, fwsize, cmpsize, hash, hash_len);
    JADE_ASSERT(res);

    // FIXME: check stack size better
    char* copy = strdup(str);
    JADE_ASSERT(copy);
    struct usbmode_ota_worker_data* ctx_data = JADE_MALLOC(sizeof(struct usbmode_ota_worker_data));
    JADE_ASSERT(ctx_data);

    ctx_data->file_to_flash = copy;
    ctx_data->data_to_send = cmpsize;

    const BaseType_t retval = xTaskCreatePinnedToCore(
        usbmode_ota_worker, "usb_ota_task", 10 * 1024, ctx_data, JADE_TASK_PRIO_USB, NULL, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(retval == pdPASS, "Failed to create usb_ota_task, xTaskCreatePinnedToCore() returned %d", retval);
}

static bool is_full_fw_file(const char* path, const char* filename, const size_t filename_len)
{
    // Must look like a fw file (name)
    if (!STR_ENDSWITH(filename, filename_len, FW_SUFFIX, strlen(FW_SUFFIX))) {
        return false;
    }

    // Must have corresponding hash file
    char hash_filename[MAX_FILENAME_SIZE];
    if (strlen(path) + 1 + filename_len + strlen(HASH_SUFFIX) + 1 > sizeof(hash_filename)) {
        return false;
    }
    const int ret = snprintf(hash_filename, sizeof(hash_filename), "%s/%s%s", path, filename, HASH_SUFFIX);
    JADE_ASSERT(ret > 0 && ret < sizeof(hash_filename));

    return file_exists(hash_filename);
}

static bool initiate_usb_ota(const usbstorage_action_context_t* ctx)
{
    JADE_ASSERT(ctx);

    // extra_path is optional
    JADE_ASSERT(!ctx->ctx);

    char filename[MAX_FILENAME_SIZE];
    if (!select_file_from_filtered_list(
            "Select Firmware", ctx->extra_path, is_full_fw_file, filename, sizeof(filename))) {
        // User abandoned
        return false;
    }

    uint8_t hash[SHA256_LEN];
    {
        char hash_filename[MAX_FILENAME_SIZE];
        const int ret = snprintf(hash_filename, sizeof(hash_filename), "%s%s", filename, HASH_SUFFIX);
        JADE_ASSERT(ret > 0 && ret < sizeof(hash_filename));

        if (!read_hash_file_to_buffer(hash_filename, hash, sizeof(hash))) {
            const char* message[] = { "Failed to read", "hash file" };
            await_error_activity(message, 2);
            return false;
        }
    }

    const size_t cmpsize = get_file_size(filename);
    const size_t fwsize = read_fwsize(filename);
    if (!cmpsize || !fwsize) {
        const char* message[] = { "Failed to parse", "firmware filename" };
        await_error_activity(message, 2);
        return false;
    }

    start_usb_ota_task(filename, fwsize, cmpsize, hash, sizeof(hash));
    return true;
}

// Initiate an OTA fw upgrade from compressed fw and hash file
// NOTE: this function starts a separate task to read the file and provide the fw chunks.
// It must return and pass control back to the main dispatcher loop to process the OTA.
bool usbstorage_firmware_ota(const char* extra_path)
{
    // extra_path is optional
    const bool is_async = true;
    const usbstorage_action_context_t ctx = { .extra_path = extra_path };
    return handle_usbstorage_action("Firmware Upgrade", initiate_usb_ota, &ctx, is_async);
}

// Sign PSBT

static bool is_psbt_file(const char* path, const char* filename, const size_t filename_len)
{
    return STR_ENDSWITH(filename, filename_len, PSBT_SUFFIX, strlen(PSBT_SUFFIX));
}

static bool sign_usb_psbt(const usbstorage_action_context_t* ctx)
{
    JADE_ASSERT(ctx);

    // extra_path is optional
    JADE_ASSERT(!ctx->ctx);

    char filename[MAX_FILENAME_SIZE];
    if (!select_file_from_filtered_list("Select PSBT", ctx->extra_path, is_psbt_file, filename, sizeof(filename))) {
        return false;
    }

    // Sanity check file size
    size_t psbt_len = get_file_size(filename);
    if (psbt_len < MIN_PSBT_FILE_SIZE) {
        const char* message[] = { "Invalid PSBT file" };
        await_error_activity(message, 1);
        return false;
    }
    if (psbt_len > MAX_PSBT_FILE_SIZE) {
        const char* message[] = { "PSBT file too large" };
        await_error_activity(message, 1);
        return false;
    }

    bool retval = false;
    struct wally_psbt* psbt = NULL;
    const size_t filename_len = strlen(filename);

    bool b64 = false;
    uint8_t* psbt_bytes = JADE_MALLOC_PREFER_SPIRAM(psbt_len);

    // Try to read as binary psbt first
    const size_t bytes_read = read_file_to_buffer(filename, psbt_bytes, psbt_len);
    JADE_ASSERT(bytes_read == psbt_len);
    if (!deserialise_psbt(psbt_bytes, psbt_len, &psbt) || !psbt) {
        // Failed ...
        // Try to interpret as base64 text file

        // Reduce length if file includes trailing whitespace
        while (psbt_len && isspace(psbt_bytes[psbt_len - 1])) {
            --psbt_len;
        }

        size_t written = 0;
        char* const psbt64 = (char*)psbt_bytes;
        psbt_bytes = JADE_MALLOC_PREFER_SPIRAM(psbt_len); // sufficient
        const int wret = wally_base64_n_to_bytes(psbt64, psbt_len, 0, psbt_bytes, psbt_len, &written);
        free(psbt64);

        if (wret != WALLY_OK || !written || written > psbt_len) {
            const char* message[] = { "Failed to load PSBT" };
            await_error_activity(message, 1);
            goto cleanup;
        }
        psbt_len = written;
        b64 = true;

        // Deserialise bytes
        if (!deserialise_psbt(psbt_bytes, psbt_len, &psbt) || !psbt) {
            const char* message[] = { "Failed to load PSBT" };
            await_error_activity(message, 1);
            goto cleanup;
        }
    }

    // Free bytes loaded from file
    free(psbt_bytes);
    psbt_bytes = NULL;
    psbt_len = 0;

    // Sign PSBT
    const char* errmsg = NULL;
    const network_t network_id = network_from_psbt_type(psbt);

    // Note we pass NULL process/params as we don't have any additional info
    const int errcode = sign_psbt(NULL, NULL, network_id, psbt, &errmsg);
    if (errcode) {
        if (errcode != CBOR_RPC_USER_CANCELLED) {
            const char* message[] = { errmsg };
            await_error_activity(message, 1);
        }
        goto cleanup;
    }

    // Write to file
    // Create a new file if name not too long.  If new name would be too long, overwrite existing file.
    char output_filename[MAX_FILENAME_SIZE];
    if (filename_len - strlen(PSBT_SUFFIX) + strlen(SIGNED_PSBT_SUFFIX) + 1 > MAX_FILENAME_SIZE) {
        const char* message[] = { "Warning: Long filename", "Overwriting existing", "psbt file" };
        await_error_activity(message, 3);
        strcpy(output_filename, filename);
    } else {
        const int ret = snprintf(output_filename, sizeof(output_filename), "%.*s%s", filename_len - strlen(PSBT_SUFFIX),
            filename, SIGNED_PSBT_SUFFIX);
        JADE_ASSERT(ret > 0 && ret < sizeof(output_filename));
    }

    if (b64) {
        // Encode to base64
        char* psbt64 = NULL;
        if (wally_psbt_to_base64(psbt, 0, &psbt64) != WALLY_OK || !psbt64) {
            const char* message[] = { "Failed to", "serialise PSBT" };
            await_error_activity(message, 2);
            goto cleanup;
        }
        const size_t psbt64_len = strlen(psbt64);
        const size_t written = write_buffer_to_file(output_filename, (const uint8_t*)psbt64, psbt64_len);
        JADE_WALLY_VERIFY(wally_free_string(psbt64));
        JADE_ASSERT(written == psbt64_len);
    } else {
        // Serialise signed PSBT to bytes
        if (!serialise_psbt(psbt, &psbt_bytes, &psbt_len)) {
            const char* message[] = { "Failed to", "serialise PSBT" };
            await_error_activity(message, 2);
            goto cleanup;
        }
        const size_t written = write_buffer_to_file(output_filename, psbt_bytes, psbt_len);
        JADE_ASSERT(written == psbt_len);
    }

    const size_t mount_point_len = strlen(USBSTORAGE_MOUNT_POINT);
    JADE_ASSERT(strlen(output_filename) > mount_point_len);
    JADE_ASSERT(!memcmp(output_filename, USBSTORAGE_MOUNT_POINT, mount_point_len));
    const char* message[] = { "PSBT file saved:", output_filename + mount_point_len + 1 };
    await_error_activity(message, 2);
    retval = true;

cleanup:
    JADE_WALLY_VERIFY(wally_psbt_free(psbt));
    free(psbt_bytes);

    return retval;
}

// Sign PSBT file, and write updated file back to the usb-storage directory.
// Accepts binary PSBT or base64-encoded PSBT file as 'xxx.psbt'.
// After any signatures are added, the file is written in the same format.
bool usbstorage_sign_psbt(const char* extra_path)
{
    // extra_path is optional
    const bool is_async = false;
    const usbstorage_action_context_t ctx = { .extra_path = extra_path };
    return handle_usbstorage_action("Sign PSBT", sign_usb_psbt, &ctx, is_async);
}

static gui_activity_t* make_export_xpub_prompt_activity(void)
{
    const char* message[] = { "Save wallet Xpub to", "connected storage?" };

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_EXPORT_XPUB_BACK },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t ftrbtns[] = { { .txt = "Options",
                                 .font = GUI_DEFAULT_FONT,
                                 .ev_id = BTN_SETTINGS_USBSTORAGE_EXPORT_XPUB_OPTIONS,
                                 .borders = GUI_BORDER_TOPRIGHT },
        { .txt = "Export",
            .font = GUI_DEFAULT_FONT,
            .ev_id = BTN_SETTINGS_USBSTORAGE_EXPORT_XPUB_ACTION,
            .borders = GUI_BORDER_TOPLEFT } };
    return make_show_message_activity(message, 2, "Export Xpub", hdrbtns, 2, ftrbtns, 2);
}

static bool export_usb_xpub_fn(const usbstorage_action_context_t* ctx)
{
    uint32_t qr_flags = storage_get_qr_flags();
    qr_flags &= ~QR_XPUB_MULTISIG; // Disallow multisig

    gui_activity_t* act = make_export_xpub_prompt_activity();
    gui_set_current_activity(act);

    while (true) {
        const int32_t ev_id = gui_activity_wait_button(act, BTN_EVENT_TIMEOUT);

        if (ev_id == BTN_SETTINGS_USBSTORAGE_EXPORT_XPUB_OPTIONS) {
            const bool for_descriptor = true;
            handle_xpub_options(&qr_flags, for_descriptor);
            gui_set_current_activity(act);
        } else if (ev_id == BTN_SETTINGS_USBSTORAGE_EXPORT_XPUB_ACTION) {
            break; // Fall through to perform the export
        } else if (ev_id == BTN_SETTINGS_EXPORT_XPUB_BACK) {
            return true;
        } else if (ev_id != BTN_EVENT_TIMEOUT) {
            return false;
        }
    }

    JADE_ASSERT(!(qr_flags & QR_XPUB_MULTISIG));
    char descriptor[512], *p = descriptor; // sufficient
    const script_variant_t script_variant = xpub_script_variant_from_flags(qr_flags);
    bool is_wrapped = false;

    // Descriptor type
    switch (script_variant) {
    case P2PKH:
        memcpy(p, "pkh([", sizeof("pkh(["));
        p += sizeof("pkh([") - 1;
        break;
    case P2WPKH_P2SH:
        memcpy(p, "sh(", sizeof("sh("));
        p += sizeof("sh(") - 1;
        is_wrapped = true;
        goto p2wpkh;
        break;
    case P2WPKH:
    p2wpkh:
        memcpy(p, "wpkh([", sizeof("wpkh(["));
        p += sizeof("wpkh([") - 1;
        break;
    case P2TR:
        memcpy(p, "tr([", sizeof("tr(["));
        p += sizeof("tr([") - 1;
        break;
    default:
        JADE_ASSERT(false);
    }

    // Fingerprint
    {
        uint8_t user_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
        wallet_get_fingerprint(user_fingerprint, sizeof(user_fingerprint));
        char* fphex = NULL;
        JADE_WALLY_VERIFY(wally_hex_from_bytes(user_fingerprint, sizeof(user_fingerprint), &fphex));
        JADE_ASSERT(fphex && strlen(fphex) == BIP32_KEY_FINGERPRINT_LEN * 2);
        memcpy(p, fphex, BIP32_KEY_FINGERPRINT_LEN * 2);
        wally_free_string(fphex);
        p += BIP32_KEY_FINGERPRINT_LEN * 2;
        *p++ = '/';
        *p = '\0';
    }

    // Path
    const uint16_t account_index = qr_flags >> ACCOUNT_INDEX_FLAGS_SHIFT;
    uint32_t path[EXPORT_XPUB_PATH_LEN];
    size_t path_len = 0;
    wallet_get_default_xpub_export_path(script_variant, account_index, path, EXPORT_XPUB_PATH_LEN, &path_len);
    const bool path_only = true;
    const size_t remaining_len = sizeof(descriptor) - (p - descriptor);
    const bool ret = wallet_bip32_path_as_str(path, path_len, p, remaining_len, path_only);
    JADE_ASSERT(ret);
    p += strlen(p);
    *p++ = ']';
    *p = '\0';

    network_t network_id;
    if (keychain_get_network_type_restriction() == NETWORK_TYPE_TEST) {
        network_id = NETWORK_BITCOIN_TESTNET;
    } else {
        network_id = NETWORK_BITCOIN;
    }

    // xpub
    {
        char* xpub = NULL;
        if (!wallet_get_xpub(network_id, path, path_len, &xpub) || !xpub) {
            const char* msg[] = { "unable to get", "xpub from path" };
            await_error_activity(msg, 2);
            return false;
        }
        const size_t xpub_len = strlen(xpub);
        // Ensure enough space remains to close the descriptor and add checksum
        JADE_ASSERT(p + xpub_len < descriptor + (sizeof(descriptor) - 32));
        strncpy(p, xpub, xpub_len);
        p += xpub_len;
        wally_free_string(xpub);
        memcpy(p, "/0/*)", sizeof("/0/*)"));
        p += sizeof("/0/*)") - 1;
        if (is_wrapped) {
            *p++ = ')';
        }
        *p++ = '\0';
    }

    // Checksum
    const uint32_t flags = 16 << WALLY_MINISCRIPT_DEPTH_SHIFT;
    struct wally_descriptor* d = NULL;
    JADE_WALLY_VERIFY(wally_descriptor_parse(descriptor, NULL, network_id, flags, &d));
    JADE_ASSERT(d && d->src && d->src_len < sizeof(descriptor));
    // Use the canonical form with checksum from the parsed descriptor
    const size_t descriptor_len = d->src_len;
    memcpy(descriptor, d->src, descriptor_len);
    descriptor[descriptor_len] = '\0';
    JADE_WALLY_VERIFY(wally_descriptor_free(d));

    const size_t written
        = write_buffer_to_file(USBSTORAGE_MOUNT_POINT "/jade-xpub.txt", (const uint8_t*)descriptor, descriptor_len);

    if (written != descriptor_len) {
        const char* msg[] = { "Failed to save", "xpub file" };
        await_error_activity(msg, 2);
        return false;
    }

    const char* msg[] = { "xpub saved to", "jade-xpub.txt" };
    await_message_activity(msg, 2);
    return true;
}

bool usbstorage_export_xpub(const char* extra_path)
{
    const bool is_async = false;
    usbstorage_action_context_t ctx = { .extra_path = NULL, .ctx = NULL };
    return handle_usbstorage_action("Export Xpub", export_usb_xpub_fn, &ctx, is_async);
}

#endif // AMALGAMATED_BUILD
