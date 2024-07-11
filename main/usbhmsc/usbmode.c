#include "../button_events.h"
#include "../gui.h"
#include "../jade_assert.h"
#include "../jade_tasks.h"
#include "../process.h"
#include "../serial.h"
#include "../ui.h"
#include "../utils/malloc_ext.h"
#include "usbhmsc.h"
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static void prepare_common_msg(CborEncoder* root_map_encoder, CborEncoder* root_encoder, const jade_msg_source_t source,
    const char* method, uint8_t* buffer, size_t buffer_len, size_t items)
{
    cbor_encoder_init(root_encoder, buffer, buffer_len, 0);
    const CborError cberr = cbor_encoder_create_map(root_encoder, root_map_encoder, items);
    JADE_ASSERT(cberr == CborNoError);
    add_string_to_map(root_map_encoder, "id", "0");
    add_string_to_map(root_map_encoder, "method", method);
}

static bool post_ota_message(
    const jade_msg_source_t source, size_t fwsize, size_t cmpsize, uint8_t* hash, size_t size_hash)
{
    JADE_ASSERT(size_hash == SHA256_LEN);
    CborEncoder root_encoder;
    CborEncoder root_map_encoder;

    // FIXME: check max size required?
    uint8_t cbor_buf[512 + 128];
    prepare_common_msg(&root_map_encoder, &root_encoder, source, "ota", cbor_buf, sizeof(cbor_buf), 3);

    CborError cberr = cbor_encode_text_stringz(&root_map_encoder, "params");
    JADE_ASSERT(cberr == CborNoError);

    CborEncoder params_encoder; // fwsize/cmpsize/fwhash
    cberr = cbor_encoder_create_map(&root_map_encoder, &params_encoder, 3);
    JADE_ASSERT(cberr == CborNoError);
    add_uint_to_map(&params_encoder, "fwsize", fwsize);
    add_uint_to_map(&params_encoder, "cmpsize", cmpsize);
    add_bytes_to_map(&params_encoder, "fwhash", hash, size_hash);

    cberr = cbor_encoder_close_container(&root_map_encoder, &params_encoder);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    const size_t cbor_len = cbor_encoder_get_buffer_size(&root_encoder, cbor_buf);
    return jade_process_push_in_message_ex(cbor_buf, cbor_len, source);
}

static bool post_ota_data_message(const jade_msg_source_t source, uint8_t* data, size_t data_len)
{
    // FIXME: check max size required?
    uint8_t cbor_buf[4096 + 128];
    CborEncoder root_encoder;
    CborEncoder root_map_encoder;

    prepare_common_msg(&root_map_encoder, &root_encoder, source, "ota_data", cbor_buf, sizeof(cbor_buf), 3);
    add_bytes_to_map(&root_map_encoder, "params", data, data_len);

    const CborError cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    const size_t cbor_len = cbor_encoder_get_buffer_size(&root_encoder, cbor_buf);
    return jade_process_push_in_message_ex(cbor_buf, cbor_len, source);
}

static bool post_ota_complete_message(const jade_msg_source_t source)
{
    // FIXME: check max size required?
    uint8_t cbor_buf[64];
    CborEncoder root_encoder;
    CborEncoder root_map_encoder; // id, method
    prepare_common_msg(&root_map_encoder, &root_encoder, source, "ota_complete", cbor_buf, sizeof(cbor_buf), 2);
    const CborError cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    const size_t cbor_len = cbor_encoder_get_buffer_size(&root_encoder, cbor_buf);
    return jade_process_push_in_message_ex(cbor_buf, cbor_len, source);
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

static bool file_exists(const char* file_path)
{
    struct stat buffer;
    return !stat(file_path, &buffer);
}

static bool read_file_to_buffer(const char* filename, uint8_t* buffer, size_t buf_size)
{
    JADE_ASSERT(filename);
    JADE_ASSERT(buffer);
    JADE_ASSERT(buf_size == SHA256_LEN);

    char hash_hex[SHA256_LEN * 2];
    struct stat st;
    if (stat(filename, &st) != 0 || st.st_size != 64) {
        return false;
    }

    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) {
        return false;
    }

    size_t bytes_read = fread(hash_hex, 1, sizeof(hash_hex), fp);
    fclose(fp);

    if (bytes_read != 64) {
        return false;
    }

    size_t written = 0;
    const int wally_res = wally_hex_n_to_bytes(hash_hex, sizeof(hash_hex), buffer, buf_size, &written);
    JADE_ASSERT(written == SHA256_LEN);
    JADE_ASSERT(wally_res == WALLY_OK);
    return true;
}

static size_t get_file_size(const char* filename)
{
    struct stat st;
    if (!stat(filename, &st)) {
        return st.st_size;
    }
    return 0;
}

#define MAX_FILENAME_SIZE 256

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
        goto cleanup;
    }

    bool bool_result = false;
    if (!rpc_get_boolean("result", &message, &bool_result)) {
        goto cleanup;
    }

    *ok = bool_result;

cleanup:
    // We return true in all cases to indicate that a message was received
    // and we should stop waiting - whether the message was processed 'successfully'
    // is indicated by the 'ok' flag in the passed context object.
    return true;
}

struct usb_worker_data {
    char* file_to_flash;
    size_t data_to_send;
};

static void usbmode_worker(void* ctx)
{
    JADE_ASSERT(ctx);
    struct usb_worker_data* ctx_data = (struct usb_worker_data*)ctx;
    JADE_ASSERT(ctx_data->file_to_flash);

    uint8_t buffer[4096];

    FILE* fp = fopen(ctx_data->file_to_flash, "rb");
    if (fp == NULL) {
        // FIXME: handle better? this happens if the user unplugged the device for example
        free(ctx_data->file_to_flash);
        vTaskDelete(NULL);
        return;
    }

    // first we send data packets and for each we wait for an ok
    bool ok;
    while (ctx_data->data_to_send) {
        ok = false;
        while (!jade_process_get_out_message(handle_ota_reply, SOURCE_INTERNAL, &ok)) {
            // Await outbound message
        }

        if (!ok) {
            /* user rejected the firmware most likely */
            break;
        }

        const size_t written = fread(buffer, 1, sizeof(buffer), fp);
        if (!written) {
            // This happens if the user unplugs the device in the middle of ota
            // at the moment we fail gracefully but we need to send another ota message for things to get unstuck on the
            // firmware side of things sending an ota complete should do the job
            // FIXME: instead create an ota_cancel msg and send that (and add support to ota for that)
            post_ota_complete_message(SOURCE_INTERNAL);
            // then we wait for the reply back
            ok = false;
            while (!jade_process_get_out_message(handle_ota_reply, SOURCE_INTERNAL, &ok)) {
                // Await outbound message
            }
            break;
        }
        const bool res = post_ota_data_message(SOURCE_INTERNAL, buffer, written);
        JADE_ASSERT(res);
        ctx_data->data_to_send -= written;
    }

    if (!fclose(fp)) {
        JADE_LOGE("Closing file %s failed", ctx_data->file_to_flash);
    }

    free(ctx_data->file_to_flash);
    const size_t data_to_send = ctx_data->data_to_send;
    free(ctx_data);

    if (!data_to_send) {
        // all data sent, proceed with ota_complete message
        post_ota_complete_message(SOURCE_INTERNAL);
        ok = false;

        while (!jade_process_get_out_message(handle_ota_reply, SOURCE_INTERNAL, &ok)) {
            // Await outbound message
        }
        // ota success, device will be rebooted soon
    }

    usb_storage_unmount();
    usb_storage_stop();
    serial_start();

    vTaskDelete(NULL);
}

static void start_usb_internal_task(char* str, size_t fwsize, size_t cmpsize, uint8_t* hash, size_t len_hash)
{
    const bool res = post_ota_message(SOURCE_INTERNAL, fwsize, cmpsize, hash, SHA256_LEN);
    JADE_ASSERT(res);
    // FIXME: check stack size better
    char* copy = strdup(str);
    JADE_ASSERT(copy);
    struct usb_worker_data* ctx_data = JADE_MALLOC_PREFER_SPIRAM(sizeof(struct usb_worker_data));
    JADE_ASSERT(ctx_data);
    ctx_data->file_to_flash = copy;
    ctx_data->data_to_send = cmpsize;
    const BaseType_t retval = xTaskCreatePinnedToCore(
        usbmode_worker, "USBFWTASK", 12 * 1024, ctx_data, JADE_TASK_PRIO_USB, NULL, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(retval == pdPASS, "Failed to create USBFWTASK, xTaskCreatePinnedToCore() returned %d", retval);
}

bool list_files(const char* const path)
{
    /* we only find files in the root dir for now */
    // FIXME: implement recursive?
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_USB_STORAGE_FW_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };
    const char* suffix = "_fw.bin";
    const char* hash_suffix = ".hash";
    size_t suffix_len = strlen(suffix);
    size_t hash_suffix_len = strlen(hash_suffix);

    btn_data_t* menubtns = NULL;
    size_t arraySize = 0;

    DIR* const dp = opendir(path);
    if (dp == NULL) {
        return false;
    }

    char full_filename[MAX_FILENAME_SIZE + hash_suffix_len + 1];

    errno = 0;
    struct dirent* entry;
    while ((entry = readdir(dp))) {
        if (errno != 0) {
            break;
        }

        if (entry->d_type == DT_REG) {
            const char* str = entry->d_name;
            size_t str_len = strlen(str);
            if (str_len + hash_suffix_len >= MAX_FILENAME_SIZE) {
                // we don't support filenames beyond 512 characters
                continue;
            }

            if (str_len >= suffix_len && !strcmp(str + str_len - suffix_len, suffix)) {
                snprintf(full_filename, sizeof(full_filename), "%s/%s%s", path, str, hash_suffix);
                if (file_exists(full_filename)) {
                    // FIXME: we should extract now and validate now the fwsize/cmpsize/hash length
                    // otherwise ota can silently fail files that have a bad fwsize
                    ++arraySize;
                    menubtns = realloc(menubtns, arraySize * sizeof(btn_data_t));
                    JADE_ASSERT(menubtns);
                    memset(&menubtns[arraySize - 1], 0, sizeof(btn_data_t));
                    char* copy = strdup(str);
                    JADE_ASSERT(copy);
                    menubtns[arraySize - 1].txt = copy;
                    menubtns[arraySize - 1].font = GUI_DEFAULT_FONT;
                    menubtns[arraySize - 1].ev_id = BTN_KEYBOARD_ASCII_OFFSET + arraySize;
                }
            }
        }
        errno = 0;
    }

    if (closedir(dp) == -1) {
        JADE_LOGE("error closing dir");
    }

    if (!menubtns) {
        return false;
    }

    gui_activity_t* act = make_menu_activity("Firmwares", hdrbtns, 2, menubtns, arraySize);

    gui_set_current_activity(act);
    int32_t ev_id = 0;
    uint8_t hash[SHA256_LEN];

    bool ota_started = false;
    while (true) {
        if (gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            if (ev_id == BTN_SETTINGS_USB_STORAGE_FW_EXIT) {
                break;
            }
            char* str = (char*)(menubtns[(ev_id - BTN_KEYBOARD_ASCII_OFFSET) - 1].txt);
            snprintf(full_filename, sizeof(full_filename), "%s/%s%s", path, str, hash_suffix);
            bool res = read_file_to_buffer(full_filename, hash, sizeof(hash));
            // FIXME: fail more gracefully if disk disappers?
            JADE_ASSERT(res);

            snprintf(full_filename, sizeof(full_filename), "%s/%s", path, str);
            const size_t cmpsize = get_file_size(full_filename);
            const size_t fwsize = read_fwsize(full_filename);
            start_usb_internal_task(full_filename, fwsize, cmpsize, hash, sizeof(hash));
            ota_started = true;
            break;
        }
    }

    for (size_t i = 0; i < arraySize; ++i) {
        free((void*)menubtns[i].txt);
    }

    free(menubtns);
    return ota_started;
}
