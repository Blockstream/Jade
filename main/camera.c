#include <string.h>

#include <esp_camera.h>
#include <quirc_internal.h>
#include <tft.h>

#include "button_events.h"
#include "camera.h"
#include "gui.h"
#include "jade_assert.h"
#include "power.h"
#include "sensitive.h"
#include "utils/event.h"
#include "utils/malloc_ext.h"

#include <wally_core.h>

static const char POINT_TO_QR[] = "Point to a QR\ncode and Scan";

// Signal to the caller that we are done, and await our death
static void post_exit_event_and_await_death(void)
{
    // Ensure we have cleaned up sensitive data
    sensitive_assert_empty();
    sensitive_clear_stack();

    // Post 'camera-exit' event
    esp_event_post(JADE_EVENT, CAMERA_EXIT, NULL, 0, portMAX_DELAY);

    // wait to be killed
    for (;;) {
        vTaskDelay(portMAX_DELAY);
    }
}

static void camera_reset(void)
{
    power_camera_off();
    vTaskDelay(20 / portTICK_PERIOD_MS);
    power_camera_on();
}

static void jade_camera_init(void)
{
    power_camera_on();
    const camera_config_t camera_config = {
        .pin_d0 = CONFIG_CAMERA_D0,
        .pin_d1 = CONFIG_CAMERA_D1,
        .pin_d2 = CONFIG_CAMERA_D2,
        .pin_d3 = CONFIG_CAMERA_D3,
        .pin_d4 = CONFIG_CAMERA_D4,
        .pin_d5 = CONFIG_CAMERA_D5,
        .pin_d6 = CONFIG_CAMERA_D6,
        .pin_d7 = CONFIG_CAMERA_D7,
        .pin_xclk = CONFIG_CAMERA_XCLK,
        .pin_pclk = CONFIG_CAMERA_PCLK,
        .pin_vsync = CONFIG_CAMERA_VSYNC,
        .pin_href = CONFIG_CAMERA_HREF,
        .pin_sscb_sda = CONFIG_CAMERA_SDA,
        .pin_sscb_scl = CONFIG_CAMERA_SCL,
        .reset_callback = camera_reset,
        .pin_reset = CONFIG_CAMERA_RESET,
        .pin_pwdn = CONFIG_CAMERA_PWDN,

        .ledc_channel = LEDC_CHANNEL_0,
        .ledc_timer = LEDC_TIMER_0,
        .xclk_freq_hz = CONFIG_CAMERA_XCLK_FREQ,

        .pixel_format = PIXFORMAT_GRAYSCALE,
        .frame_size = FRAMESIZE_QVGA,

        .fb_count = 1,
    };
    const esp_err_t err = esp_camera_init(&camera_config);
    JADE_LOGI("Camera init done");
    if (err != ESP_OK) {
        JADE_LOGE("Camera init failed with error 0x%x", err);
        post_exit_event_and_await_death();
    }
}

// Inspect qrcodes and try to extract payload - whether any were seen and any
// string data extracted are stored in the camera_data passed.
static void extract_payload(struct quirc* q, jade_camera_data_t* camera_data)
{
    JADE_ASSERT(q);
    JADE_ASSERT(camera_data);

    const int count = quirc_count(q);
    JADE_LOGD("Detected %d QR codes in image.", count);
    if (count <= 0) {
        camera_data->qr_seen = false;
        return;
    }

    // Store the first string we manage to extract - initialise to empty string.
    camera_data->qr_seen = true;
    camera_data->strdata[0] = '\0';

    struct quirc_data data;
    SENSITIVE_PUSH(&data, sizeof(data));

    // Look for a string
    for (int i = 0; i < count; ++i) {
        struct quirc_code code;
        quirc_extract(q, i, &code);

        const quirc_decode_error_t error_status = quirc_decode(&code, &data);
        if (error_status != QUIRC_SUCCESS) {
            JADE_LOGW("QUIRC error %s", quirc_strerror(error_status));
        } else if (data.data_type == QUIRC_DATA_TYPE_KANJI) {
            JADE_LOGW("QUIRC unexpected data type: %d", data.data_type);
        } else if (data.payload_len >= sizeof(camera_data->strdata)) {
            JADE_LOGW("QUIRC data too long to handle: %u", data.payload_len);
            JADE_ASSERT(data.payload_len <= sizeof(data.payload));
        } else {
            // The payload appears to be a null-terminated string, but the
            // 'payload_len'seems to be the string length not including that
            // terminator.
            // To avoid any confusion or grey areas, we copy the bytes,
            // and then explicitly add the null terminator ourselves.
            memcpy(camera_data->strdata, data.payload, data.payload_len);
            camera_data->strdata[data.payload_len] = '\0';
            SENSITIVE_POP(&data);
            return;
        }
    }
    SENSITIVE_POP(&data);
}

// Look for qr-codes, and if found extract any string data into the camera_data passed
static void qr_recoginze(void* pdata, jade_camera_data_t* camera_data)
{
    JADE_ASSERT(pdata);
    JADE_ASSERT(camera_data);

    camera_fb_t* camera_config = pdata;

    struct quirc* q = quirc_new();
    JADE_ASSERT(q);

    const int qret = quirc_resize(q, camera_config->width, camera_config->height);
    JADE_ASSERT(qret == 0);

    // Try to interpret camera image as QR-code
    uint8_t* image = quirc_begin(q, NULL, NULL);
    memcpy(image, camera_config->buf, camera_config->len);
    quirc_end(q);

    extract_payload(q, camera_data);
    quirc_destroy(q);
}

// release the fb
void jade_camera_stop(void)
{
    esp_camera_deinit();
    power_camera_off();
}

// Free all the memory structures we may have allocated
void cleanup_camera_data(jade_camera_data_t* camera_data)
{
    JADE_ASSERT(camera_data);

    // Ensure (potentially large) image buffer is freed
    if (camera_data->image_buffer) {
        free(camera_data->image_buffer);
        camera_data->image_buffer = NULL;
    }
}

// Task to take picture and decode any qr code captured
void jade_camera_task(void* data)
{
    jade_camera_data_t* const camera_data = data;

    gui_update_text(camera_data->text, "Initializing the\ncamera...");
    sensitive_init();
    jade_camera_init();
    vTaskDelay(500 / portTICK_PERIOD_MS);
    gui_update_text(camera_data->text, POINT_TO_QR);

    // Image from camera to display on screen.
    // 50% scale down - still a 20k image buffer.  Attach to jade_camera_data
    // structure so we keep track of it and it can be freed later.
    // Keep in dram in case it captures a valid mnemonic qrcode.
    const size_t image_size = sizeof(uint8_t[160][120]);
    JADE_ASSERT(camera_data->image_buffer == NULL);
    camera_data->image_buffer = JADE_MALLOC_DRAM(image_size);
    const Picture pic = { .width = 120, .height = 160, .bytes_per_pixel = 1, .data_8 = camera_data->image_buffer };

    // Make an event-data structure to track events - attached to the camera activity
    wait_event_data_t* const event_data = gui_activity_make_wait_event_data(camera_data->activity);
    JADE_ASSERT(event_data);

    // ... and register against the activity - we will await btn events later
    gui_activity_register_event(
        camera_data->activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);

    // Loop periodically refreshes screen image from camera, and waits for button event
    const TickType_t frequency = 1000 / 5 / portTICK_PERIOD_MS;
    TickType_t last_wake = xTaskGetTickCount();
    for (;;) {
        // Capture camera output
        camera_fb_t* fb = esp_camera_fb_get();
        if (!fb) {
            continue;
        }

        // Copy from camera output to screen image
        uint8_t(*scale_rotated)[120] = camera_data->image_buffer;
        uint8_t(*buf_as_matrix)[320] = (unsigned char(*)[320])fb->buf;
        for (size_t x = 0; x < 160; x++) {
            for (size_t y = 0; y < 120; y++) {
                scale_rotated[x][y] = buf_as_matrix[240 - y * 2][x * 2];
            }
        }
        gui_update_picture(camera_data->camera, &pic);

        // Await button click event
        int32_t ev_id;
        if (sync_wait_event(GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, event_data, NULL, &ev_id, NULL, frequency) == ESP_OK) {

            if (ev_id == BTN_QR_MNEMONIC_SCAN) {
                gui_update_text(camera_data->text, "Processing...");
                qr_recoginze(fb, camera_data);

                // If we saw a qr-code, we return the the caller here.
                // Any string data will have been populated in the camera_data struct
                if (camera_data->qr_seen) {
                    // We have captured a string - fall back to the calling task
                    esp_camera_fb_return(fb);
                    post_exit_event_and_await_death();
                }
                gui_update_text(camera_data->text, POINT_TO_QR);
            } else if (ev_id == BTN_QR_MNEMONIC_EXIT) {
                // Exit btn
                camera_data->qr_seen = false;
                esp_camera_fb_return(fb);
                post_exit_event_and_await_death();
            }
        }
        esp_camera_fb_return(fb);

        // Sleep, then loop to capture image again
        vTaskDelayUntil(&last_wake, frequency);
    }
}
