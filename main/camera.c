#include <esp_camera.h>

#include "button_events.h"
#include "camera.h"
#include "jade_assert.h"
#include "jade_tasks.h"
#include "power.h"
#include "sensitive.h"
#include "ui.h"
#include "utils/event.h"
#include "utils/malloc_ext.h"

void make_camera_activity(
    gui_activity_t** activity_ptr, const char* btnText, gui_view_node_t** image_node, gui_view_node_t** label_node);

// Camera-task config data
typedef struct {
    // Text to display on camera screen
    // NOTE: no text_btn means no button is shown, and all images are processed
    // NOTE: no text_label implies no ui is shown at all (and all images are processed)
    const char* text_label;
    const char* text_button;

    // Function to call to process captured image
    camera_process_fn_t fn_process;

    // Context info passed to that function
    void* ctx;
} camera_task_config_t;

// Signal to the caller that we are done, and await our death
static void post_exit_event_and_await_death(void)
{
    // Ensure we have cleaned up sensitive data
    sensitive_assert_empty();

    // Log the task stack HWM so we can estimate ideal stack size
    JADE_LOGI("Camera task complete - task stack HWM: %u free", uxTaskGetStackHighWaterMark(NULL));

    // Post 'camera-exit' event
    esp_event_post(JADE_EVENT, CAMERA_EXIT, NULL, 0, portMAX_DELAY);

    // wait to be killed
    for (;;) {
        vTaskDelay(portMAX_DELAY);
    }
}

static void camera_reset(void)
{
    esp_err_t ret = power_camera_off();
    if (ret != ESP_OK) {
        JADE_LOGE("Failed to reset/power camera off: %u", ret);
    }
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ret = power_camera_on();
    if (ret != ESP_OK) {
        JADE_LOGE("Failed to reset/power camera on: %u", ret);
    }
}

static void jade_camera_init(void)
{
    const esp_err_t ret = power_camera_on();
    if (ret != ESP_OK) {
        JADE_LOGE("Failed to inititialise/power camera on: %u", ret);
    }

    const camera_config_t camera_config = { .pin_d0 = CONFIG_CAMERA_D0,
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
        .jpeg_quality = 0 };
    const esp_err_t err = esp_camera_init(&camera_config);
    JADE_LOGI("Camera init done");
    if (err != ESP_OK) {
        JADE_LOGE("Camera init failed with error 0x%x", err);
        post_exit_event_and_await_death();
    }
}

// release the fb
static void jade_camera_stop(void)
{
    esp_camera_deinit();
    power_camera_off();
}

// Task to take picture and pass the image captured to a processing callback
static void jade_camera_task(void* data)
{
    JADE_ASSERT(data);

    camera_task_config_t* const camera_config = (camera_task_config_t*)data;
    JADE_ASSERT(camera_config->fn_process);
    JADE_ASSERT(camera_config->text_label || !camera_config->text_button);
    // camera_config->ctx is optional
    // camera_config->text_label is optional - indicates we want the images shown on screen/ui
    // camera_config->text_button is optional - indicates we want the user to select the images presented
    // (otherwise all images are presented) to the given callback function ctx.fn_process()
    // NOTE: not valid to have a button[label] if no screen[label]

    const bool has_gui = camera_config->text_label;

    gui_activity_t* act = NULL;
    gui_view_node_t* image_node = NULL;
    gui_view_node_t* label_node = NULL;

    if (has_gui) {
        // Create camera screen
        make_camera_activity(&act, camera_config->text_button, &image_node, &label_node);
        JADE_ASSERT(act);
        gui_set_current_activity(act);
    }

    // Initialise the camera
    sensitive_init();
    jade_camera_init();
    vTaskDelay(500 / portTICK_PERIOD_MS);
    void* image_buffer = NULL;
    Picture pic = {};
    const size_t image_size = sizeof(uint8_t[CAMERA_IMAGE_WIDTH / 2][CAMERA_IMAGE_HEIGHT / 2]);
    wait_event_data_t* event_data = NULL;
    if (has_gui) {
        // Update the text label to indicate readiness
        gui_update_text(label_node, camera_config->text_label);

        // Image from camera to display on screen.
        // 50% scale down and rotated - still a 20k image buffer.
        // Keep image in spiram but make sure to zero it after use in case it
        // captures potentially sensitive data eg. a valid mnemonic qrcode.
        image_buffer = JADE_MALLOC_PREFER_SPIRAM(image_size);
        SENSITIVE_PUSH(image_buffer, image_size);
        // NOTE rotated so height <-> width
        pic.width = CAMERA_IMAGE_HEIGHT / 2;
        pic.height = CAMERA_IMAGE_WIDTH / 2;
        pic.bytes_per_pixel = 1;
        pic.data_8 = image_buffer;

        // Make an event-data structure to track events - attached to the camera activity
        event_data = gui_activity_make_wait_event_data(act);
        JADE_ASSERT(event_data);

        // ... and register against the activity - we will await btn events later
        gui_activity_register_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);
    }

    // Loop periodically refreshes screen image from camera, and waits for button event
    bool done = false;
    while (!done) {
        // Capture camera output
        camera_fb_t* fb = esp_camera_fb_get();
        if (!fb) {
            JADE_LOGW("esp_camera_fb_get() failed");
            continue;
        }
        JADE_ASSERT(fb->format == PIXFORMAT_GRAYSCALE); // 1BPP/GRAYSCALE
        JADE_ASSERT(fb->width == CAMERA_IMAGE_WIDTH);
        JADE_ASSERT(fb->height == CAMERA_IMAGE_HEIGHT);

        if (!has_gui) {
            done = camera_config->fn_process(fb->width, fb->height, fb->buf, fb->len, camera_config->ctx);
        } else {
            // Copy from camera output to screen image
            JADE_ASSERT(fb->len == 4 * image_size); // twice width and twice height
            uint8_t(*scale_rotated)[CAMERA_IMAGE_HEIGHT / 2] = image_buffer;
            uint8_t(*buf_as_matrix)[CAMERA_IMAGE_WIDTH] = (uint8_t(*)[CAMERA_IMAGE_WIDTH])fb->buf;
            for (size_t x = 0; x < CAMERA_IMAGE_WIDTH / 2; ++x) {
                for (size_t y = 0; y < CAMERA_IMAGE_HEIGHT / 2; ++y) {
                    scale_rotated[x][y] = buf_as_matrix[(CAMERA_IMAGE_HEIGHT)-y * 2][x * 2];
                }
            }
            gui_update_picture(image_node, &pic, false);

            // Ensure showing camera activity/captured image
            if (gui_current_activity() != act) {
                gui_set_current_activity(act);
            }

            // If we have no 'click' button, we run the processing callback on every frame
            // (We still test to see if the 'Exit' button is pressed though)
            if (!camera_config->text_button) {
                done = camera_config->fn_process(fb->width, fb->height, fb->buf, fb->len, camera_config->ctx)
                    || (sync_wait_event(
                            GUI_BUTTON_EVENT, BTN_CAMERA_EXIT, event_data, NULL, NULL, NULL, 10 / portTICK_PERIOD_MS)
                        == ESP_OK);
            } else {
                // Await button click event before we do anything
                int32_t ev_id;
                if (sync_wait_event(
                        GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, event_data, NULL, &ev_id, NULL, 50 / portTICK_PERIOD_MS)
                    == ESP_OK) {
                    if (ev_id == BTN_CAMERA_CLICK) {
                        // Button clicked - invoke passed processing callback
                        gui_update_text(label_node, "Processing...");
                        done = camera_config->fn_process(fb->width, fb->height, fb->buf, fb->len, camera_config->ctx);

                        // If not done, will loop and continue to capture images
                        if (!done) {
                            gui_update_text(label_node, camera_config->text_label);
                        }
                    } else if (ev_id == BTN_CAMERA_EXIT) {
                        // Done with camera
                        done = true;
                    }
                }
            }
        }
        esp_camera_fb_return(fb);
    }

    // Finished with camera - free everything and kill task
    if (has_gui) {
        SENSITIVE_POP(image_buffer);
        free(image_buffer);
    }
    post_exit_event_and_await_death();
}

void jade_camera_process_images(camera_process_fn_t fn, void* ctx, const char* text_label, const char* text_button)
{
    JADE_ASSERT(fn);
    // ctx is optional

    // text_label is optional - indicates we want the images shown on screen/ui
    // text_button is optional - indicates we want the user to select the images presented
    // (otherwise all images are presented) to the given callback function ctx.fn_process()
    // NOTE: not valid to have a button[label] if no screen[label]
    JADE_ASSERT(text_label || !text_button);

// At the moment camera only supported by Jade devices
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    // Config for the camera task
    camera_task_config_t camera_config
        = { .text_label = text_label, .text_button = text_button, .fn_process = fn, .ctx = ctx };

    // Run the camera task
    TaskHandle_t camera_task;
    const BaseType_t retval = xTaskCreatePinnedToCore(&jade_camera_task, "jade_camera", 16 * 1024, &camera_config,
        JADE_TASK_PRIO_CAMERA, &camera_task, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create jade_camera task, xTaskCreatePinnedToCore() returned %d", retval);

    // Await camera exit event
    sync_await_single_event(JADE_EVENT, CAMERA_EXIT, NULL, NULL, NULL, 0);
    vTaskDelete(camera_task);
    jade_camera_stop();

#else // CONFIG_BOARD_TYPE_JADE || CONFIG_BOARD_TYPE_JADE_V1_1
    JADE_LOGW("No camera supported for this device");
    await_error_activity("No camera detected");
#endif
}