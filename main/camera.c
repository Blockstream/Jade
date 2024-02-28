#include <esp_camera.h>
#include <freertos/idf_additions.h>

#include "button_events.h"
#include "camera.h"
#include "idletimer.h"
#ifdef CONFIG_BOARD_TYPE_JADE
#include "input.h"
#endif
#include "jade_assert.h"
#include "jade_tasks.h"
#include "power.h"
#include "sensitive.h"
#include "ui.h"
#include "utils/event.h"
#include "utils/malloc_ext.h"

// When the camera is running we ensure the timeout is at least this value
// as we don't want the unit to shut down because of apparent inactivity.
#define CAMERA_MIN_TIMEOUT_SECS 300

// Size of the image as provided by the camera - note this should be consistent
// with CAMERA_IMAGE_WIDTH and CAMERA_IMAGE_HEIGHT !  TODO: fetch from Kconfig?
#define CAMERA_IMAGE_RESOLUTION FRAMESIZE_QVGA

#define MIN(a, b) (a < b ? a : b)
#define MAX(a, b) (a > b ? a : b)

// The image from the camera framebuffer is scaled and cropped to fit the display image
// (Based on Jade screen dimensions and the fact that the image is half the screen.)

// Width and height of camera image aligned to screen orientation
#if defined(CONFIG_CAMERA_ROTATE_90) || (CONFIG_CAMERA_ROTATE_270)
// Camera image height and width directions flipped
#define UI_CAMERA_IMAGE_WIDTH CAMERA_IMAGE_HEIGHT
#define UI_CAMERA_IMAGE_HEIGHT CAMERA_IMAGE_WIDTH
#else
// Height and width directions match
#define UI_CAMERA_IMAGE_WIDTH CAMERA_IMAGE_WIDTH
#define UI_CAMERA_IMAGE_HEIGHT CAMERA_IMAGE_HEIGHT
#endif

// Screen area used to display camera image - half the width x full height
#define UI_DISPLAY_WIDTH (CONFIG_DISPLAY_WIDTH / 2)
#define UI_DISPLAY_HEIGHT CONFIG_DISPLAY_HEIGHT

// Scale down if image much larger than screen area in both dimensions
// The numerator is fixed at 2, allowing half-integer scaling
#define SCALE_NUMERATOR 2
#define CALC_SCALE_DENOMINATOR(img, ui) MAX(SCALE_NUMERATOR, (((SCALE_NUMERATOR * img) + (ui / 2)) / ui))
#define SCALE_DENOMINATOR                                                                                              \
    MIN(CALC_SCALE_DENOMINATOR(UI_CAMERA_IMAGE_WIDTH, UI_DISPLAY_WIDTH),                                               \
        CALC_SCALE_DENOMINATOR(UI_CAMERA_IMAGE_HEIGHT, UI_DISPLAY_HEIGHT))
#define CAM2UI(x) ((x * SCALE_NUMERATOR) / SCALE_DENOMINATOR)
#define UI2CAM(x) ((x * SCALE_DENOMINATOR) / SCALE_NUMERATOR)

// Dimensions of image to display
#define DISPLAY_IMAGE_WIDTH MIN(UI_DISPLAY_WIDTH, CAM2UI(UI_CAMERA_IMAGE_WIDTH))
#define DISPLAY_IMAGE_HEIGHT MIN(UI_DISPLAY_HEIGHT, CAM2UI(UI_CAMERA_IMAGE_HEIGHT))

// Crop central area of camera frame if scaled image still larger
#define XOFFSET MAX(0, ((UI_CAMERA_IMAGE_WIDTH - UI2CAM(DISPLAY_IMAGE_WIDTH)) / 2))
#define YOFFSET MAX(0, ((UI_CAMERA_IMAGE_HEIGHT - UI2CAM(DISPLAY_IMAGE_HEIGHT)) / 2))

void await_qr_help_activity(const char* url);

gui_activity_t* make_camera_activity(const char* btnText, progress_bar_t* progress_bar, gui_view_node_t** image_node,
    gui_view_node_t** label_node, bool show_help_btn);

// Camera-task config data
typedef struct {
    // Text to display on camera screen
    // NOTE: no text_btn means no button is shown, and all images are processed
    // NOTE: no text_label implies no ui is shown at all (and all images are processed)
    // NOTE: help_url is optional, and only valid if a label is passed
    const char* text_label;
    const char* text_button;
    const char* help_url;

    // Any progress bar (feedback for multi-frame scanning)
    progress_bar_t* progress_bar;

    // Function to call to process captured image
    camera_process_fn_t fn_process;

    // Context info passed to that function
    void* ctx;
} camera_task_config_t;

#ifdef CONFIG_DEBUG_MODE
// Debug/testing function to cache an image - the next time the camera is called
// a frame is captured but is ignored/discarded and this image presented instead.
// Call with NULL/0 to remove debug image.
// NOTE: the image is not owned here.
static const uint8_t* debug_image_data = NULL;
void camera_set_debug_image(const uint8_t* data, const size_t len)
{
    JADE_ASSERT(!data == !len);
    JADE_ASSERT(!len || len == CAMERA_IMAGE_WIDTH * CAMERA_IMAGE_HEIGHT);
    debug_image_data = data;
}
#endif

#ifdef CONFIG_HAS_CAMERA
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

#ifndef CONFIG_ETH_USE_OPENETH
static void jade_camera_init(void)
{
    JADE_LOGI("CAMERA_IMAGE_WIDTH: %u", CAMERA_IMAGE_WIDTH);
    JADE_LOGI("CAMERA_IMAGE_HEIGHT: %u", CAMERA_IMAGE_HEIGHT);
    JADE_LOGI("UI_CAMERA_IMAGE_WIDTH: %u", UI_CAMERA_IMAGE_WIDTH);
    JADE_LOGI("UI_CAMERA_IMAGE_HEIGHT: %u", UI_CAMERA_IMAGE_HEIGHT);
    JADE_LOGI("UI_DISPLAY_WIDTH: %u", UI_DISPLAY_WIDTH);
    JADE_LOGI("UI_DISPLAY_HEIGHT: %u", UI_DISPLAY_HEIGHT);
    JADE_LOGI("DISPLAY_IMAGE_SCALE_FACTOR: %u%%", CAM2UI(100)); // percent
    JADE_LOGI("DISPLAY_IMAGE_WIDTH: %u", DISPLAY_IMAGE_WIDTH);
    JADE_LOGI("DISPLAY_IMAGE_HEIGHT: %u", DISPLAY_IMAGE_HEIGHT);
    JADE_LOGI("XOFFSET: %u", XOFFSET);
    JADE_LOGI("YOFFSET: %u", YOFFSET);

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
        .pin_reset = CONFIG_CAMERA_RESET,
        .pin_pwdn = CONFIG_CAMERA_PWDN,

        .ledc_channel = LEDC_CHANNEL_0,
        .ledc_timer = LEDC_TIMER_0,
        .xclk_freq_hz = CONFIG_CAMERA_XCLK_FREQ,

        .pixel_format = PIXFORMAT_GRAYSCALE,
        .frame_size = CAMERA_IMAGE_RESOLUTION,

        .fb_count = 1,
        .fb_location = CAMERA_FB_IN_PSRAM,
        .grab_mode = CAMERA_GRAB_LATEST,

        .jpeg_quality = 0 };
#ifdef CONFIG_BOARD_TYPE_JADE
    /* uninit wheel in order to fully cleanup in anticipation of camera calling gpio_install_isr_service itself */
    wheel_uninit(/* uninstall gpio isr service */ true);
#endif
    const esp_err_t err = esp_camera_init(&camera_config);
    JADE_LOGI("Camera init done");
    if (err != ESP_OK) {
        JADE_LOGE("Camera init failed with error 0x%x", err);
        post_exit_event_and_await_death();
    }

    sensor_t* camera_sensor = esp_camera_sensor_get();
    JADE_ASSERT(camera_sensor);
    JADE_ASSERT(camera_sensor->set_hmirror);

    camera_sensor_info_t* camera_info = esp_camera_sensor_get_info(&camera_sensor->id);
    JADE_ASSERT(camera_info);
    JADE_ASSERT(camera_info->name);
    JADE_ASSERT(camera_info->model);

    JADE_LOGI("The camera in use is: %s (%u)", camera_info->name, camera_info->model);

    // GC0308 appears to need image flipping on both axes
    if (camera_info->model == CAMERA_GC0308) {
        const int hret = camera_sensor->set_hmirror(camera_sensor, 1);
        const int vret = camera_sensor->set_vflip(camera_sensor, 1);
        if (hret || vret) {
            JADE_LOGE("Failed to set camera hmirror/vflip, returned: %d/%d", hret, vret);
        }
    }
#ifdef CONFIG_BOARD_TYPE_JADE
    /* make wheel work with interrupt service from camera */
    wheel_reinit(/* install_gpio_isr_service */ false);
#endif
}
#endif

// Stop the camera
static void jade_camera_stop(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE
    /* wheel is currently using the camera gpio_install_isr_service , clean up only part of it */
    wheel_uninit(/* uninstall_gpio_isr_service */ false);
#endif
    esp_camera_deinit();
    power_camera_off();
#ifdef CONFIG_BOARD_TYPE_JADE
    /* create a new gpio_install_isr_service for the wheel before restarting it */
    wheel_reinit(/* install_gpio_isr_service */ true);
#endif
}

static inline bool invoke_user_cb_fn(const camera_task_config_t* camera_config, const camera_fb_t* fb)
{
#ifdef CONFIG_DEBUG_MODE
    // If we have a fixed debug image, we call the user callback on that instead of on the actual captured frame.
    // We then return true (to quit the camera task) regardless (no point reprocessing same image).
    if (debug_image_data) {
        if (!camera_config->fn_process(CAMERA_IMAGE_WIDTH, CAMERA_IMAGE_HEIGHT, debug_image_data,
                CAMERA_IMAGE_WIDTH * CAMERA_IMAGE_HEIGHT, camera_config->ctx)) {
            JADE_LOGW("User callback returned false for fixed debug image - exiting camera regardless");
        }
        return true;
    }
#endif
    return camera_config->fn_process(fb->width, fb->height, fb->buf, fb->len, camera_config->ctx);
}

// Task to take picture and pass the image captured to a processing callback
static void jade_camera_task(void* data)
{
    JADE_ASSERT(data);

    JADE_ASSERT(UI2CAM(1000) >= 1000); // UI image should not be larger than camera image
    JADE_ASSERT(XOFFSET >= 0);
    JADE_ASSERT(YOFFSET >= 0);

    camera_task_config_t* const camera_config = (camera_task_config_t*)data;
    JADE_ASSERT(camera_config->fn_process);
    JADE_ASSERT(camera_config->text_label || !camera_config->text_button);
    JADE_ASSERT(camera_config->text_label || !camera_config->help_url);
    // camera_config->ctx is optional
    // camera_config->text_label is optional
    //   - presence indicates we want the images shown on screen/ui
    //   - if NULL no GUI is shown
    // camera_config->text_button is optional - indicates we want the user to select the images presented
    // (otherwise all images are presented) to the given callback function ctx.fn_process()
    // camera_config->help_url is optional - if preset a '?' (and help screen) are shown
    // NOTE: not valid to have a button[label] or help_url if no screen[title/label]
    const bool has_gui = camera_config->text_label;

    gui_activity_t* act = NULL;
    gui_view_node_t* image_node = NULL;
    gui_view_node_t* label_node = NULL;

    if (has_gui) {
        // Create camera screen
        act = make_camera_activity(
            camera_config->text_button, camera_config->progress_bar, &image_node, &label_node, camera_config->help_url);
        gui_set_current_activity(act);
    }

    // Initialise the camera
    sensitive_init();
#ifndef CONFIG_ETH_USE_OPENETH
    jade_camera_init();
#endif
    vTaskDelay(500 / portTICK_PERIOD_MS);
    void* image_buffer = NULL;
    Picture pic = {};
    const size_t image_size = sizeof(uint8_t[DISPLAY_IMAGE_HEIGHT][DISPLAY_IMAGE_WIDTH]);
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
        pic.width = DISPLAY_IMAGE_WIDTH;
        pic.height = DISPLAY_IMAGE_HEIGHT;
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
        camera_fb_t* const fb = esp_camera_fb_get();
        if (!fb) {
            JADE_LOGW("esp_camera_fb_get() failed");
            continue;
        }
        JADE_ASSERT(fb->format == PIXFORMAT_GRAYSCALE); // 1BPP/GRAYSCALE
        JADE_ASSERT(fb->width == CAMERA_IMAGE_WIDTH);
        JADE_ASSERT(fb->height == CAMERA_IMAGE_HEIGHT);

        // If we have a gui, update the image on screen and check for button events
        if (has_gui) {
            // Copy from camera output to screen image
            // (Ensure source image large enough to be scaled down to display image size)
            JADE_ASSERT(fb->len >= UI2CAM(UI2CAM(image_size))); // x and y scaled
            uint8_t(*image_matrix)[DISPLAY_IMAGE_WIDTH] = image_buffer;
            uint8_t(*fb_matrix)[CAMERA_IMAGE_WIDTH] = (uint8_t(*)[CAMERA_IMAGE_WIDTH])fb->buf;
            for (size_t imgy = 0; imgy < DISPLAY_IMAGE_HEIGHT; ++imgy) {
                for (size_t imgx = 0; imgx < DISPLAY_IMAGE_WIDTH; ++imgx) {
#if defined(CONFIG_CAMERA_ROTATE_90)
                    const size_t srcy = (CAMERA_IMAGE_HEIGHT - 1) - XOFFSET - UI2CAM(imgx);
                    const size_t srcx = YOFFSET + UI2CAM(imgy);
#elif defined(CONFIG_CAMERA_ROTATE_180)
                    const size_t srcy = (CAMERA_IMAGE_HEIGHT - 1) - YOFFSET - UI2CAM(imgy);
                    const size_t srcx = (CAMERA_IMAGE_WIDTH - 1) - XOFFSET - UI2CAM(imgx);
#elif defined(CONFIG_CAMERA_ROTATE_270)
                    const size_t srcy = XOFFSET + UI2CAM(imgx);
                    const size_t srcx = (CAMERA_IMAGE_WIDTH - 1) - YOFFSET - UI2CAM(imgy);
#else
                    const size_t srcy = YOFFSET + UI2CAM(imgy);
                    const size_t srcx = XOFFSET + UI2CAM(imgx);
#endif

#ifdef CONFIG_DEBUG_MODE
                    JADE_ASSERT(srcx < CAMERA_IMAGE_WIDTH);
                    JADE_ASSERT(srcy < CAMERA_IMAGE_HEIGHT);
#endif
                    image_matrix[imgy][imgx] = fb_matrix[srcy][srcx];
                }
            }
            gui_update_picture(image_node, &pic, false);

            // Ensure showing camera activity/captured image
            if (gui_current_activity() != act) {
                gui_set_current_activity(act);
            }

            // Check for button events
            int32_t ev_id;
            if (sync_wait_event(event_data, NULL, &ev_id, NULL, 10 / portTICK_PERIOD_MS) == ESP_OK) {
                if (ev_id == BTN_CAMERA_CLICK) {
                    // Button clicked - invoke passed processing callback
                    JADE_ASSERT(camera_config->text_button);
                    gui_update_text(label_node, "Processing...");
                    done = invoke_user_cb_fn(camera_config, fb);

                    // If not done, will loop and continue to capture images
                    if (!done) {
                        gui_update_text(label_node, camera_config->text_label);
                    }
                } else if (ev_id == BTN_CAMERA_HELP) {
                    await_qr_help_activity(camera_config->help_url);
                } else if (ev_id == BTN_CAMERA_EXIT) {
                    // Done with camera
                    done = true;
                }
            }
        }

        // If we have no 'click' button (or no gui at all), we run the processing callback on every frame
        if (!done && !camera_config->text_button) {
            done = invoke_user_cb_fn(camera_config, fb);
        }

        // Release camera output buffer
        esp_camera_fb_return(fb);
    }

    // Finished with camera - free everything and kill task
    if (has_gui) {
        SENSITIVE_POP(image_buffer);
        free(image_buffer);
    }
    post_exit_event_and_await_death();
}
#endif // CONFIG_HAS_CAMERA

void jade_camera_process_images(camera_process_fn_t fn, void* ctx, const char* text_label, const char* text_button,
    const char* help_url, progress_bar_t* progress_bar)
{
    JADE_ASSERT(fn);
    // ctx is optional

    // text_label is optional
    //   - presence indicates we want the images shown on screen/ui
    //   - if NULL no GUI is shown
    // text_button is optional - indicates we want the user to select the images presented
    // (otherwise all images are presented) to the given callback function ctx.fn_process()
    // camera_config->help_url is optional - if preset a '?' (and help screen) are shown
    // progress_bar is optional, and is for providing feedback for multi-frame scanning
    // NOTE: not valid to have a button[label], help_url or progress_bar if no gui screen[title/label]
    JADE_ASSERT(text_label || !text_button);
    JADE_ASSERT(text_label || !help_url);
    JADE_ASSERT(text_label || !progress_bar);

#ifdef CONFIG_HAS_CAMERA
    // Config for the camera task
    camera_task_config_t camera_config = { .text_label = text_label,
        .text_button = text_button,
        .help_url = help_url,
        .progress_bar = progress_bar,
        .fn_process = fn,
        .ctx = ctx };

    // When running the camera task we set the minimum idle timeout to keep the hw from sleeping too quickly
    // (If the user has set a longer timeout value that is respected)
    idletimer_set_min_timeout_secs(CAMERA_MIN_TIMEOUT_SECS);

    // Run the camera task
#ifdef CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY
    const UBaseType_t mem_caps = MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM;
#else
    const UBaseType_t mem_caps = MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL;
#endif

    TaskHandle_t camera_task;
    const BaseType_t retval = xTaskCreatePinnedToCoreWithCaps(&jade_camera_task, "jade_camera", 16 * 1024,
        &camera_config, JADE_TASK_PRIO_CAMERA, &camera_task, JADE_CORE_SECONDARY, mem_caps);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create jade_camera task, xTaskCreatePinnedToCore() returned %d", retval);

    // Await camera exit event
    sync_await_single_event(JADE_EVENT, CAMERA_EXIT, NULL, NULL, NULL, 0);
    vTaskDeleteWithCaps(camera_task);
    jade_camera_stop();

    // Remove the minimum idle timeout
    idletimer_set_min_timeout_secs(0);

#else // CONFIG_HAS_CAMERA
    JADE_LOGW("No camera supported for this device");
    const char* message[] = { "No camera detected" };
    await_error_activity(message, 1);
#endif
}
