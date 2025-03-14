#include <esp_camera.h>
#include <freertos/idf_additions.h>

#include "button_events.h"
#include "camera.h"
#include "idletimer.h"
#include "jade_assert.h"
#include "jade_tasks.h"
#include "power.h"
#include "sensitive.h"
#include "ui.h"
#include "utils/event.h"
#include "utils/malloc_ext.h"

#if defined(CONFIG_DISPLAY_TOUCHSCREEN)
void touchscreen_init(void);
void touchscreen_deinit(void);
#endif

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
// When the camera is running we ensure the timeout is at least this value
// as we don't want the unit to shut down because of apparent inactivity.
#define CAMERA_MIN_TIMEOUT_SECS 300

// Size of the image as provided by the camera - note this should be consistent
// with CAMERA_IMAGE_WIDTH and CAMERA_IMAGE_HEIGHT !  TODO: fetch from Kconfig?
#ifdef CONFIG_IDF_TARGET_ESP32S3
#define CAMERA_IMAGE_RESOLUTION FRAMESIZE_VGA
#else
#define CAMERA_IMAGE_RESOLUTION FRAMESIZE_QVGA
#endif

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

// Screen area used to display camera image - full screen
#define UI_DISPLAY_WIDTH (CONFIG_DISPLAY_WIDTH * 70 / 100) // 70% of screen width
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

static inline void copy_pixel(uint8_t dest[DISPLAY_IMAGE_HEIGHT][DISPLAY_IMAGE_WIDTH], const uint16_t destx,
    const uint16_t desty, const uint8_t src[CAMERA_IMAGE_HEIGHT][CAMERA_IMAGE_WIDTH], const uint16_t srcx,
    const uint16_t srcy)
{
#ifdef CONFIG_DEBUG_MODE
    JADE_ASSERT(destx < DISPLAY_IMAGE_WIDTH);
    JADE_ASSERT(desty < DISPLAY_IMAGE_HEIGHT);
    JADE_ASSERT(srcx < CAMERA_IMAGE_WIDTH);
    JADE_ASSERT(srcy < CAMERA_IMAGE_HEIGHT);
#endif

    // For a front-facing camera, write the image from right-to-left, so it 'moves' the way
    // the user would expect, ie. behaves like a mirror.  In the final image any writing would be backwards...
    // NOTE: this is only done here for the image going to the screen - the source data remains as
    // presented by the camera, so in the source frame-buffer (ie. as passed to the processing callback)
    // any writing would be 'correct'.  This is important for text *and QR codes* (and is why we can't use
    // sensor->set_hmirror(i) which would reverse what the hw places in the framebuffer).
#ifdef CONFIG_CAMERA_FRONT_FACING
    dest[desty][(DISPLAY_IMAGE_WIDTH - 1) - destx] = src[srcy][srcx];
#else
    dest[desty][destx] = src[srcy][srcx];
#endif
}

// Loops to copy the camera image
// Avoids any 'ifs' or function calls during the image copy loop
#if defined(CONFIG_CAMERA_ROTATE_90) || defined(CONFIG_CAMERA_ROTATE_270)
static void copy_camera_image_90(
    uint8_t dest[DISPLAY_IMAGE_HEIGHT][DISPLAY_IMAGE_WIDTH], const uint8_t src[CAMERA_IMAGE_HEIGHT][CAMERA_IMAGE_WIDTH])
{
    for (uint16_t desty = 0; desty < DISPLAY_IMAGE_HEIGHT; ++desty) {
        for (uint16_t destx = 0; destx < DISPLAY_IMAGE_WIDTH; ++destx) {
            const uint16_t srcy = (CAMERA_IMAGE_HEIGHT - 1) - XOFFSET - UI2CAM(destx);
            const uint16_t srcx = YOFFSET + UI2CAM(desty);
            copy_pixel(dest, destx, desty, src, srcx, srcy);
        }
    }
}

static void copy_camera_image_270(
    uint8_t dest[DISPLAY_IMAGE_HEIGHT][DISPLAY_IMAGE_WIDTH], const uint8_t src[CAMERA_IMAGE_HEIGHT][CAMERA_IMAGE_WIDTH])
{
    for (uint16_t desty = 0; desty < DISPLAY_IMAGE_HEIGHT; ++desty) {
        for (uint16_t destx = 0; destx < DISPLAY_IMAGE_WIDTH; ++destx) {
            const uint16_t srcy = XOFFSET + UI2CAM(destx);
            const uint16_t srcx = (CAMERA_IMAGE_WIDTH - 1) - YOFFSET - UI2CAM(desty);
            copy_pixel(dest, destx, desty, src, srcx, srcy);
        }
    }
}
#else
static void copy_camera_image_0(
    uint8_t dest[DISPLAY_IMAGE_HEIGHT][DISPLAY_IMAGE_WIDTH], const uint8_t src[CAMERA_IMAGE_HEIGHT][CAMERA_IMAGE_WIDTH])
{
    for (uint16_t desty = 0; desty < DISPLAY_IMAGE_HEIGHT; ++desty) {
        for (uint16_t destx = 0; destx < DISPLAY_IMAGE_WIDTH; ++destx) {
            const uint16_t srcy = YOFFSET + UI2CAM(desty);
            const uint16_t srcx = XOFFSET + UI2CAM(destx);
            copy_pixel(dest, destx, desty, src, srcx, srcy);
        }
    }
}

static void copy_camera_image_180(
    uint8_t dest[DISPLAY_IMAGE_HEIGHT][DISPLAY_IMAGE_WIDTH], const uint8_t src[CAMERA_IMAGE_HEIGHT][CAMERA_IMAGE_WIDTH])
{
    for (uint16_t desty = 0; desty < DISPLAY_IMAGE_HEIGHT; ++desty) {
        for (uint16_t destx = 0; destx < DISPLAY_IMAGE_WIDTH; ++destx) {
            const uint16_t srcy = (CAMERA_IMAGE_HEIGHT - 1) - YOFFSET - UI2CAM(desty);
            const uint16_t srcx = (CAMERA_IMAGE_WIDTH - 1) - XOFFSET - UI2CAM(destx);
            copy_pixel(dest, destx, desty, src, srcx, srcy);
        }
    }
}
#endif

#if defined(CONFIG_CAMERA_ROTATE_90)
#define COPY_CAMERA_IMAGE_STRAIGHT copy_camera_image_90
#define COPY_CAMERA_IMAGE_FLIPPED copy_camera_image_270
#elif defined(CONFIG_CAMERA_ROTATE_180)
#define COPY_CAMERA_IMAGE_STRAIGHT copy_camera_image_180
#define COPY_CAMERA_IMAGE_FLIPPED copy_camera_image_0
#elif defined(CONFIG_CAMERA_ROTATE_270)
#define COPY_CAMERA_IMAGE_STRAIGHT copy_camera_image_270
#define COPY_CAMERA_IMAGE_FLIPPED copy_camera_image_90
#else
#define COPY_CAMERA_IMAGE_STRAIGHT copy_camera_image_0
#define COPY_CAMERA_IMAGE_FLIPPED copy_camera_image_180
#endif

void await_qr_help_activity(const char* url);

size_t camera_displayed_image_width(void) { return UI2CAM(DISPLAY_IMAGE_WIDTH); }

size_t camera_displayed_image_height(void) { return UI2CAM(DISPLAY_IMAGE_HEIGHT); }

gui_activity_t* make_camera_activity(gui_view_node_t** image_node, gui_view_node_t** label_node, bool show_click_btn,
    qr_frame_guides_t qr_frame_guides, progress_bar_t* progress_bar, bool show_help_btn);

// Camera-task config data
typedef struct {
    // Whether to show a ui or silently collect image data
    const bool show_ui;

    // Text to display on camera screen - only valid if 'show_ui' is set.
    const char* text_label;

    // NOTE: help_url is optional, and only valid if a 'show_ui' is passed
    const char* help_url;

    // NOTE: no click button implies all images are processed
    // NOTE: atm show_click_btn and help_url are mutually exclusive
    bool show_click_button;

    // Whether to show guides for ideal QR code placement
    // NOTE: qr_frame_guides is only valid if 'show_ui' is set.
    qr_frame_guides_t qr_frame_guides;

    // Any progress bar (feedback for multi-frame scanning)
    // NOTE: progress_bar is optional, and only valid if 'show_ui' is set.
    progress_bar_t* progress_bar;

    // Function to call to process captured image
    camera_process_fn_t fn_process;

    // Context info passed to that function
    void* ctx;
} camera_task_config_t;

// Signal to the caller that we are done, and await our death
static void camera_post_exit_event_and_await_death(void)
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

        .fb_count = 2,
        .fb_location = CAMERA_FB_IN_PSRAM,
        .grab_mode = CAMERA_GRAB_LATEST,

        .jpeg_quality = 0 };
    const esp_err_t err = esp_camera_init(&camera_config);
    JADE_LOGI("Camera init done");
    if (err != ESP_OK) {
        JADE_LOGE("Camera init failed with error 0x%x", err);
        camera_post_exit_event_and_await_death();
    }

    sensor_t* camera_sensor = esp_camera_sensor_get();
    JADE_ASSERT(camera_sensor);

    camera_sensor_info_t* camera_info = esp_camera_sensor_get_info(&camera_sensor->id);
    JADE_ASSERT(camera_info);
    JADE_ASSERT(camera_info->name);
    JADE_ASSERT(camera_info->model);

    JADE_LOGI("The camera in use is: %s (%u)", camera_info->name, camera_info->model);

    // GC0308 appears to need image flipping on both axes
    if (camera_info->model == CAMERA_GC0308) {
        JADE_ASSERT(camera_sensor->set_hmirror);
        JADE_ASSERT(camera_sensor->set_vflip);
        const int hret = camera_sensor->set_hmirror(camera_sensor, 1);
        const int vret = camera_sensor->set_vflip(camera_sensor, 1);
        if (hret || vret) {
            JADE_LOGE("Failed to set camera hmirror/vflip, returned: %d/%d", hret, vret);
        }
    }

    // OV3660 needs a vertical flip for the ESP32 Wrover Cam
    // OV5640 needs vertical flip for T-Display S3 PRO
    else if (camera_info->model == CAMERA_OV3660 || camera_info->model == CAMERA_OV5640) {
        JADE_ASSERT(camera_sensor->set_vflip);
        const int vret = camera_sensor->set_vflip(camera_sensor, 1);
        if (vret) {
            JADE_LOGE("Failed to set camera vflip, returned: %d", vret);
        }
    }

#if defined(CONFIG_DISPLAY_TOUCHSCREEN)
    touchscreen_deinit();
    touchscreen_init();
#endif
}
#endif

// Stop the camera
static void jade_camera_stop(void)
{
    esp_camera_deinit();
    power_camera_off();
#if defined(CONFIG_DISPLAY_TOUCHSCREEN)
    touchscreen_deinit();
    touchscreen_init();
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

    typedef void (*copy_camera_image_fn_t)(
        uint8_t[DISPLAY_IMAGE_HEIGHT][DISPLAY_IMAGE_WIDTH], const uint8_t[CAMERA_IMAGE_HEIGHT][CAMERA_IMAGE_WIDTH]);
    copy_camera_image_fn_t copy_camera_image
        = gui_get_flipped_orientation() ? COPY_CAMERA_IMAGE_FLIPPED : COPY_CAMERA_IMAGE_STRAIGHT;

    camera_task_config_t* const camera_config = (camera_task_config_t*)data;
    JADE_ASSERT(camera_config->fn_process);
    if (!camera_config->show_ui) {
        JADE_ASSERT(!camera_config->text_label);
        JADE_ASSERT(!camera_config->show_click_button);
        JADE_ASSERT(!camera_config->help_url);
        JADE_ASSERT(camera_config->qr_frame_guides == QR_GUIDES_NONE);
        JADE_ASSERT(!camera_config->progress_bar);
    }

    // camera_config->ctx is optional
    // camera_config->show_ui indicates whether to show a ui or collect cmaera data 'silently'
    // camera_config->text_label is optional
    // camera_config->show_click_button indicates we want the user to select the images presented
    // (otherwise all images are presented) to the given callback function ctx.fn_process()
    // camera_config->help_url is optional - if preset a '?' (and help screen) are shown
    // camera_config->qr_frame_guides is optional - if set guides for ideal QR placement are shown
    // camera_config->progress_bar is optional, and is for providing feedback for multi-frame scanning
    // NOTE: not valid to have a label, click button, help_url, qr frame or progress bar if no ui shown
    // NOTE: atm show_click_btn and help_url are mutually exclusive

    gui_activity_t* act = NULL;
    gui_view_node_t* image_node = NULL;
    gui_view_node_t* label_node = NULL;

    if (camera_config->show_ui) {
        // Create camera screen
        act = make_camera_activity(&image_node, &label_node, camera_config->show_click_button,
            camera_config->qr_frame_guides, camera_config->progress_bar, camera_config->help_url);
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
    const char* const label = camera_config->text_label ? camera_config->text_label : "";

    if (camera_config->show_ui) {
        // Update the text label to indicate readiness
        gui_update_text(label_node, label);

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
        if (camera_config->show_ui) {
            // Copy from camera output to screen image
            // (Ensure source image large enough to be scaled down to display image size)
            JADE_ASSERT(fb->len >= UI2CAM(UI2CAM(image_size))); // x and y scaled
            uint8_t(*image_matrix)[DISPLAY_IMAGE_WIDTH] = image_buffer;
            const uint8_t(*fb_matrix)[CAMERA_IMAGE_WIDTH] = (const uint8_t(*)[CAMERA_IMAGE_WIDTH])fb->buf;
            copy_camera_image(image_matrix, fb_matrix);
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
                    JADE_ASSERT(camera_config->show_click_button);
                    gui_update_text(label_node, "Processing...");
                    done = invoke_user_cb_fn(camera_config, fb);

                    // If not done, will loop and continue to capture images
                    if (!done) {
                        gui_update_text(label_node, label);
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
        if (!done && !camera_config->show_click_button) {
            done = invoke_user_cb_fn(camera_config, fb);
        }

        // Release camera output buffer
        esp_camera_fb_return(fb);
    }

    // Finished with camera - free everything and kill task
    if (camera_config->show_ui) {
        SENSITIVE_POP(image_buffer);
        free(image_buffer);
    }
    camera_post_exit_event_and_await_death();
}

void jade_camera_process_images(camera_process_fn_t fn, void* ctx, const bool show_ui, const char* text_label,
    const bool show_click_button, const qr_frame_guides_t qr_frame_guides, const char* help_url,
    progress_bar_t* progress_bar)
{
    JADE_ASSERT(fn);
    // ctx is optional

    // show_ui indicates whether to show a ui or collect cmaera data 'silently'
    // text_label is optional
    // text_button is optional - indicates we want the user to select the images presented
    // (otherwise all images are presented) to the given callback function ctx.fn_process()
    // show_qr_frame_guide is optional - if set guides for ideal QR placement are shown
    // help_url is optional - if preset a '?' (and help screen) are shown
    // progress_bar is optional, and is for providing feedback for multi-frame scanning
    // NOTE: not valid to have a label, button[label], help_url, qr frame or progress bar if no ui shown
    // NOTE: atm show_click_btn and help_url are mutually exclusive
    if (!show_ui) {
        JADE_ASSERT(!text_label);
        JADE_ASSERT(!show_click_button);
        JADE_ASSERT(!help_url);
        JADE_ASSERT(qr_frame_guides == QR_GUIDES_NONE);
        JADE_ASSERT(!progress_bar);
    }

    // Config for the camera task
    camera_task_config_t camera_config = { .show_ui = show_ui,
        .text_label = text_label,
        .show_click_button = show_click_button,
        .help_url = help_url,
        .qr_frame_guides = qr_frame_guides,
        .progress_bar = progress_bar,
        .fn_process = fn,
        .ctx = ctx };

    // When running the camera task we set the minimum idle timeout to keep the hw from sleeping too quickly
    // (If the user has set a longer timeout value that is respected)
    idletimer_set_min_timeout_secs(CAMERA_MIN_TIMEOUT_SECS);

    // Run the camera task
#ifdef CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM
    const UBaseType_t mem_caps = MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM;
#else
    const UBaseType_t mem_caps = MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL;
#endif

#if defined(CONFIG_IDF_TARGET_ESP32S3) && defined(CONFIG_RETURN_CAMERA_IMAGES)
    const uint32_t stack_size = 18 * 1024;
#else
    const uint32_t stack_size = 16 * 1024;
#endif

    TaskHandle_t camera_task;
    const BaseType_t retval = xTaskCreatePinnedToCoreWithCaps(&jade_camera_task, "jade_camera", stack_size,
        &camera_config, JADE_TASK_PRIO_CAMERA, &camera_task, JADE_CORE_SECONDARY, mem_caps);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create jade_camera task, xTaskCreatePinnedToCore() returned %d", retval);

    // Await camera exit event
    sync_await_single_event(JADE_EVENT, CAMERA_EXIT, NULL, NULL, NULL, 0);
    vTaskDeleteWithCaps(camera_task);
    jade_camera_stop();

    // Remove the minimum idle timeout
    idletimer_set_min_timeout_secs(0);
}

#else // CONFIG_HAS_CAMERA

void jade_camera_process_images(camera_process_fn_t fn, void* ctx, const bool show_ui, const char* text_label,
    const bool show_click_button, const qr_frame_guides_t qr_frame_guides, const char* help_url,
    progress_bar_t* progress_bar)
{
    JADE_LOGW("No camera supported for this device");
    const char* message[] = { "No camera detected" };
    await_error_activity(message, 1);
}

#endif // CONFIG_HAS_CAMERA
