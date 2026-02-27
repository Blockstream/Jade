#include "esp_camera.h"
#include "camera.h"
#include "jade_assert.h"
#include "jade_log.h"
#include "sdkconfig.h"
#include <string.h>
#include <time.h>

#ifdef CONFIG_LIBJADE_CAMERA

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>

static uint8_t _cam_frame_buffer[CAMERA_IMAGE_WIDTH * CAMERA_IMAGE_HEIGHT];
static uint64_t _cam_frame_count = 0;
static bool _cam_stopped = false;
static pthread_mutex_t _cam_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t _cam_cond = PTHREAD_COND_INITIALIZER;

// Called by the host to push a grayscale camera frame.
// data must be CAMERA_IMAGE_WIDTH * CAMERA_IMAGE_HEIGHT bytes of 8-bit grayscale.
bool libjade_push_camera_frame(const uint8_t* data, const size_t len)
{
    if (!data || len != sizeof(_cam_frame_buffer)) {
        return false;
    }
    pthread_mutex_lock(&_cam_mutex);
    if (!_cam_stopped) {
        memcpy(_cam_frame_buffer, data, len);
        _cam_frame_count++;
        pthread_cond_signal(&_cam_cond);
    }
    pthread_mutex_unlock(&_cam_mutex);
    return true;
}

esp_err_t esp_camera_init(const camera_config_t* config)
{
    JADE_ASSERT(config);
    JADE_ASSERT(config->pixel_format == PIXFORMAT_GRAYSCALE);
    JADE_ASSERT(config->frame_size == FRAMESIZE_QVGA);
    pthread_mutex_lock(&_cam_mutex);
    _cam_frame_count = 0;
    _cam_stopped = false;
    pthread_mutex_unlock(&_cam_mutex);
    return ESP_OK;
}

esp_err_t esp_camera_deinit(void)
{
    pthread_mutex_lock(&_cam_mutex);
    _cam_stopped = true;
    pthread_cond_broadcast(&_cam_cond);
    pthread_mutex_unlock(&_cam_mutex);
    return ESP_OK;
}

camera_fb_t* esp_camera_fb_get(void)
{
    static camera_fb_t fb = {
        .buf = _cam_frame_buffer,
        .len = sizeof(_cam_frame_buffer),
        .width = CAMERA_IMAGE_WIDTH,
        .height = CAMERA_IMAGE_HEIGHT,
        .format = PIXFORMAT_GRAYSCALE,
    };
    gettimeofday(&fb.timestamp, NULL);
    pthread_mutex_lock(&_cam_mutex);
    if (_cam_stopped) {
        pthread_mutex_unlock(&_cam_mutex);
        return NULL;
    }
    const uint64_t count_before = _cam_frame_count;
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += 100 * 1000000; // 100 ms
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    while (_cam_frame_count == count_before && !_cam_stopped) {
        const int rc = pthread_cond_timedwait(&_cam_cond, &_cam_mutex, &deadline);
        if (rc == ETIMEDOUT) {
            break;
        }
    }
    pthread_mutex_unlock(&_cam_mutex);
    // Always return the buffer (possibly stale/zero if no frame arrived yet),
    // matching the original v4l2 behaviour of never returning NULL on timeout.
    return &fb;
}

void esp_camera_fb_return(camera_fb_t* fb) { /* static buffer, nothing to free */ }

#else

esp_err_t esp_camera_init(const camera_config_t* config) { return ESP_FAIL; }
esp_err_t esp_camera_deinit() { return ESP_FAIL; }
camera_fb_t* esp_camera_fb_get(void) { return NULL; }
void esp_camera_fb_return(camera_fb_t* fb) {}
bool libjade_push_camera_frame(const uint8_t* data, const size_t len) { return false; }

static const uint8_t* debug_image_data = NULL;
void camera_set_debug_image(const uint8_t* data, const size_t len)
{
    JADE_ASSERT(!data == !len);
    JADE_ASSERT(!len || len == CAMERA_IMAGE_WIDTH * CAMERA_IMAGE_HEIGHT);
    debug_image_data = data;
}

void jade_camera_process_images(camera_process_fn_t fn, void* ctx, const bool show_ui, const char* text_label,
    const bool show_click_button, const qr_guide_type_t qr_guide_type, const char* help_url,
    progress_bar_t* progress_bar)
{
    if (debug_image_data) {
        if (!fn(CAMERA_IMAGE_WIDTH, CAMERA_IMAGE_HEIGHT, debug_image_data, CAMERA_IMAGE_WIDTH * CAMERA_IMAGE_HEIGHT,
                ctx)) {
            JADE_LOGW("User callback returned false for fixed debug image - exiting camera regardless");
        }
    }
}

void camera_stop(void) {}

#endif // CONFIG_LIBJADE_CAMERA
