#ifndef CAMERA_H_
#define CAMERA_H_

#include <ui.h>

#include <sdkconfig.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Size of the image as provided by the camera - note this should be consistent
// with CAMERA_IMAGE_RESOLUTION !  TODO: fetch from Kconfig?
#ifdef CONFIG_IDF_TARGET_ESP32S3
#define CAMERA_IMAGE_WIDTH 640
#define CAMERA_IMAGE_HEIGHT 480
#else
#define CAMERA_IMAGE_WIDTH 320
#define CAMERA_IMAGE_HEIGHT 240
#endif

// Function to process images from the camera.
// Should return false if processing incomplete (and so should be called again with the next frame)
// Should return true when processing complete (and the image capture loop/task should exit)
typedef bool (*camera_process_fn_t)(size_t width, size_t height, const uint8_t* data, size_t len, void* ctx);

#ifdef CONFIG_DEBUG_MODE
// Debug/testing function to cache an image - the next time the camera is called
// a frame is captured but is ignored/discarded and this image presented instead.
// Call with NULL/0 to remove debug image.
// NOTE: the image is not owned here.
void camera_set_debug_image(const uint8_t* data, size_t len);
#endif

// Function to process images from the camera.
// Consecutive image frames will be passed to the given callback until
// that function returns true, at which point this function will return.
// If show_ui is set, a GUI screen is shown, if not, not ...
// If a 'text_label' is passed it is shown with the camera image.
// If 'show_click_button'' is passed, the user must click to process an image, otherwise
// every frame captured is passed to the processing function.
// 'show_qr_frame_guide' can be passed to indicate the ideal QR code placement
// 'help_url' can be passed to link to a help url/resource.
// 'progress_bar' can be passed to give feedback on multi-frame scanning.
void jade_camera_process_images(camera_process_fn_t fn, void* ctx, bool show_ui, const char* text_label,
    bool show_click_button, bool show_qr_frame_guide, const char* help_url, progress_bar_t* progress_bar);

#endif /* CAMERA_H_ */
