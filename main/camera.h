#ifndef CAMERA_H_
#define CAMERA_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Size of the image as provided by the camera lib
#define CAMERA_IMAGE_WIDTH 320
#define CAMERA_IMAGE_HEIGHT 240

// Function to process images from the camera.
// Should return false if processing incomplete (and so should be called again with the next frame)
// Should return true when processing complete (and the image capture loop/task should exit)
typedef bool (*camera_process_fn_t)(size_t width, size_t height, const uint8_t* data, size_t len, void* ctx);

// Function to process images from the camera.
// Consecutive image frames will be passed to the given callback until
// that function returns true, at which point this function will return.
// If a 'text_label' is passed, a GUI screen is shown, if not, not ...
// If a 'text_button' is passed, the user must click to process an image, otherwise
// every frame captured is passed to the processing function.
void jade_camera_process_images(camera_process_fn_t fn, void* ctx, const char* text_label, const char* text_button);

#endif /* CAMERA_H_ */
