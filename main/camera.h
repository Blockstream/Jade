#ifndef CAMERA_H_
#define CAMERA_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// An extracted QR code string
#define QR_MAX_STRING_LENGTH 256

struct quirc;
typedef struct _qr_data_t qr_data_t;

// Function to tell whether the extracted qr data is valid for the callers purposes
typedef bool (*qr_valid_fn_t)(qr_data_t* qr_data);

// Function to process images from the camera.
// Should return false if processing incomplete (and so should be called again with the next frame)
// Should return true when processing complete (and the image capture loop/task should exit)
typedef bool (*camera_process_fn_t)(size_t width, size_t height, const uint8_t* data, size_t len, void* ctx);

struct _qr_data_t {
    char strdata[QR_MAX_STRING_LENGTH];
    size_t len;

    // An optional validation function - if included, scanning will only stop
    // and populate the string fields if the validation returns true.
    // If NULL, any successfully extracted string is sufficient.
    qr_valid_fn_t is_valid;

    // Arbitrary context that may be required by the validation function.
    void* ctx;

    // Cached internal quirc struct - caller should set to NULL
    struct quirc* q;
};

// Function to scan a qr code with the camera.
// Any scanned/extracted string (which passes any additional validity check)
// is written to the passed qr_data struct, and the function returns true.
// The fucntion returns false if scanning is aborted, and no string is returned.
bool jade_camera_scan_qr(qr_data_t* qr_data);

// Function to process images from the camera.
// Consecutive image frames will be passed to the given callback until
// that function returns true, at which point this function will return.
// If a 'text_label' is passed, a GUI screen is shown, if not, not ...
// If a 'text_button' is passed, the user must click to process an image, otherwise
// every frame captured is passed to the processing function.
void jade_camera_process_images(camera_process_fn_t fn, void* ctx, const char* text_label, const char* text_button);

#endif /* CAMERA_H_ */
