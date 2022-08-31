#ifndef CAMERA_H_
#define CAMERA_H_

#include <stdbool.h>
#include <stddef.h>

// An extracted QR code string
#define QR_MAX_STRING_LENGTH 256

struct quirc;
typedef struct _qr_data_t qr_data_t;

// Function to tell whether the extracted qr data is valid for the callers purposes
typedef bool (*qr_valid_fn_t)(qr_data_t* qr_data);

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

#endif /* CAMERA_H_ */
