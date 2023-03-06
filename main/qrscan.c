#include <quirc.h>
#include <string.h>

#include "camera.h"
#include "jade_assert.h"
#include "qrscan.h"
#include "sensitive.h"
#include "utils/malloc_ext.h"

// Inspect qrcodes and try to extract payload - whether any were seen and any
// string data extracted are stored in the qr_data struct passed.
static bool qr_extract_payload(qr_data_t* qr_data)
{
    JADE_ASSERT(qr_data);
    JADE_ASSERT(qr_data->q);
    JADE_ASSERT(qr_data->ds);

    qr_data->data[0] = '\0';
    qr_data->len = 0;

    const int count = quirc_count(qr_data->q);
    if (count <= 0) {
        return false;
    }
    JADE_LOGI("Detected %d QR codes in image.", count);

    // Store the first string we manage to extract - initialise to empty string.
    struct quirc_data data;
    SENSITIVE_PUSH(&data, sizeof(data));

    // Look for a string
    for (int i = 0; i < count; ++i) {
        struct quirc_code code;
        quirc_extract(qr_data->q, i, &code);

        const quirc_decode_error_t error_status = quirc_decode(&code, &data, qr_data->ds);
        if (error_status != QUIRC_SUCCESS) {
            JADE_LOGW("QUIRC error %s", quirc_strerror(error_status));
        } else if (data.data_type == QUIRC_DATA_TYPE_KANJI) {
            JADE_LOGW("QUIRC unexpected data type: %d", data.data_type);
        } else if (!data.payload_len) {
            JADE_LOGW("QUIRC empty string");
        } else if (data.payload_len >= sizeof(qr_data->data)) {
            JADE_LOGW("QUIRC data too long to handle: %u", data.payload_len);
            JADE_ASSERT(data.payload_len <= sizeof(data.payload));
        } else {
            // The payload appears to be a nul terminated string, but the
            // 'payload_len' seems to be the string length not including that
            // terminator.
            // To avoid any confusion or grey areas, we copy the bytes,
            // and then explicitly add the nul terminator ourselves.
            memcpy(qr_data->data, data.payload, data.payload_len);
            qr_data->data[data.payload_len] = '\0';
            qr_data->len = data.payload_len;
            SENSITIVE_POP(&data);
            return true;
        }
    }
    SENSITIVE_POP(&data);
    return false;
}

// Look for qr-codes, and if found extract any string data into the camera_data passed
static bool qr_recognize(
    const size_t width, const size_t height, const uint8_t* data, const size_t len, void* ctx_qr_data)
{
    JADE_ASSERT(data);
    JADE_ASSERT(ctx_qr_data);
    JADE_ASSERT(len == width * height);

    qr_data_t* const qr_data = (qr_data_t*)ctx_qr_data;
    JADE_ASSERT(qr_data);
    JADE_ASSERT(qr_data->q);

    // Checked qr image buffer exists and is the correct size
    int quirc_width = 0, quirc_height = 0;
    uint8_t* const quirc_image = quirc_begin(qr_data->q, &quirc_width, &quirc_height);
    JADE_ASSERT(quirc_image);
    JADE_ASSERT(quirc_width == width);
    JADE_ASSERT(quirc_height == height);

    // Try to interpret image as a QR-code
    memcpy(quirc_image, data, len);
    quirc_end(qr_data->q);

    // If no QR data can be recognised/extracted, return false
    if (!qr_extract_payload(qr_data) || !qr_data->len) {
        qr_data->len = 0;
        return false;
    }

    // If we have extracted data and we have an additional validation
    // function, run that function now - clear the data and return false
    // if it fails.  Otherwise all good.
    if (qr_data->is_valid && !qr_data->is_valid(qr_data)) {
        qr_data->len = 0;
        return false;
    }

    // QR data was extracted and validated - return true
    return true;
}

#ifdef CONFIG_DEBUG_MODE
// Function to scan single image - may be useful for testing
bool scan_qr(const size_t width, const size_t height, const uint8_t* data, const size_t len, qr_data_t* qr_data)
{
    JADE_ASSERT(qr_data);
    JADE_ASSERT(!qr_data->q);

    // Create the quirc structs
    qr_data->q = quirc_new();
    JADE_ASSERT(qr_data->q);
    qr_data->ds = JADE_MALLOC_DRAM(sizeof(struct datastream));
    JADE_ASSERT(qr_data->ds);

    // Also correctly size the internal image buffer
    const int qret = quirc_resize(qr_data->q, width, height);
    JADE_ASSERT(qret == 0);
    qr_data->len = 0;

    const bool ret = qr_recognize(width, height, data, len, qr_data);

    // Destroy the quirc structs created above
    quirc_destroy(qr_data->q);
    qr_data->q = NULL;
    free(qr_data->ds);
    qr_data->ds = NULL;

    // Any scanned qr code will be in the qr_data passed
    return ret && qr_data->len > 0;
}
#endif // CONFIG_DEBUG_MODE

// Main entry point to run camera task to capture frames and scan each
// image until a valid qr-code is found ('valid' as defined by the caller).
bool jade_camera_scan_qr(qr_data_t* qr_data, const char* title, const char* text_label)
{
    JADE_ASSERT(qr_data);
    JADE_ASSERT(title);
    JADE_ASSERT(text_label);

// At the moment camera only supported by Jade devices
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    // Create the quirc structs (reused for each frame) - destroyed below
    JADE_ASSERT(!qr_data->q);
    qr_data->q = quirc_new();
    JADE_ASSERT(qr_data->q);
    qr_data->ds = JADE_MALLOC_DRAM(sizeof(struct datastream));
    JADE_ASSERT(qr_data->ds);

    // Also correctly size the internal image buffer since we know the size of the camera images
    // This image buffer is then reused for every camera image frame processed.
    const int qret = quirc_resize(qr_data->q, CAMERA_IMAGE_WIDTH, CAMERA_IMAGE_HEIGHT);
    JADE_ASSERT(qret == 0);
    qr_data->len = 0;

    // Run the camera task trying to interpet frames as qr-codes
    jade_camera_process_images(qr_recognize, qr_data, title, text_label, NULL, qr_data->progress_bar);

    // Destroy the quirc structs created above
    quirc_destroy(qr_data->q);
    qr_data->q = NULL;
    free(qr_data->ds);
    qr_data->ds = NULL;

    // Any scanned qr code will be in the qr_data passed
    return qr_data->len > 0;
#else // CONFIG_BOARD_TYPE_JADE || CONFIG_BOARD_TYPE_JADE_V1_1
    JADE_LOGW("No camera supported for this device");
    await_error_activity("No camera detected");
    return false;
#endif
}
