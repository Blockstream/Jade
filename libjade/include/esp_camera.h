#ifndef _LIBJADE_ESP_CAMERA_H_
#define _LIBJADE_ESP_CAMERA_H_ 1

#include "esp_err.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

typedef enum {
    FRAMESIZE_96X96, // 96x96
    FRAMESIZE_QQVGA, // 160x120
    FRAMESIZE_128X128, // 128x128
    FRAMESIZE_QCIF, // 176x144
    FRAMESIZE_HQVGA, // 240x176
    FRAMESIZE_240X240, // 240x240
    FRAMESIZE_QVGA, // 320x240
    FRAMESIZE_320X320, // 320x320
    FRAMESIZE_CIF, // 400x296
    FRAMESIZE_HVGA, // 480x320
    FRAMESIZE_VGA, // 640x480
    FRAMESIZE_SVGA, // 800x600
    FRAMESIZE_XGA, // 1024x768
    FRAMESIZE_HD, // 1280x720
    FRAMESIZE_SXGA, // 1280x1024
    FRAMESIZE_UXGA, // 1600x1200
    // 3MP Sensors
    FRAMESIZE_FHD, // 1920x1080
    FRAMESIZE_P_HD, //  720x1280
    FRAMESIZE_P_3MP, //  864x1536
    FRAMESIZE_QXGA, // 2048x1536
    // 5MP Sensors
    FRAMESIZE_QHD, // 2560x1440
    FRAMESIZE_WQXGA, // 2560x1600
    FRAMESIZE_P_FHD, // 1080x1920
    FRAMESIZE_QSXGA, // 2560x1920
    FRAMESIZE_5MP, // 2592x1944
    FRAMESIZE_INVALID
} framesize_t;

typedef enum {
    PIXFORMAT_RGB565, // 2BPP/RGB565
    PIXFORMAT_YUV422, // 2BPP/YUV422
    PIXFORMAT_YUV420, // 1.5BPP/YUV420
    PIXFORMAT_GRAYSCALE, // 1BPP/GRAYSCALE
    PIXFORMAT_JPEG, // JPEG/COMPRESSED
    PIXFORMAT_RGB888, // 3BPP/RGB888
    PIXFORMAT_RAW, // RAW
    PIXFORMAT_RGB444, // 3BP2P/RGB444
    PIXFORMAT_RGB555, // 3BP2P/RGB555
} pixformat_t;

/**
 * @brief Configuration structure for camera initialization
 */
typedef struct {
    pixformat_t pixel_format; /*!< Format of the pixel data: PIXFORMAT_ + YUV422|GRAYSCALE|RGB565|JPEG  */
    framesize_t frame_size; /*!< Size of the output image: FRAMESIZE_ + QVGA|CIF|VGA|SVGA|XGA|SXGA|UXGA  */

    int jpeg_quality; /*!< Quality of JPEG output. 0-63 lower means higher quality  */
} camera_config_t;

/**
 * @brief Data structure of camera frame buffer
 */
typedef struct {
    uint8_t* buf; /*!< Pointer to the pixel data */
    size_t len; /*!< Length of the buffer in bytes */
    size_t width; /*!< Width of the buffer in pixels */
    size_t height; /*!< Height of the buffer in pixels */
    pixformat_t format; /*!< Format of the pixel data */
    struct timeval timestamp; /*!< Timestamp since boot of the first DMA buffer of the frame */
} camera_fb_t;

esp_err_t esp_camera_init(const camera_config_t* config);

esp_err_t esp_camera_deinit();

/**
 * @brief Obtain pointer to a frame buffer.
 *
 * @return pointer to the frame buffer
 */
camera_fb_t* esp_camera_fb_get(void);

/**
 * @brief Return the frame buffer to be reused again.
 *
 * @param fb    Pointer to the frame buffer
 */
void esp_camera_fb_return(camera_fb_t* fb);

#endif // _LIBJADE_ESP_CAMERA_H_
