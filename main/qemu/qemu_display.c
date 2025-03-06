#ifndef AMALGAMATED_BUILD
#include "sdkconfig.h"
#if defined(CONFIG_ETH_USE_OPENETH) && defined(CONFIG_HAS_CAMERA)
#include "../camera.h"
#include "../gui.h"
#include "../jade_assert.h"
#include "../ui.h"
#include "../utils/malloc_ext.h"
#include "qemu_display.h"
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/queue.h>
#include <freertos/task.h>

#include "../random.h"
#include <esp_camera.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_netif.h>

#define QEMU_HTTP_PORT 30122
#define QEMU_MAX_WS_SIZE (1024 * 16)
#define DISPLAY_SIZE (CONFIG_DISPLAY_WIDTH * CONFIG_DISPLAY_HEIGHT)
#define CAMERA_IMAGE_SIZE (CAMERA_IMAGE_WIDTH * CAMERA_IMAGE_HEIGHT)

// commands sent
#define LATEST_DISPLAY 0
#define WEBCAM_CAPTURE 1
#define DISABLE_WEBCAM_CAPTURE 2

// commands received
#define PROVIDE_DISPLAY 0
#define LEFT_WHEEL_TRIGGERED 1
#define MIDDLE_CLICK_WHEEL_TRIGGERED 2
#define RIGHT_WHEEL_TRIGGERED 3
#define FRONT_BUTTON_TRIGGERED 4
#define CAMERA_FRAME_INBOUND 12

static struct async_resp_arg* resp_arg = NULL;
static uint8_t* ws_pkt_buf = NULL;
static camera_fb_t* camerafb = NULL;
static uint8_t* camerabuf = NULL;
static uint32_t cameracounter = 0;
static bool requires_flush = true;

static QueueHandle_t cameraqueue = NULL;

static color_t* pixels = NULL;
static uint8_t* packet_payload = NULL;

struct async_resp_arg {
    httpd_handle_t hd;
    int fd;
};

esp_err_t __wrap_esp_camera_init(const camera_config_t* config) { return ESP_OK; }

esp_err_t __wrap_esp_camera_deinit()
{
    if (!resp_arg) {
        return ESP_OK;
    }
    const httpd_handle_t hd = resp_arg->hd;
    const int fd = resp_arg->fd;
    httpd_ws_frame_t ws_pkt = { 0 };
    uint8_t payload_value = DISABLE_WEBCAM_CAPTURE;
    ws_pkt.payload = &payload_value;
    ws_pkt.len = 1;
    ws_pkt.type = HTTPD_WS_TYPE_BINARY;
    httpd_ws_send_frame_async(hd, fd, &ws_pkt);
    return ESP_OK;
}

camera_fb_t* __wrap_esp_camera_fb_get()
{
    if (!resp_arg) {
        return NULL;
    }
    camera_fb_t* fb = camerafb;
    fb->format = PIXFORMAT_GRAYSCALE;
    fb->width = CAMERA_IMAGE_WIDTH;
    fb->height = CAMERA_IMAGE_HEIGHT;
    fb->len = CAMERA_IMAGE_SIZE;
    const httpd_handle_t hd = resp_arg->hd;
    const int fd = resp_arg->fd;
    httpd_ws_frame_t ws_pkt = { 0 };
    uint8_t payload_value = WEBCAM_CAPTURE;
    ws_pkt.payload = &payload_value;
    ws_pkt.len = 1;
    ws_pkt.type = HTTPD_WS_TYPE_BINARY;
    httpd_ws_send_frame_async(hd, fd, &ws_pkt);
    const TickType_t time_start = xTaskGetTickCount();

    while (true) {
        if (xTaskGetTickCount() > time_start + 10000 / portTICK_PERIOD_MS) {
            /* we couldn't get the image in X seconds */
            return NULL;
        }
        if (xQueueReceive(cameraqueue, &fb->buf, 20 / portTICK_PERIOD_MS) == pdTRUE) {
            break;
        }
    }
    return fb;
}

void __wrap_esp_camera_fb_return(camera_fb_t* fb)
{
    // reuse struct and buf until the camera is disabled since we only do one frame
}

void qemu_draw_bitmap(int x, int y, int w, int h, const uint16_t* color_data)
{
    JADE_ASSERT(pixels);
    JADE_ASSERT(color_data);

    JADE_ASSERT(x + w <= CONFIG_DISPLAY_WIDTH + CONFIG_DISPLAY_OFFSET_X);
    JADE_ASSERT(y + h <= CONFIG_DISPLAY_HEIGHT + CONFIG_DISPLAY_OFFSET_Y);

    const int initial_offset = (x - CONFIG_DISPLAY_OFFSET_X) + (y - CONFIG_DISPLAY_OFFSET_Y) * CONFIG_DISPLAY_WIDTH;
    for (int i = 0; i < h; ++i) {
        for (int k = 0; k < w; ++k) {
            pixels[initial_offset + k + (i * CONFIG_DISPLAY_WIDTH)] = ((uint16_t*)color_data)[i * w + k];
        }
    }
    requires_flush = true;
}

#define min(A, B) ((A) < (B) ? (A) : (B))

static void send_async(void* unused)
{
    const httpd_handle_t hd = resp_arg->hd;
    const int fd = resp_arg->fd;
    packet_payload[0] = LATEST_DISPLAY;
    httpd_ws_frame_t ws_pkt = { .type = HTTPD_WS_TYPE_BINARY, .payload = packet_payload };
    size_t tosend = DISPLAY_SIZE;
    while (tosend) {
        /* Given our pixels are 2 bytes we have to send data in multiples of
         * 2 - we can't send half a pixel */
        int sendable_pixels = QEMU_MAX_WS_SIZE - 1;
        sendable_pixels &= ~1;
        ws_pkt.len = min(tosend * 2, sendable_pixels) + 1; /* command byte */
        JADE_ASSERT(ws_pkt.len & 1);
        memcpy(packet_payload + 1, pixels + (DISPLAY_SIZE - tosend), ws_pkt.len - 1);
        if (httpd_ws_send_frame_async(hd, fd, &ws_pkt) != ESP_OK) {
            /* in case of network failure fail gracefully */
            return;
        }
        tosend -= (ws_pkt.len - 1) / 2;
    }
}

void qemu_display_flush(void)
{
    JADE_ASSERT(pixels);
    if (!requires_flush || !resp_arg) {
        return;
    }
    requires_flush = false;
    httpd_queue_work(resp_arg->hd, send_async, resp_arg);
}

void qemu_display_init(void)
{
    JADE_ASSERT(!pixels);
    JADE_ASSERT(!packet_payload);
    pixels = JADE_MALLOC_PREFER_SPIRAM(sizeof(uint16_t) * DISPLAY_SIZE);
    packet_payload = JADE_MALLOC_PREFER_SPIRAM(QEMU_MAX_WS_SIZE);
    resp_arg = JADE_MALLOC_PREFER_SPIRAM(sizeof(struct async_resp_arg));
}

static void setup_async_send(httpd_req_t* req)
{
    resp_arg->hd = req->handle;
    resp_arg->fd = httpd_req_to_sockfd(req);
}

static esp_err_t ws_handler(httpd_req_t* req)
{
    if (req->method == HTTP_GET) {
        cameracounter = 0;
        return ESP_OK;
    }
    setup_async_send(req);

    httpd_ws_frame_t ws_pkt = { 0 };
    ws_pkt.type = HTTPD_WS_TYPE_BINARY;
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);

    if (ret != ESP_OK) {
        return ret;
    }

    JADE_ASSERT(ws_pkt_buf);
    JADE_ASSERT(ws_pkt.len > 0);
    ws_pkt.payload = ws_pkt_buf;

    ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
    if (ret != ESP_OK || (*ws_pkt_buf != 12 && ws_pkt.len != 1)) {
        return ret;
    }

    switch (*ws_pkt_buf) {
    case PROVIDE_DISPLAY:
        JADE_ASSERT(ws_pkt.len == 1);
        packet_payload[0] = LATEST_DISPLAY;
        ws_pkt.payload = packet_payload;
        size_t tosend = DISPLAY_SIZE;
        while (tosend) {
            /* Given our pixels are 2 bytes we have to send data in multiples of
             * 2 - we can't send half a pixel */
            int sendable_pixels = QEMU_MAX_WS_SIZE - 1;
            sendable_pixels &= ~1;
            ws_pkt.len = min(tosend * 2, sendable_pixels) + 1; /* command byte */
            JADE_ASSERT(ws_pkt.len & 1);
            memcpy(packet_payload + 1, pixels + (DISPLAY_SIZE - tosend), ws_pkt.len - 1);
            if (httpd_ws_send_frame(req, &ws_pkt) != ESP_OK) {
                /* in case of network failure fail gracefully */
                return ESP_OK;
            }
            tosend -= (ws_pkt.len - 1) / 2;
        }
        return ESP_OK;
    case LEFT_WHEEL_TRIGGERED:
        JADE_ASSERT(ws_pkt.len == 1);
        gui_prev();
        break;
    case MIDDLE_CLICK_WHEEL_TRIGGERED:
        JADE_ASSERT(ws_pkt.len == 1);
        gui_wheel_click();
        break;
    case RIGHT_WHEEL_TRIGGERED:
        JADE_ASSERT(ws_pkt.len == 1);
        gui_next();
        break;
    case FRONT_BUTTON_TRIGGERED:
        JADE_ASSERT(ws_pkt.len == 1);
        gui_front_click();
        break;
    case CAMERA_FRAME_INBOUND:
        JADE_ASSERT(ws_pkt.len > 1);
        memcpy(camerabuf + cameracounter, ws_pkt_buf + 1, ws_pkt.len - 1);
        if (cameracounter + (ws_pkt.len - 1) == CAMERA_IMAGE_SIZE) {
            xQueueSend(cameraqueue, &camerabuf, portMAX_DELAY);
            cameracounter = 0;
        } else {
            cameracounter += ws_pkt.len - 1;
        }
        break;
    default:
        JADE_LOGE("Unexpected byte %d received by ws client for request len %d", *ws_pkt_buf, ws_pkt.len);
        JADE_ASSERT(false);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static const httpd_uri_t ws
    = { .uri = "/ws", .method = HTTP_GET, .handler = ws_handler, .user_ctx = NULL, .is_websocket = true };

extern const uint8_t displayhtmlstart[] asm("_binary_display_html_gz_start");
extern const uint8_t displayhtmlend[] asm("_binary_display_html_gz_end");

esp_err_t home_handler(httpd_req_t* req)
{
    httpd_resp_set_type(req, HTTPD_TYPE_TEXT);
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_send(req, (char*)displayhtmlstart, displayhtmlend - displayhtmlstart);
    return ESP_OK;
}

extern const uint8_t jadepngstart[] asm("_binary_jade_png_gz_start");
extern const uint8_t jadepngend[] asm("_binary_jade_png_gz_end");

esp_err_t png_handler(httpd_req_t* req)
{
    httpd_resp_set_type(req, "image/png");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_send(req, (char*)jadepngstart, jadepngend - jadepngstart);
    return ESP_OK;
}

static const httpd_uri_t webpage
    = { .uri = "/", .method = HTTP_GET, .handler = home_handler, .user_ctx = NULL, .is_websocket = false };

static const httpd_uri_t png
    = { .uri = "/jade.png", .method = HTTP_GET, .handler = png_handler, .user_ctx = NULL, .is_websocket = false };

bool qemu_start_display_webserver(void)
{
    httpd_handle_t server = NULL;
    JADE_ASSERT(pixels);
    JADE_ASSERT(packet_payload);
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.keep_alive_enable = true;
    config.server_port = QEMU_HTTP_PORT;
    ws_pkt_buf = JADE_MALLOC_PREFER_SPIRAM(CAMERA_IMAGE_SIZE + 1);

    cameraqueue = xQueueCreate(1, sizeof(void*));
    JADE_ASSERT(cameraqueue);

    JADE_ASSERT(!camerafb);
    JADE_ASSERT(!camerabuf);

    camerafb = JADE_MALLOC_PREFER_SPIRAM(sizeof(camera_fb_t));
    camerabuf = JADE_MALLOC_PREFER_SPIRAM(CAMERA_IMAGE_SIZE);

    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_register_uri_handler(server, &ws);
        httpd_register_uri_handler(server, &png);
        httpd_register_uri_handler(server, &webpage);
        return true;
    }

    return false;
}
#endif
#endif // AMALGAMATED_BUILD
