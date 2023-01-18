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
#include <esp_timer.h>
#include <tftspi.h>

#define QEMU_HTTP_PORT 30122
#define WS_DISPLAY_TIMEOUT 100000

static color_t* display = NULL;
static struct async_resp_arg* resp_arg = NULL;
static uint8_t* ws_pkt_buf = NULL;
static camera_fb_t* camerafb = NULL;
static uint8_t* camerabuf = NULL;
static uint32_t cameracounter = 0;
static esp_timer_handle_t displaytimer;

static QueueHandle_t cameraqueue = NULL;

struct async_resp_arg {
    httpd_handle_t hd;
    int fd;
};

static void display_timeout_fn(void* unused)
{
    const httpd_handle_t hd = resp_arg->hd;
    const int fd = resp_arg->fd;
    httpd_ws_frame_t ws_pkt = { 0 };
    ws_pkt.payload = (uint8_t*)display;
    ws_pkt.len = 240 * 135 * sizeof(color_t) + 1;
    ws_pkt.type = HTTPD_WS_TYPE_BINARY;
    httpd_ws_send_frame_async(hd, fd, &ws_pkt);
}

static void ws_async_send(void)
{
    if (!resp_arg) {
        return;
    }
    if (esp_timer_is_active(displaytimer)) {
        const esp_err_t ret = esp_timer_restart(displaytimer, WS_DISPLAY_TIMEOUT);
        if (ret == ESP_OK) {
            return;
        }
    }
    // timer was not active or failed to restart
    const esp_err_t ret = esp_timer_start_once(displaytimer, WS_DISPLAY_TIMEOUT);
    JADE_ASSERT(ret == ESP_OK);
}

esp_err_t __wrap_esp_camera_init(const camera_config_t* config) { return ESP_OK; }

esp_err_t __wrap_esp_camera_deinit()
{
    const httpd_handle_t hd = resp_arg->hd;
    const int fd = resp_arg->fd;
    httpd_ws_frame_t ws_pkt = { 0 };
    uint8_t payload_value = 2; /* disable webcam capture */
    ws_pkt.payload = &payload_value;
    ws_pkt.len = 1;
    ws_pkt.type = HTTPD_WS_TYPE_BINARY;
    httpd_ws_send_frame_async(hd, fd, &ws_pkt);
    return ESP_OK;
}

camera_fb_t* __wrap_esp_camera_fb_get()
{
    camera_fb_t* fb = camerafb;
    fb->format = PIXFORMAT_GRAYSCALE; // 1BPP/GRAYSCALE
    fb->width = CAMERA_IMAGE_WIDTH;
    fb->height = CAMERA_IMAGE_HEIGHT;
    const size_t image_size = sizeof(uint8_t[CAMERA_IMAGE_WIDTH / 2][CAMERA_IMAGE_HEIGHT / 2]);
    fb->len = 4 * image_size; // twice width and twice height
    const httpd_handle_t hd = resp_arg->hd;
    const int fd = resp_arg->fd;
    httpd_ws_frame_t ws_pkt = { 0 };
    uint8_t payload_value = 1;
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

static void set_color(color_t* position, color_t color, size_t num)
{
    for (color_t* i = position; i < (position + num); ++i) {
        *i = color;
    }
}

void __wrap_send_data(int x1, int y1, int x2, int y2, uint32_t len, color_t* buf)
{
    if (!display) {
        return;
    }
    color_t* const leftcorner = ((color_t*)(((uint8_t*)display) + 1)) + (x1 - 40) + ((y1 - 53) * 240);
    size_t color_counter = 0;
    for (int v = 0; v < y2 - y1; ++v) {
        color_t* position = leftcorner + 240 * v;
        for (color_t* i = position; i < position + (x2 - x1); ++i, ++color_counter) {
            *i = buf[color_counter];
        }
    }

    if (y1 == 187) {
        // a bit ugly: we only send the display update when it is the last row
        // and we force the update rather than do the async timeout based one
        display_timeout_fn(NULL);
    } else {
        ws_async_send();
    }
}

void __wrap_TFT_pushColorRep(int x1, int y1, int x2, int y2, color_t data, uint32_t len)
{
    if (!display) {
        return;
    }

    color_t* const leftcorner = ((color_t*)(((uint8_t*)display) + 1)) + (x1 - 40) + ((y1 - 53) * 240);
    for (int i = 0; i < (y2 - y1) + 1; ++i) {
        set_color(leftcorner + (240 * i), data, (x2 - x1) + 1);
    }
    ws_async_send();
}

void __wrap_drawPixel(int16_t x, int16_t y, color_t color, uint8_t sel)
{
    if (!display) {
        return;
    }
    *(((color_t*)(((uint8_t*)display) + 1)) + (x - 40) + ((y - 53) * 240)) = color;
    ws_async_send();
}

static void setup_async_send(httpd_req_t* req)
{
    if (!resp_arg) {
        resp_arg = JADE_MALLOC_PREFER_SPIRAM(sizeof(struct async_resp_arg));
    }
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
    case 0:
        JADE_ASSERT(ws_pkt.len == 1);
        ws_pkt.len = 240 * 135 * sizeof(color_t) + 1;
        ws_pkt.payload = (uint8_t*)display;
        return httpd_ws_send_frame(req, &ws_pkt);
    case 1:
        JADE_ASSERT(ws_pkt.len == 1);
        gui_prev();
        break;
    case 2:
        JADE_ASSERT(ws_pkt.len == 1);
        gui_wheel_click();
        break;
    case 3:
        JADE_ASSERT(ws_pkt.len == 1);
        gui_next();
        break;
    case 4:
        JADE_ASSERT(ws_pkt.len == 1);
        gui_front_click();
        break;
    case 12:
        JADE_ASSERT(ws_pkt.len > 1);
        memcpy(camerabuf + cameracounter, ws_pkt_buf + 1, ws_pkt.len - 1);
        if (cameracounter + (ws_pkt.len - 1) == 320 * 240) {
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
    JADE_ASSERT(!display);
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    display = JADE_MALLOC_PREFER_SPIRAM(240 * 135 * sizeof(color_t) + 1);
    ((uint8_t*)display)[0] = 0;
    config.server_port = QEMU_HTTP_PORT;
    const size_t image_size = sizeof(uint8_t[CAMERA_IMAGE_WIDTH / 2][CAMERA_IMAGE_HEIGHT / 2]);
    ws_pkt_buf = JADE_MALLOC_PREFER_SPIRAM(image_size * 4 + 1);

    cameraqueue = xQueueCreate(1, sizeof(void*));
    JADE_ASSERT(cameraqueue);

    JADE_ASSERT(!camerafb);
    JADE_ASSERT(!camerabuf);

    camerafb = JADE_MALLOC_PREFER_SPIRAM(sizeof(camera_fb_t));
    camerabuf = JADE_MALLOC_PREFER_SPIRAM(320 * 240);

    const esp_timer_create_args_t timer_args = {
        .callback = &display_timeout_fn,
    };

    esp_timer_create(&timer_args, &displaytimer);

    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_register_uri_handler(server, &ws);
        httpd_register_uri_handler(server, &png);
        httpd_register_uri_handler(server, &webpage);
        return true;
    }

    return false;
}
#endif
