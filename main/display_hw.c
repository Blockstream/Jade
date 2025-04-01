#ifndef AMALGAMATED_BUILD
#include "display_hw.h"

#include "display.h"

#include "jade_assert.h"
#include "jade_tasks.h"
#include "utils/malloc_ext.h"
#include "utils/util.h"
#include <driver/gpio.h>

#include <esp_lcd_panel_io.h>
#include <esp_lcd_panel_ops.h>
#include <esp_lcd_panel_vendor.h>

#include "freertos/semphr.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>

/*
 * Nota bene:
 * All displays are at least 240x135 (min display size)
 *
 * T display S3 is different in that it does not use the SPI interface.
 * All the other devices use SPI.
 *
 * M5 Core S3 is different in that in doesn't have buttons so we are forced to
 * leave some space at the bottom for virtual buttons.
 *
 * */

static TaskHandle_t* gui_h = NULL;
static SemaphoreHandle_t init_done = NULL;

#ifdef CONFIG_BOARD_TYPE_TTGO_TDISPLAYS3

static void set_gpio_high(gpio_num_t num)
{
    gpio_config_t bk_gpio_config = { .mode = GPIO_MODE_OUTPUT, .pin_bit_mask = 1ULL << num };
    ESP_ERROR_CHECK(gpio_config(&bk_gpio_config));
    ESP_ERROR_CHECK(gpio_set_level(num, 1));
}

#else

#include <driver/spi_common.h>

#endif

#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER_DOUBLE
static color_t** _disp_buf = NULL;
static uint8_t buffer_selected = 0;
#endif // CONFIG_DISPLAY_FULL_FRAME_BUFFER_DOUBLE
static color_t* disp_buf = NULL;
#if CONFIG_PIN_NUM_DATA0 != -1
#define TRANSFER_BUFFER_LINES CONFIG_DISPLAY_HEIGHT
#else // not i80, thus SPI - use fewer lines, save dram
#define TRANSFER_BUFFER_LINES 8
#endif // CONFIG_PIN_NUM_DATA0
#else
#define TRANSFER_BUFFER_LINES 1
#endif // CONFIG_DISPLAY_FULL_FRAME_BUFFER

#define TRANSFER_QUEUE_DEPTH 8

#if defined(CONFIG_DISPLAY_FULL_FRAME_BUFFER) && !defined(CONFIG_DISPLAY_FULL_FRAME_BUFFER_DOUBLE)
static bool color_trans_done(esp_lcd_panel_io_handle_t panel_io, esp_lcd_panel_io_event_data_t* edata, void* user_ctx)
{
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    vTaskNotifyGiveFromISR(*gui_h, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }
    return false;
}
#endif

static esp_lcd_panel_handle_t ph = NULL;

static void esp_lcd_init(void* _ignored)
{
#ifdef ESP_PLATFORM
    esp_lcd_panel_io_handle_t io_handle = NULL;

#if CONFIG_DISPLAY_PIN_BL != -1
    gpio_config_t bk_gpio_config = { .mode = GPIO_MODE_OUTPUT, .pin_bit_mask = 1ULL << CONFIG_DISPLAY_PIN_BL };
    ESP_ERROR_CHECK(gpio_config(&bk_gpio_config));
    ESP_ERROR_CHECK(gpio_set_level(CONFIG_DISPLAY_PIN_BL, 0));
#endif

#if CONFIG_PIN_NUM_DATA0 != -1
    set_gpio_high(CONFIG_LCD_POWER_PIN_NUM);
    set_gpio_high(CONFIG_LCD_RD_PIN_NUM);
    set_gpio_high(CONFIG_LCD_BACKLIGHT_PIN_NUM);

    esp_lcd_i80_bus_handle_t i80_bus = NULL;
    esp_lcd_i80_bus_config_t bus_config = {
            .clk_src = LCD_CLK_SRC_DEFAULT,
            .dc_gpio_num = CONFIG_PIN_NUM_DC,
            .wr_gpio_num = CONFIG_PIN_NUM_WR,
            .data_gpio_nums = {
                CONFIG_PIN_NUM_DATA0,
                CONFIG_PIN_NUM_DATA1,
                CONFIG_PIN_NUM_DATA2,
                CONFIG_PIN_NUM_DATA3,
                CONFIG_PIN_NUM_DATA4,
                CONFIG_PIN_NUM_DATA5,
                CONFIG_PIN_NUM_DATA6,
                CONFIG_PIN_NUM_DATA7,
            },
            .bus_width = 8,
            .max_transfer_bytes = CONFIG_DISPLAY_WIDTH * TRANSFER_BUFFER_LINES * sizeof(uint16_t) + 8,
            .psram_trans_align = CONFIG_PSRAM_DATA_ALIGNMENT,
            .sram_trans_align = 4,
    };

    ESP_ERROR_CHECK(esp_lcd_new_i80_bus(&bus_config, &i80_bus));
    esp_lcd_panel_io_i80_config_t io_config = {
            .cs_gpio_num = CONFIG_PIN_NUM_CS,
            .pclk_hz = CONFIG_LCD_PIXEL_CLOCK_HZ,
            .trans_queue_depth = TRANSFER_QUEUE_DEPTH,
            .dc_levels = {
                .dc_idle_level = 0,
                .dc_cmd_level = 0,
                .dc_dummy_level = 0,
                .dc_data_level = 1,
            },
            .lcd_cmd_bits = CONFIG_LCD_CMD_BITS,
            .lcd_param_bits = CONFIG_LCD_PARAM_BITS,
#if defined(CONFIG_DISPLAY_FULL_FRAME_BUFFER) && !defined(CONFIG_DISPLAY_FULL_FRAME_BUFFER_DOUBLE)
            .on_color_trans_done = color_trans_done,
#endif

    };

    ESP_ERROR_CHECK(esp_lcd_new_panel_io_i80(i80_bus, &io_config, &io_handle));
    esp_lcd_panel_dev_config_t panel_config = {
        .reset_gpio_num = CONFIG_PIN_NUM_RST,
        .bits_per_pixel = 16,
    };
#else // not i80, thus SPI
    spi_bus_config_t buscfg = {
        .sclk_io_num = CONFIG_DISPLAY_PIN_CLK,
        .mosi_io_num = CONFIG_DISPLAY_PIN_MOSI,
        .miso_io_num = CONFIG_DISPLAY_PIN_MISO,
        .quadwp_io_num = GPIO_NUM_NC,
        .quadhd_io_num = GPIO_NUM_NC,
        .max_transfer_sz = CONFIG_DISPLAY_WIDTH * TRANSFER_BUFFER_LINES * sizeof(uint16_t) + 8,
    };

    ESP_ERROR_CHECK(spi_bus_initialize(CONFIG_DISPLAY_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO));

    esp_lcd_panel_io_spi_config_t io_config
        = {.dc_gpio_num = CONFIG_DISPLAY_PIN_DC,
              .cs_gpio_num = CONFIG_DISPLAY_PIN_CS,
              .pclk_hz = CONFIG_DISPLAY_SPI_CLOCK,
              .lcd_cmd_bits = 8,
              .lcd_param_bits = 8,
              .spi_mode = 0,
#if defined(CONFIG_DISPLAY_FULL_FRAME_BUFFER) && !defined(CONFIG_DISPLAY_FULL_FRAME_BUFFER_DOUBLE)
              .on_color_trans_done = color_trans_done,
#endif
              .trans_queue_depth = TRANSFER_QUEUE_DEPTH,
          };

    ESP_ERROR_CHECK(
        esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)CONFIG_DISPLAY_SPI_HOST, &io_config, &io_handle));
    esp_lcd_panel_dev_config_t panel_config = {
        .reset_gpio_num = CONFIG_DISPLAY_PIN_RST,
#ifdef CONFIG_DCS_ADDRESS_MODE_BGR_SELECTED
        .rgb_endian = LCD_RGB_ENDIAN_BGR,
#endif
        .bits_per_pixel = 16,
    };
#endif // else CONFIG_PIN_NUM_DATA0

    ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(io_handle, &panel_config, &ph));

#if CONFIG_DISPLAY_PIN_BL != -1
    ESP_ERROR_CHECK(gpio_set_level(CONFIG_DISPLAY_PIN_BL, 1));
#endif

    ESP_ERROR_CHECK(esp_lcd_panel_reset(ph));
    ESP_ERROR_CHECK(esp_lcd_panel_init(ph));

#ifdef CONFIG_DCS_ADDRESS_MODE_SWAP_XY_SELECTED
    ESP_ERROR_CHECK(esp_lcd_panel_swap_xy(ph, true));
#endif

#ifdef CONFIG_DCS_ADDRESS_MODE_MIRROR_X_SELECTED
#define X_FLIPPED true
#else
#define X_FLIPPED false
#endif

#ifdef CONFIG_DCS_ADDRESS_MODE_MIRROR_Y_SELECTED
#define Y_FLIPPED true
#else
#define Y_FLIPPED false
#endif
    ESP_ERROR_CHECK(esp_lcd_panel_mirror(ph, X_FLIPPED, Y_FLIPPED));

#ifdef CONFIG_DISPLAY_INVERT
    ESP_ERROR_CHECK(esp_lcd_panel_invert_color(ph, true));
#endif

    ESP_ERROR_CHECK(esp_lcd_panel_set_gap(ph, CONFIG_DISPLAY_OFFSET_X, CONFIG_DISPLAY_OFFSET_Y));

    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(ph, true));
#else
#define X_FLIPPED false
#define Y_FLIPPED false
    ph = (void*)1;
#endif
    xSemaphoreGive(init_done);
    for (;;) {
        vTaskDelay(portMAX_DELAY);
    }
}

bool display_hw_flip_orientation(const bool flipped_orientation)
{
    ESP_ERROR_CHECK(esp_lcd_panel_mirror(ph, flipped_orientation ^ X_FLIPPED, flipped_orientation ^ Y_FLIPPED));
    return flipped_orientation;
}

void display_hw_init(TaskHandle_t* gui_handle)
{
    JADE_ASSERT(gui_handle);
    JADE_ASSERT(!*gui_handle);
    JADE_ASSERT(!init_done);
    init_done = xSemaphoreCreateBinary();
    JADE_ASSERT(init_done);

    gui_h = gui_handle;

#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER_DOUBLE
    _disp_buf = JADE_MALLOC_PREFER_SPIRAM(2 * sizeof(color_t*));
    _disp_buf[0]
        = JADE_MALLOC_PREFER_SPIRAM_ALIGNED(CONFIG_DISPLAY_WIDTH * CONFIG_DISPLAY_HEIGHT * sizeof(color_t), 16);
    _disp_buf[1]
        = JADE_MALLOC_PREFER_SPIRAM_ALIGNED(CONFIG_DISPLAY_WIDTH * CONFIG_DISPLAY_HEIGHT * sizeof(color_t), 16);
    disp_buf = _disp_buf[0];
#endif
#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
#ifndef CONFIG_DISPLAY_FULL_FRAME_BUFFER_DOUBLE
    disp_buf = JADE_MALLOC_PREFER_SPIRAM_ALIGNED(CONFIG_DISPLAY_WIDTH * CONFIG_DISPLAY_HEIGHT * sizeof(color_t), 16);
#endif
#endif
    /* We have to initialize the lcd on the same core we are going to call it from,
     * see https://github.com/espressif/esp-idf/issues/12347
     * otherwise we could run the esp_lcd_init function directly */
    TaskHandle_t lcdInitTaskHandle;
    xTaskCreatePinnedToCore(
        esp_lcd_init, "lcd_init_task", 2 * 3072, NULL, JADE_TASK_PRIO_GUI, &lcdInitTaskHandle, JADE_CORE_GUI);
    JADE_ASSERT(lcdInitTaskHandle);
    xSemaphoreTake(init_done, portMAX_DELAY);
    vTaskDelete(lcdInitTaskHandle);
    vSemaphoreDelete(init_done);
}

inline void display_hw_draw_bitmap(int x, int y, int w, int h, const uint16_t* color_data)
{
    JADE_ASSERT(ph);
    JADE_ASSERT(color_data);
    const int calculatedx = x - CONFIG_DISPLAY_OFFSET_X;
    const int calculatedy = y - CONFIG_DISPLAY_OFFSET_Y;
#if (defined(CONFIG_BOARD_TYPE_M5_CORES3) || defined(CONFIG_BOARD_TYPE_TTGO_TWATCHS3))                                 \
    && defined(CONFIG_DISPLAY_FULL_FRAME_BUFFER)
    /* this is required for the virtual buttons */
    if (calculatedy >= CONFIG_DISPLAY_HEIGHT) {
        ESP_ERROR_CHECK(
            esp_lcd_panel_draw_bitmap(ph, calculatedx, calculatedy, calculatedx + w, calculatedy + h, color_data));
        ESP_ERROR_CHECK(esp_lcd_panel_draw_bitmap(ph, calculatedx, calculatedy, x + w, calculatedy + h, color_data));
        return;
    }
#endif
#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
    if (!calculatedx && w == CONFIG_DISPLAY_WIDTH) {
        /* if we can copy the whole frame buffer in one go */
        uint16_t* screen_ptr = &disp_buf[calculatedy * CONFIG_DISPLAY_WIDTH];
        jmemcpy(screen_ptr, color_data, w * h * sizeof(color_t));
        return;
    }

    /* otherwise copy one line at the time */
    const int data_stride = w * sizeof(uint16_t);
    uint16_t* screen_ptr = &disp_buf[calculatedx + calculatedy * CONFIG_DISPLAY_WIDTH];
    const uint16_t* data_ptr = color_data;

    for (int k = 0; k < h; ++k) {
        jmemcpy(screen_ptr, data_ptr, data_stride);
        screen_ptr += CONFIG_DISPLAY_WIDTH;
        data_ptr += w;
    }
#else // DISPLAY_FULL_FRAME_BUFFER
    /* with no buffer draw immediately to display */
    ESP_ERROR_CHECK(esp_lcd_panel_draw_bitmap(
        ph, calculatedx, calculatedy, x - CONFIG_DISPLAY_OFFSET_X + w, calculatedy + h, color_data));
#endif
}

#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
inline void display_hw_draw_rect(int x, int y, int w, int h, const uint16_t color)
{
    const int calculatedx = x - CONFIG_DISPLAY_OFFSET_X;
    const int calculatedy = y - CONFIG_DISPLAY_OFFSET_Y;
    uint16_t* screen_ptr = &disp_buf[calculatedx + calculatedy * CONFIG_DISPLAY_WIDTH];

    if ((!calculatedx && w == CONFIG_DISPLAY_WIDTH)) {
        if (color == 0x0000 || color == 0xFFFF) {
            // small optimization, we can use memset instead of memcpy if it's black/white
            jmemset(screen_ptr, color, CONFIG_DISPLAY_WIDTH * h * sizeof(color_t));
        } else {
            if (w % 2 == 0) {
                uint32_t* disp_buf_32 = (uint32_t*)screen_ptr;
                const uint32_t color32 = ((uint32_t)color << 16) | color;
                const size_t size = CONFIG_DISPLAY_WIDTH * h / 2;
                // we do two pixel at the time, FIXME: maybe with ESP32S3 SIMD we can do more?
                for (size_t i = 0; i < size; ++i) {
                    disp_buf_32[i] = color32;
                }
            } else {
                // one pixel at the time
                for (size_t i = 0; i < h; ++i) {
                    for (size_t k = 0; k < w; ++k) {
                        screen_ptr[k + CONFIG_DISPLAY_WIDTH * i] = color;
                    }
                }
            }
        }
    } else {
        if ((color == 0x0000 || color == 0xFFFF)) {
            // in this we can use memset still, per line
            const int data_stride = w * sizeof(color_t);
            for (size_t i = 0; i < h; ++i) {
                jmemset(screen_ptr, color, data_stride);
                screen_ptr += CONFIG_DISPLAY_WIDTH;
            }
        } else {
            // it's not black or white so we can't use memset
            if (w % 2 == 0) {
                // we can do two pixel at the time
                // FIXME: maybe we can do more with ESP32S3 SIMD?
                uint32_t* disp_buf_32 = (uint32_t*)screen_ptr;
                const uint32_t color32 = ((uint32_t)color << 16) | color;
                const size_t size = w / 2;
                for (size_t i = 0; i < h; ++i) {
                    for (size_t k = 0; k < size; ++k) {
                        disp_buf_32[k] = color32;
                    }
                    disp_buf_32 += CONFIG_DISPLAY_WIDTH / 2;
                }
            } else {
                // one pixel at the time
                for (size_t i = 0; i < h; ++i) {
                    for (size_t k = 0; k < w; ++k) {
                        screen_ptr[k + CONFIG_DISPLAY_WIDTH * i] = color;
                    }
                }
            }
        }
    }
}

inline uint16_t* display_hw_get_buffer(void) { return disp_buf; }

#endif

#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER_DOUBLE
static inline void switch_buffer(void)
{
    buffer_selected = 1 - buffer_selected;
    disp_buf = _disp_buf[buffer_selected];
    /* it is necessary to copy the old buffer over the new one as writes can be partial */
    /* FIXME: 5.2+ idf seems to support dma memcpy for ESP32 S2/S3 */
    jmemcpy(disp_buf, _disp_buf[1 - buffer_selected], CONFIG_DISPLAY_WIDTH * CONFIG_DISPLAY_HEIGHT * sizeof(color_t));
}
#endif

#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
/* flushing is only necessary and useful if we do any kind of large buffering (i.e. if we have spiram and a
 * single/double full screen buffer) */
void display_hw_flush(void)
{
    ESP_ERROR_CHECK(esp_lcd_panel_draw_bitmap(ph, 0, 0, CONFIG_DISPLAY_WIDTH, CONFIG_DISPLAY_HEIGHT, disp_buf));
#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER_DOUBLE
    /* we only need to switch buffer if we have more than one and we don't bother waiting for writes */
    switch_buffer();
#else
    /* if we only have one frame buffer we always wait for it to written */
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
#endif
}
#endif // FRAME BUFFER
#endif // AMALGAMATED_BUILD
