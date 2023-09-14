#include "display.h"
#include "gui.h"

#include <string.h>

#include "button_events.h"
#include "jade_assert.h"
#include "power.h"
#include "storage.h"
#include "utils/malloc_ext.h"
#include <deflate.h>

// GUI configuration, see gui.h for more details
dispWin_t GUI_DISPLAY_WINDOW = { .x1 = CONFIG_GUI_DISPLAY_WINDOW_X1,
    .y1 = CONFIG_GUI_DISPLAY_WINDOW_Y1,
    .x2 = CONFIG_GUI_DISPLAY_WINDOW_X2,
    .y2 = CONFIG_GUI_DISPLAY_WINDOW_Y2 };
jlocale_t GUI_LOCALE = LOCALE_EN;
bool GUI_VIEW_DEBUG = false;
uint8_t GUI_TARGET_FRAMERATE = 15;
uint8_t GUI_SCROLL_WAIT_END = 32;
uint8_t GUI_SCROLL_WAIT_FRAME = 7;
uint8_t GUI_STATUS_BAR_HEIGHT = 24;
uint8_t GUI_TITLE_FONT = UBUNTU16_FONT;
uint8_t GUI_DEFAULT_FONT = DEJAVU18_FONT;

#define SPI_BUS TFT_HSPI_HOST

void display_init(void)
{
    JADE_LOGI("display/screen init");
    power_screen_on();

    esp_err_t ret;
    TFT_PinsInit();
    spi_lobo_device_handle_t spi;
    spi_lobo_bus_config_t buscfg = {
        .miso_io_num = PIN_NUM_MISO, // set SPI MISO pin
        .mosi_io_num = PIN_NUM_MOSI, // set SPI MOSI pin
        .sclk_io_num = PIN_NUM_CLK, // set SPI CLK pin
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 6 * 1024,
    };
    spi_lobo_device_interface_config_t devcfg = {
        .clock_speed_hz = 8000000, // Initial clock out at 8 MHz
        .mode = 0, // SPI mode 0
        .spics_io_num = -1, // we will use external CS pin
        .spics_ext_io_num = PIN_NUM_CS, // external CS pin
        .flags = LB_SPI_DEVICE_HALFDUPLEX, // ALWAYS SET  to HALF DUPLEX MODE!! for display spi
    };
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ret = spi_lobo_bus_add_device(SPI_BUS, &buscfg, &devcfg, &spi);
    JADE_ASSERT(ret == ESP_OK);
    disp_spi = spi;
    ret = spi_lobo_device_select(spi, 1);
    JADE_ASSERT(ret == ESP_OK);
    ret = spi_lobo_device_deselect(spi);
    JADE_ASSERT(ret == ESP_OK);
    TFT_display_init();
    max_rdclock = find_rd_speed();
    spi_lobo_set_speed(spi, DEFAULT_SPI_CLOCK);
    font_rotate = 0;
    text_wrap = 1; // wrap to next line
    font_transparent = 1;
    font_forceFixed = 0;
    gray_scale = 0;
    TFT_setRotation(CONFIG_DISP_ORIENTATION_DEFAULT);
    TFT_resetclipwin();

    // Default screen brightness if not set
    if (!storage_get_brightness()) {
        storage_set_brightness(BACKLIGHT_MAX);
    }
}

typedef struct {
    Icon* icon;
    Picture* pic;
    size_t written;
} image_deflate_ctx_t;

#define MAX_FLASH_PICTURE_SIZE (198 * 62 * sizeof(uint16_t))
#define MAX_FLASH_ICON_SIZE (200 * 200 / 8)

static int uncompressed_image_stream_writer(void* ctx, uint8_t* uncompressed, size_t towrite)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(uncompressed);
    JADE_ASSERT(towrite);

    image_deflate_ctx_t* const ictx = (image_deflate_ctx_t*)ctx;

    // Should be loading a picture or an icon, not both!
    JADE_ASSERT((ictx->icon && ictx->icon->data) || (ictx->pic && ictx->pic->data_8));
    JADE_ASSERT(!ictx->pic || !ictx->icon);

    const size_t max_image_size = ictx->icon ? MAX_FLASH_ICON_SIZE : MAX_FLASH_PICTURE_SIZE;
    if (towrite + ictx->written > max_image_size + 1) { // +1 for the prefixed width byte
        // larger than we want to handle
        return DEFLATE_ERROR;
    }

    if (!ictx->written) {
        // First iteration, extract first byte from uncompressed stream to get the width
        uint16_t* const width = ictx->icon ? &ictx->icon->width : (uint16_t*)&ictx->pic->width;
        *width = uncompressed[0];
        --towrite;
        ++uncompressed;
    }

    uint8_t* const dest = ictx->icon ? (uint8_t*)ictx->icon->data : ictx->pic->data_8;
    memcpy(dest + ictx->written, uncompressed, towrite);
    ictx->written += towrite;
    return DEFLATE_OK;
}
static void decompress_image(const uint8_t* const start, const uint8_t* const end, image_deflate_ctx_t* const ictx)
{
    JADE_ASSERT(start);
    JADE_ASSERT(end);
    JADE_ASSERT(ictx);

    const size_t compressed_size = end - start;
    struct deflate_ctx* const dctx = JADE_MALLOC_PREFER_SPIRAM(sizeof(struct deflate_ctx));
    int dret = deflate_init_write_compressed(dctx, compressed_size, uncompressed_image_stream_writer, ictx);
    JADE_ASSERT(!dret);
    dret = dctx->write_compressed(dctx, (uint8_t*)start, compressed_size);
    JADE_ASSERT(!dret);
    free(dctx);
}

Picture* get_picture(const uint8_t* const start, const uint8_t* const end)
{
    JADE_ASSERT(start);
    JADE_ASSERT(end);

    // Setup for Picture load
    image_deflate_ctx_t ictx = { .icon = NULL, .pic = JADE_MALLOC(sizeof(Picture)), .written = 0 };
    ictx.pic->data_8 = JADE_MALLOC_PREFER_SPIRAM(MAX_FLASH_PICTURE_SIZE);
    ictx.pic->bytes_per_pixel = 2;
    ictx.pic->width = 0;
    ictx.pic->height = 0;

    // Decompress the image data
    decompress_image(start, end, &ictx);

    // Deduce the image height
    JADE_ASSERT(ictx.pic->width);
    JADE_ASSERT(ictx.written);
    ictx.pic->height = ictx.written / (ictx.pic->width * ictx.pic->bytes_per_pixel);
    JADE_ASSERT(ictx.pic->height);
    JADE_ASSERT(ictx.pic->height * ictx.pic->width * ictx.pic->bytes_per_pixel == ictx.written);
    return ictx.pic;
}

Icon* get_icon(const uint8_t* const start, const uint8_t* const end)
{
    JADE_ASSERT(start);
    JADE_ASSERT(end);

    // Setup for Icon load
    image_deflate_ctx_t ictx = { .icon = JADE_MALLOC(sizeof(Icon)), .pic = NULL, .written = 0 };
    ictx.icon->data = JADE_MALLOC_PREFER_SPIRAM(MAX_FLASH_ICON_SIZE);
    ictx.icon->width = 0;
    ictx.icon->height = 0;
    ictx.written = 0;

    // Decompress the image data
    decompress_image(start, end, &ictx);

    // Deduce the image height
    JADE_ASSERT(ictx.icon->width);
    JADE_ASSERT(ictx.written);
    ictx.icon->height = (ictx.written * 8) / ictx.icon->width;
    JADE_ASSERT(ictx.icon->height);
    JADE_ASSERT(ictx.icon->height * ictx.icon->width == ictx.written * 8);
    return ictx.icon;
}

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
extern const uint8_t splashstart[] asm("_binary_splash_bin_gz_start");
extern const uint8_t splashend[] asm("_binary_splash_bin_gz_end");
#endif

gui_activity_t* display_splash(void)
{
    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* splash_node;
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    Picture* const pic = get_picture(splashstart, splashend);
    gui_make_picture(&splash_node, pic);
#else
    gui_make_text(&splash_node, "Jade DIY", TFT_WHITE);
#endif
    gui_set_align(splash_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(splash_node, act->root_node);

    // set the current activity and draw it on screen
    gui_set_current_activity(act);
    return act;
}

// get/set screen orientation
bool display_is_orientation_flipped(void)
{
    // Our default appears to be 'LANDSCAPE_FLIP' (?)
    return orientation == LANDSCAPE;
}

void display_toggle_orientation(void) { TFT_setRotation(orientation == LANDSCAPE ? LANDSCAPE_FLIP : LANDSCAPE); }
