#include "display.h"
#include "gui.h"

#include <string.h>

#include "button_events.h"
#include "jade_assert.h"
#include "power.h"

// GUI configuration, see gui.h for more details
jlocale_t GUI_LOCALE = LOCALE_EN;
bool GUI_VIEW_DEBUG = false;
uint16_t GUI_TARGET_FRAMERATE = 15;
uint16_t GUI_SCROLL_WAIT_END = 32;
uint16_t GUI_SCROLL_WAIT_FRAME = 7;
dispWin_t GUI_DISPLAY_WINDOW = { .x1 = 40, .y1 = 53, .x2 = 280, .y2 = 188 };
uint16_t GUI_STATUS_BAR_HEIGHT = 24;
uint32_t GUI_DEFAULT_FONT = DEFAULT_FONT;

#define SPI_BUS TFT_HSPI_HOST

void display_init(void)
{
    JADE_LOGI("Powering the screen");
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
}

#include "../logo/splash.c"

gui_activity_t* display_splash(void)
{
    gui_activity_t* act;
    gui_make_activity(&act, false, NULL);

    gui_view_node_t* splash_node;
    gui_make_picture(&splash_node, &splash);
    gui_set_parent(splash_node, act->root_node);

    // set the current activity and draw it on screen
    gui_set_current_activity(act);
    power_backlight_on();
    return act;
}

// get/set screen orientation
bool display_is_orientation_flipped(void)
{
    // Our default appears to be 'LANDSCAPE_FLIP' (?)
    return orientation == LANDSCAPE;
}

void display_toggle_orientation(void) { TFT_setRotation(orientation == LANDSCAPE ? LANDSCAPE_FLIP : LANDSCAPE); }
