#ifndef AMALGAMATED_BUILD
#include "display.h"
#include "gui.h"

#include <string.h>

#include "button_events.h"
#include "jade_assert.h"
#include "power.h"
#include "storage.h"
#include "utils/malloc_ext.h"
#include "utils/util.h"
#ifndef CONFIG_LIBJADE
#include <deflate.h>
#endif

#if defined(CONFIG_ETH_USE_OPENETH)
#define BUF_N 1
#if defined(CONFIG_HAS_CAMERA)
#include "qemu_display.h"
#endif
#else
// if we have psram we want to have either 2 buffers or to wait for paint in flush
#include "display_hw.h"
#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
#define BUF_N 1
#else
/* we need at least two buffers if we don't use a full framebuffer */
#define BUF_N 2
#endif
#endif

#define BUF_LINES 1

#define DISP_BUF_LEN (CONFIG_DISPLAY_WIDTH * BUF_LINES)

#ifndef CONFIG_DISPLAY_FULL_FRAME_BUFFER
static color_t _disp_buf[BUF_N][DISP_BUF_LEN];
static color_t* disp_buf = _disp_buf[0];
#endif

#if !defined(CONFIG_ETH_USE_OPENETH) && BUF_N > 1
static uint16_t buffer_selected = 0;
static inline void switch_buffer(void)
{
    buffer_selected = (buffer_selected + 1) % BUF_N;
    disp_buf = _disp_buf[buffer_selected];
}
#endif

static inline void draw_bitmap(int x, int y, int w, int h, const uint16_t* color_data);

#if defined(CONFIG_BOARD_TYPE_WS_TOUCH_LCD2)
#define DISPLAY_TOUCH_NAV_BUTTON_AREA 40
#define DISPLAY_TOUCH_NAV_BUTTON_MARGIN 5
#define DISPLAY_TOUCH_NAV_BUTTON_WIDTH 40
static void draw_touch_nav_buttons(void)
{
    uint16_t line[CONFIG_DISPLAY_WIDTH] = { TFT_BLACK };
    for (int16_t i = 0; i < DISPLAY_TOUCH_NAV_BUTTON_AREA; ++i) {
        draw_bitmap(CONFIG_DISPLAY_OFFSET_X, CONFIG_DISPLAY_HEIGHT + i + CONFIG_DISPLAY_OFFSET_Y,
            CONFIG_DISPLAY_WIDTH + CONFIG_DISPLAY_OFFSET_X, 1, line);
    }

    const int16_t nav_y1 = CONFIG_DISPLAY_HEIGHT + DISPLAY_TOUCH_NAV_BUTTON_MARGIN + CONFIG_DISPLAY_OFFSET_Y;
    const int16_t nav_y2 = (CONFIG_DISPLAY_HEIGHT + (DISPLAY_TOUCH_NAV_BUTTON_AREA - DISPLAY_TOUCH_NAV_BUTTON_MARGIN))
        + CONFIG_DISPLAY_OFFSET_Y;

    const int16_t center = (CONFIG_DISPLAY_WIDTH / 2) + CONFIG_DISPLAY_OFFSET_X;
    const int16_t left = DISPLAY_TOUCH_NAV_BUTTON_MARGIN + CONFIG_DISPLAY_OFFSET_X;
    const int16_t right = (CONFIG_DISPLAY_WIDTH - DISPLAY_TOUCH_NAV_BUTTON_MARGIN) + CONFIG_DISPLAY_OFFSET_X;
    const int16_t half_width = DISPLAY_TOUCH_NAV_BUTTON_WIDTH / 2;

    const struct {
        const char* symbol;
        int16_t x1;
        int16_t x2;
    } buttons[] = { { "H", left, left + DISPLAY_TOUCH_NAV_BUTTON_WIDTH },
        { "J", center - half_width, center + half_width },
        { "I", right - DISPLAY_TOUCH_NAV_BUTTON_WIDTH, right } };

    display_set_font(JADE_SYMBOLS_16x16_FONT, NULL);
    for (size_t i = 0; i < sizeof(buttons) / sizeof(buttons[0]); ++i) {
        const dispWin_t button_area
            = { .x1 = buttons[i].x1, .y1 = nav_y1, .x2 = buttons[i].x2, .y2 = nav_y2 };
        display_print_in_area(buttons[i].symbol, CENTER, CENTER, button_area, 0);
    }
    display_set_font(DEFAULT_FONT, NULL);
}

void display_touch_navbar_redraw(void) { draw_touch_nav_buttons(); }
#else
void display_touch_navbar_redraw(void) {}
#endif

static inline void draw_bitmap(int x, int y, int w, int h, const uint16_t* color_data)
{
    // JADE_ASSERT(color_data == &_fg || color_data == disp_buf);
#if defined(CONFIG_ETH_USE_OPENETH)
#if defined(CONFIG_HAS_CAMERA)
    qemu_draw_bitmap(x, y, w, h, color_data);
#endif
#else
    display_hw_draw_bitmap(x, y, w, h, color_data);
#if BUF_N > 1
    if (color_data != &_fg) {
        switch_buffer();
    }
#endif
#endif
}

// GUI configuration, see gui.h for more details
dispWin_t GUI_DISPLAY_WINDOW = { .x1 = CONFIG_DISPLAY_OFFSET_X,
    .y1 = CONFIG_DISPLAY_OFFSET_Y,
    .x2 = CONFIG_DISPLAY_WIDTH + CONFIG_DISPLAY_OFFSET_X,
    .y2 = CONFIG_DISPLAY_HEIGHT + CONFIG_DISPLAY_OFFSET_Y };

jlocale_t GUI_LOCALE = LOCALE_EN;
uint8_t GUI_TARGET_FRAMERATE = 20;
uint8_t GUI_SCROLL_WAIT_END = 32;
uint8_t GUI_SCROLL_WAIT_FRAME = 7;
uint8_t GUI_STATUS_BAR_HEIGHT = HOME_SCREEN_DEEP_STATUS_BAR ? 44 : 24;
uint8_t GUI_TITLE_FONT = UBUNTU16_FONT;
uint8_t GUI_DEFAULT_FONT = DEJAVU18_FONT;

extern const unsigned char tft_SmallFont[];
extern const unsigned char tft_DefaultFont[];
extern const unsigned char tft_Dejavu18[];
extern const unsigned char tft_Dejavu24[];
extern const unsigned char tft_Ubuntu16[];
extern const unsigned char tft_Comic24[];
extern const unsigned char tft_minya24[];
extern const unsigned char tft_tooney32[];
extern const unsigned char tft_def_small[];
extern const unsigned char tft_BigFont[];
extern const unsigned char tft_Sinclair_M[];
extern const unsigned char tft_Sinclair_S[];
extern const unsigned char tft_Retro8x16[];
extern const unsigned char tft_various_symbols[];
extern const unsigned char tft_Various_Symbols_32x32[];
extern const unsigned char tft_Battery_24x48[];
extern const unsigned char jade_symbols_16x16[];
extern const unsigned char jade_symbols_16x32[];
extern const unsigned char jade_symbols_24x24[];

const color_t TFT_BLACK = 0x0000;
const color_t TFT_NAVY = 0x0F00;
const color_t TFT_DARKGREEN = 0xE003;
const color_t TFT_DARKCYAN = 0xEF03;
const color_t TFT_MAROON = 0x0078;
const color_t TFT_PURPLE = 0x0F78;
const color_t TFT_OLIVE = 0xE07B;
const color_t TFT_LIGHTGREY = 0x18C6;
const color_t TFT_DARKGREY = 0xEF7B;
const color_t TFT_BLUE = 0x1F00;
const color_t TFT_GREEN = 0xE007;
const color_t TFT_CYAN = 0xFF07;
const color_t TFT_RED = 0x00F8;
const color_t TFT_MAGENTA = 0x1FF8;
const color_t TFT_YELLOW = 0xE0FF;
const color_t TFT_WHITE = 0xFFFF;
const color_t TFT_ORANGE = 0x20FD;
const color_t TFT_GREENYELLOW = 0xE5AF;
const color_t TFT_PINK = 0x19FE;

color_t _fg = TFT_WHITE;

static Font cfont = {
    .font = tft_DefaultFont,
    .x_size = 0,
    .y_size = 0x0B,
    .offset = 0,
    .numchars = 95,
    .bitmap = 1,
};

#ifndef CONFIG_DISPLAY_FULL_FRAME_BUFFER
static inline void fill_disp_buf_color(size_t opt_loop, color_t original, uint32_t color32)
{
    if (original == 0x0000 || original == 0xFFFF) {
        jmemset(disp_buf, original, opt_loop * 4);
    } else {
        uint32_t* disp_buf_32 = (uint32_t*)disp_buf;
        for (size_t i = 0; i < opt_loop; ++i) {
            disp_buf_32[i] = color32;
        }
    }
}
#endif

#define min(A, B) ((A) < (B) ? (A) : (B))

void display_fill_rect(int x, int y, int w, int h, color_t color)
{
    if ((x >= GUI_DISPLAY_WINDOW.x2) || (y > GUI_DISPLAY_WINDOW.y2)) {
        JADE_LOGE("x or y are incorrect x (%d) >= GUI_DISPLAY_WINDOW.x2 (%d) or y (%d) > GUI_DISPLAY_WINDOW.y2 (%d)", x,
            GUI_DISPLAY_WINDOW.x2, y, GUI_DISPLAY_WINDOW.y2);
        return;
    }
    if (x < GUI_DISPLAY_WINDOW.x1) {
        w -= (GUI_DISPLAY_WINDOW.x1 - x);
        x = GUI_DISPLAY_WINDOW.x1;
    }
    if (y < GUI_DISPLAY_WINDOW.y1) {
        h -= (GUI_DISPLAY_WINDOW.y1 - y);
        y = GUI_DISPLAY_WINDOW.y1;
    }
    if (w < 0) {
        w = 0;
    }
    if (h < 0) {
        h = 0;
    }
    if ((x + w) > (GUI_DISPLAY_WINDOW.x2 + 1)) {
        w = GUI_DISPLAY_WINDOW.x2 - x + 1;
    }
    if ((y + h) > (GUI_DISPLAY_WINDOW.y2 + 1)) {
        h = GUI_DISPLAY_WINDOW.y2 - y + 1;
    }
    if (w == 0) {
        w = 1;
    }
    if (h == 0) {
        h = 1;
    }

    if (x < CONFIG_DISPLAY_OFFSET_X || y < CONFIG_DISPLAY_OFFSET_Y
        || (x - CONFIG_DISPLAY_OFFSET_X) + w > CONFIG_DISPLAY_WIDTH
        || ((y - CONFIG_DISPLAY_OFFSET_Y) + h > CONFIG_DISPLAY_HEIGHT)) {
        JADE_LOGE(
            "display_fill_rect called with bad params (ignored) x %d y %d w %d h %d color %u\n", x, y, w, h, color);
#if !defined(CONFIG_BOARD_TYPE_M5_CORES3) && !defined(CONFIG_BOARD_TYPE_TTGO_TWATCHS3)                                 \
    && !defined(CONFIG_BOARD_TYPE_WS_TOUCH_LCD2)
        return;
#endif
    }

#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
    display_hw_draw_rect(x, y, w, h, color);
#else

    // running without a full frame buffer
    const int lines_in_buf = DISP_BUF_LEN / w;
    int lines_left = h;

    const uint32_t color32 = ((uint32_t)color << 16) | color;
    const size_t opt_loop = min(lines_left, lines_in_buf) * w / sizeof(color_t);

#if BUF_N == 1
    // if we do have a framebuffer we should aim to never touch this disp_buf but directly
    // the other one
    /* if we have only one buffer we fill it once because it won't get switched when calling draw_bitmap */
    fill_disp_buf_color(opt_loop, color, color32);
#endif

    while (lines_left) {
#if BUF_N > 1
        /* if we have more than one buf then disp_buf will be switch each time draw_bitmap is called so we need to
         * refill it */
        fill_disp_buf_color(opt_loop, color, color32);
#endif
        // if we are switching buffers then for each draw_bitmap we need to refill
        const int maximum_lines = min(lines_left, lines_in_buf);
        const int cy = y + h - lines_left;
        draw_bitmap(x, cy, w, maximum_lines, disp_buf);
        lines_left -= maximum_lines;
    }
#endif // DISPLAY_FULL_FRAME_BUFFER
}

static void display_clear(void)
{
    display_fill_rect(
        CONFIG_DISPLAY_OFFSET_X, CONFIG_DISPLAY_OFFSET_Y, CONFIG_DISPLAY_WIDTH, CONFIG_DISPLAY_HEIGHT, TFT_BLACK);
}

void display_init(TaskHandle_t* gui_h)
{
    JADE_LOGI("display/screen init");
    JADE_ASSERT(gui_h);
    JADE_ASSERT(!*gui_h);

    power_screen_on();
    vTaskDelay(100 / portTICK_PERIOD_MS);

#if defined(CONFIG_ETH_USE_OPENETH)
#if defined(CONFIG_HAS_CAMERA)
    qemu_display_init();
#endif
#else
    JADE_ASSERT(gui_h);
    display_hw_init(gui_h);

#if defined(CONFIG_BOARD_TYPE_WS_TOUCH_LCD2)
    /* The TwatchS3 and core s3 don't have buttons that can be used (just power and
       reset)
       but it has a touch panel, we use the bottom 40 pixels worth of height
       to display 3 buttons (prev, OK, next), we handle this here rather than
       in display_hw because we want to draw text inside the virtual buttons */

    vTaskDelay(50 / portTICK_PERIOD_MS);

    display_touch_navbar_redraw();
    vTaskDelay(50 / portTICK_PERIOD_MS);
#endif
#endif

    display_clear();

    // Default screen brightness if not set
    if (!storage_get_brightness()) {
        storage_set_brightness(BACKLIGHT_MAX);
    }
}

bool display_flip_orientation(const bool flipped_orientation)
{
#ifndef CONFIG_ETH_USE_OPENETH
    return display_hw_flip_orientation(flipped_orientation);
#else
    // Not supported for qemu
    return false;
#endif
}

typedef struct {
    Icon* icon;
    Picture* pic;
    size_t written;
    uint16_t allocated_size;
} image_deflate_ctx_t;

// Sanity checks
#define MAX_FLASH_PICTURE_SIZE (198 * 62 * sizeof(uint16_t))
#define MAX_FLASH_ICON_SIZE (200 * 200 / 8)

static int uncompressed_image_stream_writer(void* ctx, uint8_t* uncompressed, size_t towrite)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(uncompressed);
    JADE_ASSERT(towrite);

    image_deflate_ctx_t* const ictx = (image_deflate_ctx_t*)ctx;

    // Should be loading a picture or an icon, not both!
    JADE_ASSERT(!ictx->icon != !ictx->pic);

    if (!ictx->written) {
        // First iteration
        JADE_ASSERT(towrite >= 3); // Assume can read at least 3 bytes
        JADE_ASSERT(!ictx->allocated_size);

        // NOTE: first byte in uncompressed stream is image width

        // Extract next two bytes to get image data length (little-endian)
        ictx->allocated_size = uncompressed[1] + (uncompressed[2] << 8);
        const size_t max_allowed_size = ictx->icon ? MAX_FLASH_ICON_SIZE : MAX_FLASH_PICTURE_SIZE;
        if (!ictx->allocated_size || ictx->allocated_size > max_allowed_size) {
            // larger than we want to handle
            return DEFLATE_ERROR;
        }

        // Allocate appropriate data buffer and set image width
        if (ictx->icon) {
            JADE_ASSERT(!ictx->icon->data);
            ictx->icon->data = JADE_MALLOC_PREFER_SPIRAM(ictx->allocated_size);
            ictx->icon->width = uncompressed[0];
        } else {
            JADE_ASSERT(!ictx->pic->data_8);
            ictx->pic->data_8 = JADE_MALLOC_PREFER_SPIRAM(ictx->allocated_size);
            ictx->pic->width = uncompressed[0];
        }

        // Count bytes read and bump read pointer
        towrite -= 3;
        uncompressed += 3;
    }

    if (towrite + ictx->written > ictx->allocated_size) {
        // larger than allocation
        return DEFLATE_ERROR;
    }

    uint8_t* const dest = ictx->icon ? (uint8_t*)ictx->icon->data : ictx->pic->data_8;
    JADE_ASSERT(dest);
    jmemcpy(dest + ictx->written, uncompressed, towrite);
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
    JADE_ASSERT(ictx->written == ictx->allocated_size);
    free(dctx);
}

Picture* get_picture(const uint8_t* const start, const uint8_t* const end)
{
    JADE_ASSERT(start);
    JADE_ASSERT(end);

    // Setup for Picture load
    image_deflate_ctx_t ictx = { .icon = NULL, .pic = JADE_MALLOC(sizeof(Picture)), .written = 0, .allocated_size = 0 };
    ictx.pic->data_8 = NULL;
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
    image_deflate_ctx_t ictx = { .icon = JADE_MALLOC(sizeof(Icon)), .pic = NULL, .written = 0, .allocated_size = 0 };
    ictx.icon->data = NULL;
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

typedef struct {
    uint8_t charCode;
    int adjYOffset;
    int width;
    int height;
    int xOffset;
    int xDelta;
    uint16_t dataPtr;
} propFont;

static propFont fontChar;

#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
uint16_t* get_display_buffer_at(int x, int y)
{
    const int calculated_x = x - CONFIG_DISPLAY_OFFSET_X;
    const int calculated_y = y - CONFIG_DISPLAY_OFFSET_Y;
    uint16_t* hw_buf = display_hw_get_buffer();
    return hw_buf + calculated_x + calculated_y * CONFIG_DISPLAY_WIDTH;
}
#endif

static inline bool get_icon_pixel(uint16_t x, uint16_t y, uint16_t width, const Icon* icon)
{
    const uint32_t val = ((uint32_t)width) * y + x;

    const uint32_t elem = val / 32;
    const uint32_t bit = val % 32;

    return (icon->data[elem] >> bit) & 1;
}

void display_icon(const Icon* imgbuf, int x, int y, color_t color, dispWin_t area, const color_t* bg_color)
{
    JADE_ASSERT(imgbuf);

    JADE_ASSERT(imgbuf->width <= CONFIG_DISPLAY_WIDTH);
    JADE_ASSERT(imgbuf->height <= CONFIG_DISPLAY_HEIGHT);

    const uint16_t width = imgbuf->width;
    const uint16_t height = imgbuf->height;

    const uint16_t draw_width = min(width, area.x2 - area.x1);
    const uint16_t draw_height = min(height, area.y2 - area.y1);

#ifndef CONFIG_DISPLAY_FULL_FRAME_BUFFER
    uint16_t start_x = 0;
    uint16_t start_y = 0;
#endif

    if (x == RIGHT) {
        x = area.x2 - draw_width;
    } else if (x == CENTER) {
        x = ((area.x2 - area.x1 - draw_width) / 2) + area.x1;
#ifndef CONFIG_DISPLAY_FULL_FRAME_BUFFER
        start_x = (width - draw_width) / 2;
#endif
    } else {
        x = x + area.x1;
    }

    if (y == BOTTOM) {
        y = area.y2 - draw_height;
    } else if (y == CENTER) {
        y = ((area.y2 - area.y1 - draw_height) / 2) + area.y1;
#ifndef CONFIG_DISPLAY_FULL_FRAME_BUFFER
        start_y = (height - draw_height) / 2;
#endif
    } else {
        y = y + area.y1;
    }

#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
    uint16_t* disp_ptr = get_display_buffer_at(x, y);
    const uint32_t* icon_data = imgbuf->data;
    uint32_t icon_bits = 0, bit_counter = 0;
    const uint32_t stride = CONFIG_DISPLAY_WIDTH - draw_width;
    for (size_t i = 0; i < draw_height; ++i) {
        if (bg_color) {
            const color_t bg = *bg_color;
            for (size_t k = 0; k < draw_width; ++k, ++bit_counter) {
                if (!(bit_counter & 31)) {
                    icon_bits = *icon_data++; // Read next word every 32 bits
                }
                *disp_ptr++ = icon_bits & 0x1 ? color : bg;
                icon_bits >>= 1;
            }
        } else {
            for (size_t k = 0; k < draw_width; ++k, ++bit_counter) {
                if (!(bit_counter & 31)) {
                    icon_bits = *icon_data++; // Read next word every 32 bits
                }
                if (icon_bits & 0x1) {
                    *disp_ptr = color;
                }
                ++disp_ptr;
                icon_bits >>= 1;
            }
        }
        disp_ptr += stride;
    }
#else

    uint16_t buf_x = 0;
    for (uint16_t loop_y = 0; loop_y < draw_height; ++loop_y) {
        for (uint16_t loop_x = 0; loop_x < draw_width; ++loop_x) {
            if (get_icon_pixel(loop_x + start_x, loop_y + start_y, width, imgbuf)) {
                disp_buf[buf_x++] = color;
            } else if (bg_color) {
                disp_buf[buf_x++] = *bg_color;
            } else {
                // Transparent, draw icon row so far
                if (buf_x) {
                    draw_bitmap(x + loop_x - buf_x, y + loop_y, buf_x, 1, disp_buf);
                    buf_x = 0;
                }
            }
        }
        // End of line, draw icon row remaining
        if (buf_x) {
            draw_bitmap(x + draw_width - buf_x, y + loop_y, buf_x, 1, disp_buf);
            buf_x = 0;
        }
    }
#endif
}

static inline bool is_within_limits(int cx, int cy)
{
    // Allow for characters to be printed in the virtual button area
#ifndef CONFIG_DISPLAY_TOUCHSCREEN
    if ((cx < CONFIG_DISPLAY_OFFSET_X) || (cy < CONFIG_DISPLAY_OFFSET_Y)
        || (cx > (CONFIG_DISPLAY_WIDTH + CONFIG_DISPLAY_OFFSET_X))
        || (cy > (CONFIG_DISPLAY_HEIGHT + CONFIG_DISPLAY_OFFSET_Y))) {
        return false;
    }
#endif
    return true;
}

static int print_proportional_char(int x, int y)
{
    uint8_t ch = 0;
    const int char_width = (fontChar.width > fontChar.xDelta) ? fontChar.width : fontChar.xDelta;

    uint8_t mask = 0x80;

    for (uint8_t j = 0; j < fontChar.height; ++j) {
        for (int i = 0; i < fontChar.width; ++i) {
            if (!((i + (j * fontChar.width)) % 8)) {
                mask = 0x80;
                ch = cfont.font[fontChar.dataPtr++];
            }

            if ((ch & mask)) {
                const int cx = (uint16_t)(x + fontChar.xOffset + i);
                const int cy = (uint16_t)(y + j + fontChar.adjYOffset);
                if (!is_within_limits(cx, cy)) {
                    continue;
                }
                draw_bitmap(cx, cy, 1, 1, &_fg);
            }
            mask >>= 1;
        }
    }

    return char_width;
}

static uint8_t get_char_ptr(const uint8_t c)
{
    uint16_t tempPtr = 4;

    do {
        fontChar.charCode = cfont.font[tempPtr++];
        if (fontChar.charCode == 0xFF) {
            return 0;
        }

        fontChar.adjYOffset = cfont.font[tempPtr++];
        fontChar.width = cfont.font[tempPtr++];
        fontChar.height = cfont.font[tempPtr++];
        fontChar.xOffset = cfont.font[tempPtr++];
        fontChar.xOffset = fontChar.xOffset < 0x80 ? fontChar.xOffset : -(0xFF - fontChar.xOffset);
        fontChar.xDelta = cfont.font[tempPtr++];

        if (c != fontChar.charCode && fontChar.charCode != 0xFF) {
            if (fontChar.width != 0) {
                tempPtr += (((fontChar.width * fontChar.height) - 1) / 8) + 1;
            }
        }
    } while ((c != fontChar.charCode) && (fontChar.charCode != 0xFF));

    fontChar.dataPtr = tempPtr;
    if (c != fontChar.charCode) {
        return 0;
    }

    return 1;
}

static inline void print_char(uint8_t c, int x, int y)
{
    const uint8_t fz = (cfont.x_size + 7) >> 3;
    uint16_t temp = ((c - cfont.offset) * (fz * cfont.y_size)) + 4;
    uint16_t cx, cy;
    for (uint8_t j = 0; j < cfont.y_size; ++j) {
        for (uint16_t k = 0; k < fz; ++k) {
            uint8_t ch = cfont.font[temp + k];
            uint8_t mask = 0x80;
            for (uint8_t i = 0; i < 8; ++i) {
                if (ch & mask) {
                    cx = x + i + (k << 3);
                    cy = y + j;
                    if (!is_within_limits(cx, cy)) {
                        continue;
                    }
                    draw_bitmap(cx, cy, 1, 1, &_fg);
                }
                mask >>= 1;
            }
        }
        temp += fz;
    }
}

int display_get_string_width(const char* str)
{
    if (cfont.x_size != 0) {
        return strlen(str) * cfont.x_size;
    }

    int strWidth = 0;
    const char* tempStrptr = str;
    int charWidth, xDelta;

    while (*tempStrptr) {
        if (get_char_ptr(*tempStrptr++)) {
            charWidth = fontChar.width;
            xDelta = fontChar.xDelta;
            strWidth += ((charWidth > xDelta) ? charWidth : xDelta) + 1;
        }
    }

    return strWidth - 1;
}

int display_get_font_height(void)
{
    if (cfont.bitmap == 1) {
        return cfont.y_size;
    }
    return 0;
}

static void get_max_width_height(void)
{
    uint16_t tempPtr = 4;
    uint8_t cc, cy, cw, ch, cd;
    uint8_t max_x_size = 0;
    uint8_t y_size = 0;
    int numchars = 0;

    while (true) {
        cc = cfont.font[tempPtr++];
        if (cc == 0xFF) {
            break;
        }

        numchars++;
        cy = cfont.font[tempPtr++];
        cw = cfont.font[tempPtr++];
        ch = cfont.font[tempPtr++];
        tempPtr++;
        cd = cfont.font[tempPtr++];
        cy += ch;

        if (cw > max_x_size) {
            max_x_size = cw;
        }

        if (cd > max_x_size) {
            max_x_size = cd;
        }

        if (ch > y_size) {
            y_size = ch;
        }

        if (cy > y_size) {
            y_size = cy;
        }

        if (cw != 0) {
            tempPtr += (((cw * ch) - 1) >> 3) + 1;
        }
    }

    cfont.numchars = numchars;
    cfont.max_x_size = max_x_size;
    cfont.y_size = y_size;
    cfont.size = tempPtr;
}

void display_set_font(uint8_t font, const char* font_file)
{
    cfont.font = NULL;

    if (font == DEJAVU18_FONT) {
        cfont.font = tft_Dejavu18;
    } else if (font == DEJAVU24_FONT) {
        cfont.font = tft_Dejavu24;
    } else if (font == UBUNTU16_FONT) {
        cfont.font = tft_Ubuntu16;
    } else if (font == COMIC24_FONT) {
        cfont.font = tft_Comic24;
    } else if (font == MINYA24_FONT) {
        cfont.font = tft_minya24;
    } else if (font == TOONEY32_FONT) {
        cfont.font = tft_tooney32;
    } else if (font == SMALL_FONT) {
        cfont.font = tft_SmallFont;
    } else if (font == DEF_SMALL_FONT) {
        cfont.font = tft_def_small;
    } else if (font == BIG_FONT) {
        cfont.font = tft_BigFont;
    } else if (font == SINCLAIR_M) {
        cfont.font = tft_Sinclair_M;
    } else if (font == SINCLAIR_S) {
        cfont.font = tft_Sinclair_S;
    } else if (font == RETRO_8X16) {
        cfont.font = tft_Retro8x16;
    } else if (font == VARIOUS_SYMBOLS_FONT) {
        cfont.font = tft_various_symbols;
    } else if (font == VARIOUS_SYMBOLS_32_FONT) {
        cfont.font = tft_Various_Symbols_32x32;
    } else if (font == BATTERY_FONT) {
        cfont.font = tft_Battery_24x48;
    } else if (font == JADE_SYMBOLS_16x16_FONT) {
        cfont.font = jade_symbols_16x16;
    } else if (font == JADE_SYMBOLS_16x32_FONT) {
        cfont.font = jade_symbols_16x32;
    } else if (font == JADE_SYMBOLS_24x24_FONT) {
        cfont.font = jade_symbols_24x24;
    } else {
        cfont.font = tft_DefaultFont;
    }

    cfont.bitmap = 1;
    cfont.x_size = cfont.font[0];
    cfont.y_size = cfont.font[1];
    if (cfont.x_size > 0) {
        cfont.offset = cfont.font[2];
        cfont.numchars = cfont.font[3];
        cfont.size = cfont.x_size * cfont.y_size * cfont.numchars;
    } else {
        cfont.offset = 4;
        get_max_width_height();
    }
}

#define LASTX 7000
#define LASTY 8000

void display_print_in_area(const char* st, int x, int y, dispWin_t areaWin, bool wrap)
{
    if (!cfont.bitmap) {
        return;
    }
    int TFT_X = 0;
    int TFT_Y = 0;

    if ((x >= LASTX) && (x < LASTY)) {
        x = TFT_X + (x - LASTX);
    } else if (x > CENTER) {
        x += areaWin.x1;
    }

    if (y >= LASTY) {
        y = TFT_Y + (y - LASTY);
    } else if (y > CENTER) {
        y += areaWin.y1;
    }

    int stl = strlen(st);
    int tmpw = display_get_string_width(st);
    int fh = cfont.y_size;

    if (x == RIGHT) {
        x = areaWin.x2 - tmpw;
    } else if (x == CENTER) {
        x = ((areaWin.x2 - areaWin.x1 - tmpw) / 2) + areaWin.x1;
    }

    if (y == BOTTOM) {
        y = areaWin.y2 - fh;
    } else if (y == CENTER) {
        y = ((areaWin.y2 - areaWin.y1 - fh) / 2) + areaWin.y1;
    }

    if (x < areaWin.x1) {
        x = areaWin.x1;
    }
    if (y < areaWin.y1) {
        y = areaWin.y1;
    }
    if ((x > areaWin.x2) || (y > areaWin.y2)) {
        return;
    }

    TFT_X = x;
    TFT_Y = y;

    // for non-proportional fonts, char width is the same for all chars
    // for proportional fonts, this value is calculated as each char is printed
    tmpw = cfont.x_size;
    int tmph = cfont.y_size;

    if ((TFT_Y + tmph - 1) > areaWin.y2) {
        return;
    }

    uint8_t ch;

    for (int i = 0; i < stl; ++i) {
        ch = st[i];

        if (ch == 0x0A) {
            if (cfont.bitmap == 1) {
                TFT_Y += tmph;
                if (TFT_Y > (areaWin.y2 - tmph)) {
                    break;
                }
                TFT_X = areaWin.x1;
            }
        } else {
            if (!cfont.x_size) {
                if (get_char_ptr(ch)) {
                    tmpw = fontChar.xDelta;
                } else {
                    continue;
                }
            }

            if ((TFT_X + tmpw) > (areaWin.x2)) {
                if (!wrap) {
                    break;
                }
                TFT_Y += tmph;
                if (TFT_Y > (areaWin.y2 - tmph)) {
                    break;
                }
                TFT_X = areaWin.x1;
            }

            if (!cfont.x_size) {
                TFT_X += print_proportional_char(TFT_X, TFT_Y) + 1;
            } else {
                if ((ch < cfont.offset) || ((ch - cfont.offset) > cfont.numchars)) {
                    ch = cfont.offset;
                }
                print_char(ch, TFT_X, TFT_Y);
                TFT_X += tmpw;
            }
        }
    }
}

// Macros to convert a grayscale 0-255 index to big-endian 565 RGB
#define GS_MASK1 0xF8
#define GS_MASK2 0xFC
#define GS_CPU(n) (((n & GS_MASK1) << 8) | ((n & GS_MASK2) << 3) | ((n & GS_MASK1) >> 3))
// TODO: this should just be GS_CPU(n) if our arch is natively big-endian
#define GS(n) ((GS_CPU(n) & 0x00ff) << 8) | ((GS_CPU(n) & 0xff00) >> 8)

// We have 6 bits max per R/G/B, so only need 64 distinct mappings
static const uint16_t gray_565[64] = { GS(0), GS(4), GS(8), GS(12), GS(16), GS(20), GS(24), GS(28), GS(32), GS(36),
    GS(40), GS(44), GS(48), GS(52), GS(56), GS(60), GS(64), GS(68), GS(72), GS(76), GS(80), GS(84), GS(88), GS(92),
    GS(96), GS(100), GS(104), GS(108), GS(112), GS(116), GS(120), GS(124), GS(128), GS(132), GS(136), GS(140), GS(144),
    GS(148), GS(152), GS(156), GS(160), GS(164), GS(168), GS(172), GS(176), GS(180), GS(184), GS(188), GS(192), GS(196),
    GS(200), GS(204), GS(208), GS(212), GS(216), GS(220), GS(224), GS(228), GS(232), GS(236), GS(240), GS(244), GS(248),
    GS(252) };

#undef GS_CPU
#undef GS

void display_picture(const Picture* imgbuf, int x, int y, dispWin_t area)
{
    JADE_ASSERT(imgbuf);

    JADE_ASSERT(imgbuf->width <= CONFIG_DISPLAY_WIDTH);
    JADE_ASSERT(imgbuf->height <= CONFIG_DISPLAY_HEIGHT);

    int calculatedx = 0;
    int calculatedy = 0;

    switch (x) {
    case CENTER:
        calculatedx = ((area.x2 - area.x1 - imgbuf->width) / 2) + area.x1;
        break;
    case RIGHT:
        calculatedx = area.x2 - imgbuf->width;
        break;
    default:
        calculatedx = x + area.x1;
        break;
    }

    switch (y) {
    case CENTER:
        calculatedy = ((area.y2 - area.y1 - imgbuf->height) / 2) + area.y1;
        break;
    case BOTTOM:
        calculatedy = area.y2 - imgbuf->height;
        break;
    default:
        calculatedy = y + area.y1;
        break;
    }

    JADE_ASSERT(calculatedx >= CONFIG_DISPLAY_OFFSET_X);
    JADE_ASSERT(calculatedy >= CONFIG_DISPLAY_OFFSET_Y);
    JADE_ASSERT((calculatedx - CONFIG_DISPLAY_OFFSET_X) + imgbuf->width <= CONFIG_DISPLAY_WIDTH);
    JADE_ASSERT((calculatedy - CONFIG_DISPLAY_OFFSET_Y) + imgbuf->height <= CONFIG_DISPLAY_HEIGHT);

    if (imgbuf->bytes_per_pixel == 2) {
        // the image uses the same 16bit pixels as we do on our display so no transformation
        // this kind of image is like the one from boot not the ones from camera atm
        draw_bitmap(calculatedx, calculatedy, imgbuf->width, imgbuf->height, imgbuf->data);
        return;
    }

    // at the moment we only support 8 bit and 16 bit colors, no 24/32 bit color yet
    JADE_ASSERT(imgbuf->bytes_per_pixel == 1);

#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
    uint16_t* disp_ptr = get_display_buffer_at(calculatedx, calculatedy);
    const uint8_t* src_ptr = imgbuf->data_8;
    const uint32_t stride = CONFIG_DISPLAY_WIDTH - imgbuf->width;
    for (size_t i = 0; i < imgbuf->height; ++i) {
        for (size_t k = 0; k < imgbuf->width; ++k) {
            *disp_ptr++ = gray_565[*src_ptr >> 2];
            ++src_ptr;
        }
        disp_ptr += stride;
    }
#else

    const int lines_in_buf = DISP_BUF_LEN / imgbuf->width;
    int lines_left = imgbuf->height;
    while (lines_left) {
        // for each line in the input we have left we calculate how many would fit in our buffer
        const int maximum_lines = min(lines_left, lines_in_buf);
        const int line_offset = imgbuf->height - lines_left;
        uint16_t* disp_ptr = disp_buf;
        const uint8_t* src_ptr = imgbuf->data_8 + line_offset * imgbuf->width;

        for (int i = 0; i < maximum_lines * imgbuf->width; ++i) {
            *disp_ptr++ = gray_565[*src_ptr >> 2];
            ++src_ptr;
        }

        draw_bitmap(calculatedx, calculatedy + line_offset, imgbuf->width, maximum_lines, disp_buf);
        lines_left -= maximum_lines;
    }
#endif // DISPLAY_FULL_FRAME_BUFFER
}

void display_flush(void)
{
#if defined(CONFIG_ETH_USE_OPENETH)
#if defined(CONFIG_HAS_CAMERA)
    qemu_display_flush();
#endif
#else
#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
    display_hw_flush();
#endif
#endif
}
#endif // AMALGAMATED_BUILD
