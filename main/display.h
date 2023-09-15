#ifndef DISPLAY_H_
#define DISPLAY_H_

#include <arch/sys_arch.h>
#include <esp_event.h>

#define color_t uint16_t

typedef struct {
    uint16_t x1;
    uint16_t y1;
    uint16_t x2;
    uint16_t y2;
} dispWin_t;

typedef struct {
    uint8_t* font;
    uint8_t x_size;
    uint8_t y_size;
    uint8_t offset;
    uint16_t numchars;
    uint16_t size;
    uint8_t max_x_size;
    uint8_t bitmap;
    color_t color;
} Font;

typedef struct {
    uint16_t width, height;
    uint32_t* data;
} Icon;

typedef struct {
    union {
        uint16_t* data;
        uint8_t* data_8;
    };
    uint16_t width, height;
    uint8_t bytes_per_pixel;
} Picture;

extern const color_t TFT_BLACK;
extern const color_t TFT_NAVY;
extern const color_t TFT_DARKGREEN;
extern const color_t TFT_DARKCYAN;
extern const color_t TFT_MAROON;
extern const color_t TFT_PURPLE;
extern const color_t TFT_OLIVE;
extern const color_t TFT_LIGHTGREY;
extern const color_t TFT_DARKGREY;
extern const color_t TFT_BLUE;
extern const color_t TFT_GREEN;
extern const color_t TFT_CYAN;
extern const color_t TFT_RED;
extern const color_t TFT_MAGENTA;
extern const color_t TFT_YELLOW;
extern const color_t TFT_WHITE;
extern const color_t TFT_ORANGE;
extern const color_t TFT_GREENYELLOW;
extern const color_t TFT_PINK;

// === Special coordinates constants ===
#define CENTER -9003
#define RIGHT -9004
#define BOTTOM -9004

// === Embedded fonts constants ===
#define DEFAULT_FONT 0
#define DEJAVU18_FONT 1
#define DEJAVU24_FONT 2
#define UBUNTU16_FONT 3
#define COMIC24_FONT 4
#define MINYA24_FONT 5
#define TOONEY32_FONT 6
#define SMALL_FONT 7
#define DEF_SMALL_FONT 8
#define FONT_7SEG 9
#define BIG_FONT 11
#define SINCLAIR_M 12
#define SINCLAIR_S 13
#define SINCLAIR_INV_M 14
#define SINCLAIR_INV_S 15
#define RETRO_8X16 16
#define VARIOUS_SYMBOLS_FONT 17
#define VARIOUS_SYMBOLS_32_FONT 18
#define BATTERY_FONT 19
#define JADE_SYMBOLS_16x16_FONT 20
#define JADE_SYMBOLS_16x32_FONT 21
#define JADE_SYMBOLS_24x24_FONT 22

void display_init(TaskHandle_t* gui_h);
Icon* get_icon(const uint8_t* start, const uint8_t* end);
Picture* get_picture(const uint8_t* start, const uint8_t* end);
void display_picture(const Picture* imgbuf, int x, int y, dispWin_t area);
void display_fill_rect(int x, int y, int w, int h, color_t color);
void display_icon(const Icon* imgbuf, int x, int y, color_t color, dispWin_t area, const color_t* bg_color);
void display_print_in_area(const char* st, int x, int y, dispWin_t areaWin, bool wrap);
int display_get_string_width(const char* str);
void display_set_font(uint8_t font, const char* font_file);
int display_get_font_height(void);
void display_flush(void);
#endif /* DISPLAY_H_ */
