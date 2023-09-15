#ifndef QEMU_DISPLAY_H
#define QEMU_DISPLAY_H

#include <stdbool.h>

bool qemu_start_display_webserver(void);
void qemu_display_init(void);
void qemu_draw_bitmap(int x, int y, int w, int h, const uint16_t* color_data);
void qemu_display_flush(void);

#endif /* QEMU_DISPLAY_H */
