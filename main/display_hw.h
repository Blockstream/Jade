#ifndef DISPLAY_HW_H_
#define DISPLAY_HW_H_
#include <arch/sys_arch.h>
#include <stdint.h>
void display_hw_init(TaskHandle_t* gui_handle);
void display_hw_draw_bitmap(int x, int y, int w, int h, const uint16_t* color_data);
#ifdef CONFIG_DISPLAY_FULL_FRAME_BUFFER
void display_hw_flush(void);
void display_hw_draw_rect(int x, int y, int w, int h, const uint16_t color_data);
uint16_t* display_hw_get_buffer(void);
#endif
#endif /* DISPLAY_HW_H_ */
