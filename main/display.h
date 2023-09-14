#ifndef DISPLAY_H_
#define DISPLAY_H_

#include <esp_event.h>
#include <freertos/task.h>

#include "gui.h"
#include "tft.h"
#include "tftspi.h"

void display_init(void);

gui_activity_t* display_splash(void);

bool display_is_orientation_flipped(void);
void display_toggle_orientation(void);

Icon* get_icon(const uint8_t* start, const uint8_t* end);
Picture* get_picture(const uint8_t* start, const uint8_t* end);

#endif /* DISPLAY_H_ */
