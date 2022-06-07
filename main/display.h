#ifndef DISPLAY_H_
#define DISPLAY_H_

#include <esp_event.h>
#include <freertos/task.h>

#include "gui.h"
#include "tft.h"
#include "tftspi.h"

void display_init(void);

void display_splash(gui_activity_t** ppact);

bool display_is_orientation_flipped(void);
void display_toggle_orientation(void);

#endif /* DISPLAY_H_ */
