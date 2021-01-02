#ifndef DISPLAY_H_
#define DISPLAY_H_

#include <esp_event.h>
#include <freertos/task.h>

#include "gui.h"
#include "tft.h"
#include "tftspi.h"

void display_init();

gui_activity_t* display_splash();

bool display_is_orientation_flipped();
void display_toggle_orientation();

#endif /* DISPLAY_H_ */
