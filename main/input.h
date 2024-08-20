#ifndef INPUT_H_
#define INPUT_H_

#include <sdkconfig.h>
#include <stdbool.h>

extern int button_selector;
extern bool button_selected;

void input_init(void);

void button_init(void);
void button_tap(void* arg);
void button_long(void* arg);

void wheel_init(void);

#if defined(CONFIG_DISPLAY_TOUCHSCREEN)
void touchscreen_init(void);
#endif

#endif /* INPUT_H_ */
