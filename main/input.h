#ifndef BUTTONS_H_
#define BUTTONS_H_

#include <sdkconfig.h>
#include <stdbool.h>

#define BUTTON_FRONT CONFIG_INPUT_FRONT_SW

#define BUTTON_ENC CONFIG_INPUT_WHEEL_SW

#define ROT_ENC_A_GPIO CONFIG_INPUT_WHEEL_A
#define ROT_ENC_B_GPIO CONFIG_INPUT_WHEEL_B

#define ENABLE_HALF_STEPS false // Set to true to enable tracking of rotary encoder at half step resolution
#define RESET_AT 0 // Set to a positive non-zero number to reset the position if this value is exceeded

// Set to true to reverse the clockwise/counterclockwise sense
#ifdef CONFIG_INPUT_INVERT_WHEEL
#define FLIP_DIRECTION true
#else
#define FLIP_DIRECTION false
#endif

extern int button_selector;
extern bool button_selected;

void input_init();
void set_invert_wheel(bool inverted);

void button_init();
void button_tap(void* arg);
void button_long(void* arg);

void wheel_init();

#endif /* BUTTONS_H_ */
