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
#ifdef CONFIG_BOARD_TYPE_JADE
void wheel_uninit(bool uninstall_gpio_isr_service);
void wheel_reinit(bool install_gpio_isr_service);
#endif

#endif /* INPUT_H_ */
