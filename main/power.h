#ifndef POWER_H_
#define POWER_H_

#include <esp_err.h>
#include <stdbool.h>
#include <stdint.h>

esp_err_t power_init();
esp_err_t power_shutdown();

esp_err_t power_backlight_on();
esp_err_t power_backlight_off();

esp_err_t power_screen_on();
esp_err_t power_screen_off();

esp_err_t power_camera_on();
esp_err_t power_camera_off();

uint16_t power_get_vbat();
uint8_t power_get_battery_status();
bool power_get_battery_charging();
uint16_t power_get_ibat_charge();
uint16_t power_get_ibat_discharge();
uint16_t power_get_vusb();
uint16_t power_get_iusb();
uint16_t power_get_temp();

bool usb_connected();

#endif /* POWER_H_ */
