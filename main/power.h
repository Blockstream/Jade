#ifndef POWER_H_
#define POWER_H_

#include <esp_err.h>
#include <stdbool.h>
#include <stdint.h>

esp_err_t power_init();

esp_err_t power_screen_on();
esp_err_t power_screen_off();
esp_err_t power_set_camera_voltage();
esp_err_t power_enable_dc_dc1();
esp_err_t power_enable_dc_dc2();
esp_err_t power_enable_adcs();
esp_err_t power_enable_charging();
esp_err_t power_enable_coulomb_counter();
esp_err_t power_setup_pek();
esp_err_t power_set_v_off();
esp_err_t power_open_drain_gpio();
esp_err_t power_gpio_on();
esp_err_t power_gpio_off();
esp_err_t power_shutdown();

uint16_t power_get_vbat();
uint8_t power_get_battery_status();
bool power_get_battery_charging();
uint16_t power_get_ibat_charge();
uint16_t power_get_ibat_discharge();
uint16_t power_get_vusb();
uint16_t power_get_iusb();
uint16_t power_get_temp();

bool usb_get_status();

#endif /* POWER_H_ */
