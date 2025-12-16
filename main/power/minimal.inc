// No-op/minimal implementation for devices with no power-management chip
//
#include <esp_sleep.h>

esp_err_t power_init(void) { return ESP_OK; }

esp_err_t power_shutdown(void)
{
    // If we don't have a PMU, use esp_deep_sleep()
    esp_deep_sleep_start();
    return ESP_OK;
}

esp_err_t power_screen_on(void) { return ESP_OK; }

esp_err_t power_backlight_on(const uint8_t brightness) { return ESP_OK; }
esp_err_t power_backlight_off(void) { return ESP_OK; }

esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

uint16_t power_get_vbat(void) { return 0; }
uint8_t power_get_battery_status(void) { return 0; }
bool power_get_battery_charging(void) { return false; }
uint16_t power_get_ibat_charge(void) { return 0; }
uint16_t power_get_ibat_discharge(void) { return 0; }
uint16_t power_get_vusb(void) { return 0; }
uint16_t power_get_iusb(void) { return 0; }
uint16_t power_get_temp(void) { return 0; }

void disable_usb_host(void) {}
void enable_usb_host(void) {}

bool usb_is_powered(void) { return true; }
