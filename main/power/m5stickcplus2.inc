// M5StickCPlus implmentation - uses IP5303 Power PMU
//
#include <driver/gpio.h>
#include <esp_adc/adc_oneshot.h>

#define POWER_HOLD_GPIO 4
#define BATTERY_ADC_CHANNEL ADC_CHANNEL_2

static adc_oneshot_unit_handle_t adc1_handle = NULL;

esp_err_t power_init(void)
{
    // Set the power hold pin to keep the device from powering down straight away
    gpio_reset_pin(POWER_HOLD_GPIO);
    gpio_set_direction(POWER_HOLD_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(POWER_HOLD_GPIO, 1);

    // Initialise the ADC to measure battery level
    //-------------ADC1 Init---------------//
    adc_oneshot_unit_init_cfg_t init_config1 = {
        .unit_id = ADC_UNIT_1,
    };
    ESP_ERROR_CHECK(adc_oneshot_new_unit(&init_config1, &adc1_handle));
    JADE_ASSERT(adc1_handle);

    //-------------ADC1 Config---------------//
    adc_oneshot_chan_cfg_t config = {
        .bitwidth = ADC_BITWIDTH_DEFAULT,
        .atten = ADC_ATTEN_DB_12,
    };
    ESP_ERROR_CHECK(adc_oneshot_config_channel(adc1_handle, BATTERY_ADC_CHANNEL, &config));

    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
    gpio_set_level(POWER_HOLD_GPIO, 0);
    return ESP_OK;
}

esp_err_t power_screen_on(void) { return ESP_OK; }
esp_err_t power_screen_off(void) { return ESP_OK; }

esp_err_t power_backlight_on(const uint8_t brightness) { return ESP_OK; }
esp_err_t power_backlight_off(void) { return ESP_OK; }

esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

uint16_t power_get_vbat(void)
{
    JADE_ASSERT(adc1_handle);

    int vbat = 0;
    ESP_ERROR_CHECK(adc_oneshot_read(adc1_handle, BATTERY_ADC_CHANNEL, &vbat));
    return (uint16_t)(vbat * 1.7);
}

uint8_t power_get_battery_status(void)
{
    const uint16_t vbat = power_get_vbat();
    if (vbat > 4000) {
        return 5;
    } else if (vbat > 3800) {
        return 4;
    } else if (vbat > 3600) {
        return 3;
    } else if (vbat > 3400) {
        return 2;
    } else if (vbat > 3200) {
        return 1;
    }
    return 0;
}

bool power_get_battery_charging(void) { return 0; }
uint16_t power_get_ibat_charge(void) { return 0; }
uint16_t power_get_ibat_discharge(void) { return 0; }
uint16_t power_get_vusb(void) { return 0; }
uint16_t power_get_iusb(void) { return 0; }
uint16_t power_get_temp(void) { return 0; }

bool usb_is_powered(void) { return true; }
