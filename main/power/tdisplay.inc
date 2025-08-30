// tdisplay and devices with no power-management but it can measure voltage level of the battery and
// detect charging status when a battery is connected through an analog input
//
#include <driver/gpio.h>
#include <esp_adc/adc_cali.h>
#include <esp_adc/adc_oneshot.h>

#define BATTERY_ADC_CHANNEL ADC_CHANNEL_6

static adc_oneshot_unit_handle_t adc1_handle = NULL;
static adc_cali_handle_t adc1_cali_handle = NULL;

esp_err_t power_init(void)
{
    // Initialise the ADC to measure battery level
    adc_oneshot_unit_init_cfg_t init_config1 = {
        .unit_id = ADC_UNIT_1,
    };
    ESP_ERROR_CHECK(adc_oneshot_new_unit(&init_config1, &adc1_handle));
    JADE_ASSERT(adc1_handle);
    // ADC Config
    adc_oneshot_chan_cfg_t config = {
        .atten = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    ESP_ERROR_CHECK(adc_oneshot_config_channel(adc1_handle, BATTERY_ADC_CHANNEL, &config));
    // Curve fitting calibration
    adc_cali_curve_fitting_config_t cali_config = {
        .unit_id = ADC_UNIT_1,
        .atten = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    ESP_ERROR_CHECK(adc_cali_create_scheme_curve_fitting(&cali_config, &adc1_cali_handle));
    return ESP_OK;
}

esp_err_t power_shutdown(void) { return ESP_OK; }
esp_err_t power_screen_on(void) { return ESP_OK; }
esp_err_t power_backlight_on(const uint8_t brightness) { return ESP_OK; }
esp_err_t power_backlight_off(void) { return ESP_OK; }
esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

uint16_t power_get_vbat(void)
{
    JADE_ASSERT(adc1_handle);
    int cal_vbat = 0;
    int raw_vbat = 0;
    ESP_ERROR_CHECK(adc_oneshot_read(adc1_handle, BATTERY_ADC_CHANNEL, &raw_vbat));
    ESP_ERROR_CHECK(adc_cali_raw_to_voltage(adc1_cali_handle, raw_vbat, &cal_vbat));
    return (uint16_t)(cal_vbat * 2);
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

bool power_get_battery_charging(void)
{
    uint16_t vbat = power_get_vbat();
    // If the voltage is greater than 4500 mV and less than 4750 it means its charging
    if (vbat > 4500 && vbat < 4750) {
        return true;
    }
    return false;
}

uint16_t power_get_ibat_charge(void) { return 0; }
uint16_t power_get_ibat_discharge(void) { return 0; }
uint16_t power_get_vusb(void) { return 0; }
uint16_t power_get_iusb(void) { return 0; }
uint16_t power_get_temp(void) { return 0; }

bool usb_connected(void)
{
    // If the voltage is greater than 4500 mV it means USB is connected
    uint16_t vbat = power_get_vbat();
    if (vbat > 4500) {
        return true;
    }
    return false;
}
