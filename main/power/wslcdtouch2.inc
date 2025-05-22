// Waveshare LCD Touch 2 implmentation
//
#include <esp_sleep.h>
#include <driver/gpio.h>
#include <driver/ledc.h>
#include <esp_adc/adc_cali.h>
#include <esp_adc/adc_cali_scheme.h>
#include <esp_adc/adc_oneshot.h>
#include <freertos/idf_additions.h>

#include "soc/gpio_num.h"
#include "hal/gpio_types.h"
#include "hal/adc_types.h"
#include "button_gpio.h"
#include "iot_button.h"
#include "power.h"

#define BATTERY_ADC_CHANNEL ADC_CHANNEL_4
#define BATTERY_ADC_ATTEN ADC_ATTEN_DB_12
#define BATTERY_EMA_ALPHA 0.3 // estimated moving average smoothing factor

#define LCD_BL_LEDC_TIMER LEDC_TIMER_0
#define LCD_BL_LEDC_MODE LEDC_LOW_SPEED_MODE

#define LCD_BL_LEDC_CHANNEL LEDC_CHANNEL_0
#define LCD_BL_LEDC_DUTY_RES LEDC_TIMER_10_BIT
#define LCD_BL_LEDC_DUTY (1024)
#define LCD_BL_LEDC_FREQUENCY (10000)

static adc_oneshot_unit_handle_t adc1_handle = NULL;
static adc_cali_handle_t adc1_cali_chan0_handle = NULL;

static int ema_voltage = 0;

static void button_shutdown(void* arg, void* ctx)
{
    power_backlight_off();
    while (gpio_get_level(GPIO_NUM_0) == 0) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    power_shutdown();
}

static esp_err_t boot_button_init(void)
{
    const button_config_t btn_cfg = {
        .long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
        .short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
    };

    const button_gpio_config_t btn_gpio_cfg = {
        .gpio_num = 0,
        .active_level = 0,
    };

    button_handle_t btn_handle = NULL;
    ESP_ERROR_CHECK(iot_button_new_gpio_device(&btn_cfg, &btn_gpio_cfg, &btn_handle));
    ESP_ERROR_CHECK(iot_button_register_cb(btn_handle, BUTTON_LONG_PRESS_HOLD, NULL, button_shutdown, NULL));

    esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_ALL);
    gpio_hold_en(GPIO_NUM_0);
    gpio_deep_sleep_hold_en();
    esp_sleep_enable_ext0_wakeup(GPIO_NUM_0, 0);

    return ESP_OK;
}

static esp_err_t brightness_init(void)
{
    gpio_reset_pin(CONFIG_DISPLAY_PIN_BL);
    gpio_set_direction(CONFIG_DISPLAY_PIN_BL, GPIO_MODE_OUTPUT);
    gpio_set_level(CONFIG_DISPLAY_PIN_BL, 1);

    ledc_timer_config_t ledc_timer = { .speed_mode = LCD_BL_LEDC_MODE,
        .timer_num = LCD_BL_LEDC_TIMER,
        .duty_resolution = LCD_BL_LEDC_DUTY_RES,
        .freq_hz = LCD_BL_LEDC_FREQUENCY, // Set output frequency at 5 kHz
        .clk_cfg = LEDC_AUTO_CLK };
    ESP_ERROR_CHECK(ledc_timer_config(&ledc_timer));

    ledc_channel_config_t ledc_channel = { .speed_mode = LCD_BL_LEDC_MODE,
        .channel = LCD_BL_LEDC_CHANNEL,
        .timer_sel = LCD_BL_LEDC_TIMER,
        .intr_type = LEDC_INTR_DISABLE,
        .gpio_num = CONFIG_DISPLAY_PIN_BL,
        .duty = 0, // Set duty to 0%
        .hpoint = 0 };
    ESP_ERROR_CHECK(ledc_channel_config(&ledc_channel));

    return ESP_OK;
}

esp_err_t power_init(void)
{
    // Use the BOOT button as a sleep/wakeup button
    ESP_ERROR_CHECK(boot_button_init());

    // Initialise backlight brightness
    ESP_ERROR_CHECK(brightness_init());

    // Initialise the ADC to measure battery level
    adc_oneshot_unit_init_cfg_t init_config1 = {
        .unit_id = ADC_UNIT_1,
    };
    ESP_ERROR_CHECK(adc_oneshot_new_unit(&init_config1, &adc1_handle));
    JADE_ASSERT(adc1_handle);

    adc_oneshot_chan_cfg_t config = {
        .bitwidth = ADC_BITWIDTH_DEFAULT,
        .atten = BATTERY_ADC_ATTEN,
    };
    ESP_ERROR_CHECK(adc_oneshot_config_channel(adc1_handle, BATTERY_ADC_CHANNEL, &config));

    // Use voltage calibration
    adc_cali_curve_fitting_config_t cali_config = {
        .unit_id = ADC_UNIT_1,
        .atten = BATTERY_ADC_ATTEN,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    if (adc_cali_create_scheme_curve_fitting(&cali_config, &adc1_cali_chan0_handle) != ESP_OK) {
        JADE_LOGW("ADC calibration not available, continuing without it");
        adc1_cali_chan0_handle = NULL;
    }

    return ESP_OK;
}

esp_err_t power_shutdown(void) { esp_deep_sleep_start(); }

esp_err_t power_screen_on(void) { return ESP_OK; }
esp_err_t power_screen_off(void) { return ESP_OK; }

esp_err_t power_backlight_on(uint8_t brightness)
{
    if (brightness < BACKLIGHT_MIN) {
        brightness = BACKLIGHT_MIN;
    } else if (brightness > BACKLIGHT_MAX) {
        brightness = BACKLIGHT_MAX;
    }

    uint32_t duty = (brightness * (LCD_BL_LEDC_DUTY - 1)) / 5;
    ESP_ERROR_CHECK(ledc_set_duty(LCD_BL_LEDC_MODE, LCD_BL_LEDC_CHANNEL, duty));
    ESP_ERROR_CHECK(ledc_update_duty(LCD_BL_LEDC_MODE, LCD_BL_LEDC_CHANNEL));

    return ESP_OK;
}

esp_err_t power_backlight_off(void)
{
    ESP_ERROR_CHECK(ledc_set_duty(LCD_BL_LEDC_MODE, LCD_BL_LEDC_CHANNEL, 0));
    ESP_ERROR_CHECK(ledc_update_duty(LCD_BL_LEDC_MODE, LCD_BL_LEDC_CHANNEL));

    return ESP_OK;
}

esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

uint16_t power_get_vbat(void)
{
    JADE_ASSERT(adc1_handle);

    int raw_adc, voltage;
    ESP_ERROR_CHECK(adc_oneshot_read(adc1_handle, BATTERY_ADC_CHANNEL, &raw_adc));

    if (adc1_cali_chan0_handle) {
        adc_cali_raw_to_voltage(adc1_cali_chan0_handle, raw_adc, &voltage);
    } else {
        voltage = (raw_adc * 3300) / 4095; // mV
    }

    // apply Estimated Moving Average since the ADC seems to have a lot of noise
    ema_voltage = BATTERY_EMA_ALPHA * voltage + (1 - BATTERY_EMA_ALPHA) * (ema_voltage == 0 ? voltage : ema_voltage);
    /* JADE_LOGI("Raw: %.2dmV, Smoothed: %.2d mV", voltage, ema_voltage); */
    return (uint16_t)ema_voltage;
}

uint8_t power_get_battery_status(void)
{
    const uint16_t vbat = power_get_vbat() * 3; // apply voltage divider
    if (vbat > 3800) {
        return 5;
    } else if (vbat > 3600) {
        return 4;
    } else if (vbat > 3400) {
        return 3;
    } else if (vbat > 3200) {
        return 2;
    } else if (vbat > 3000) {
        return 1;
    }
    return 0;
}

// The STAT pin on the charging IC isn't exposed to a GPIO so we cannot read it
// and can't easily tap it with a wire. There is a charging LED though so you
// can see if the battery is being charged.
bool power_get_battery_charging(void) { return 0; }
uint16_t power_get_ibat_charge(void) { return 0; }
uint16_t power_get_ibat_discharge(void) { return 0; }
uint16_t power_get_vusb(void) { return 0; }
uint16_t power_get_iusb(void) { return 0; }
uint16_t power_get_temp(void) { return 0; }

void disable_usb_host(void) {}
void enable_usb_host(void) {}

// This is only a guess by the ADC voltage when the USB is plugged in
bool usb_connected(void) { return power_get_vbat() > 1350; }
