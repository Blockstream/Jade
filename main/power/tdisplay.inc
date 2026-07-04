// T-Display (ESP32) implementation without PMIC (ADC-based)
//

#include <driver/gpio.h>
#include <driver/ledc.h>
#include <esp_adc/adc_cali.h>
#include <esp_adc/adc_cali_scheme.h>
#include <esp_adc/adc_oneshot.h>
#include <esp_sleep.h>

#define BATTERY_ADC_CHANNEL ADC_CHANNEL_6
#define BATTERY_ADC_ATTEN ADC_ATTEN_DB_12
#define BATTERY_EMA_ALPHA 0.3f // estimated moving average smoothing factor

#define LCD_BL_LEDC_TIMER LEDC_TIMER_0
#define LCD_BL_LEDC_MODE LEDC_LOW_SPEED_MODE
#define LCD_BL_LEDC_CHANNEL LEDC_CHANNEL_0
#define LCD_BL_LEDC_DUTY_RES LEDC_TIMER_10_BIT
#define LCD_BL_LEDC_DUTY_MAX ((1 << 10) - 1)
#define LCD_BL_LEDC_FREQUENCY 10000

static adc_oneshot_unit_handle_t adc1_handle = NULL;
static adc_cali_handle_t adc1_cali_chan0_handle = NULL;

static float ema_voltage = 0.0f;

static esp_err_t brightness_init(void)
{
    gpio_reset_pin(CONFIG_DISPLAY_PIN_BL);
    gpio_set_direction(CONFIG_DISPLAY_PIN_BL, GPIO_MODE_OUTPUT);

    ledc_timer_config_t ledc_timer = { .speed_mode = LCD_BL_LEDC_MODE,
        .timer_num = LCD_BL_LEDC_TIMER,
        .duty_resolution = LCD_BL_LEDC_DUTY_RES,
        .freq_hz = LCD_BL_LEDC_FREQUENCY,
        .clk_cfg = LEDC_AUTO_CLK };
    ESP_ERROR_CHECK(ledc_timer_config(&ledc_timer));

    ledc_channel_config_t ledc_channel = { .speed_mode = LCD_BL_LEDC_MODE,
        .channel = LCD_BL_LEDC_CHANNEL,
        .timer_sel = LCD_BL_LEDC_TIMER,
        .intr_type = LEDC_INTR_DISABLE,
        .gpio_num = CONFIG_DISPLAY_PIN_BL,
        .duty = 0,
        .hpoint = 0 };
    ESP_ERROR_CHECK(ledc_channel_config(&ledc_channel));
    return ESP_OK;
}

esp_err_t power_init(void)
{
    ESP_ERROR_CHECK(brightness_init());

    // Initialise the ADC to measure battery level
    adc_oneshot_unit_init_cfg_t init_config1 = {
        .unit_id = ADC_UNIT_1,
    };
    ESP_ERROR_CHECK(adc_oneshot_new_unit(&init_config1, &adc1_handle));
    JADE_ASSERT(adc1_handle);
    // ADC Config
    adc_oneshot_chan_cfg_t config = {
        .atten = BATTERY_ADC_ATTEN,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    ESP_ERROR_CHECK(adc_oneshot_config_channel(adc1_handle, BATTERY_ADC_CHANNEL, &config));
    // ESP32 (original) uses Line Fitting, not Curve Fitting like S3
    adc_cali_line_fitting_config_t cali_config = {
        .unit_id = ADC_UNIT_1,
        .atten = BATTERY_ADC_ATTEN,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    if (adc_cali_create_scheme_line_fitting(&cali_config, &adc1_cali_chan0_handle) != ESP_OK) {
        JADE_LOGW("ADC calibration not available, continuing without it");
        adc1_cali_chan0_handle = NULL;
    }
    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
    esp_deep_sleep_start();
    return ESP_OK;
}
esp_err_t power_screen_on(void) { return ESP_OK; }
esp_err_t power_screen_off(void) { return ESP_OK; }
esp_err_t power_backlight_on(uint8_t brightness)
{
    if (brightness < BACKLIGHT_MIN) {
        brightness = BACKLIGHT_MIN;
    } else if (brightness > BACKLIGHT_MAX) {
        brightness = BACKLIGHT_MAX;
    }

    const uint32_t duty = (brightness * LCD_BL_LEDC_DUTY_MAX) / BACKLIGHT_MAX;
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
        ESP_ERROR_CHECK(adc_cali_raw_to_voltage(adc1_cali_chan0_handle, raw_adc, &voltage));
    } else {
        // Fallback for ESP32: 3.3V ref approx (less accurate without cali)
        voltage = (raw_adc * 3300) / 4095;
    }
    // Apply Estimated Moving Average (EMA)
    const float ema_v = (ema_voltage > 0) ? ema_voltage : (float)voltage;
    ema_voltage = (BATTERY_EMA_ALPHA * voltage) + ((1.0f - BATTERY_EMA_ALPHA) * ema_v);
    // T-Display voltage divider is 2 (100k/100k)
    return (uint16_t)(ema_voltage * 2);
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
    // The charging IC STAT pin is not connected to GPIO.
    // Return USB status as a proxy for charging (Dummy status)
    return usb_is_powered();
}

uint16_t power_get_ibat_charge(void) { return 0; }
uint16_t power_get_ibat_discharge(void) { return 0; }
uint16_t power_get_vusb(void) { return 0; }
uint16_t power_get_iusb(void) { return 0; }
uint16_t power_get_temp(void) { return 0; }

void disable_usb_host(void) {}
void enable_usb_host(void) {}

bool usb_is_powered(void)
{
    // The T-Display (ESP32) does not have native USB (uses CP2104/CH9102 bridge).
    // We cannot reliably detect if we are on USB or Battery because the charging IC
    // applies voltage to the battery rails even without a battery.
    const uint16_t vbat = power_get_vbat();
    return (vbat < 1000) || (vbat > 4150);
}
