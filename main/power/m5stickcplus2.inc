// M5StickC Plus 2 implementation - uses IP5303 Power PMU
//
#include <driver/gpio.h>
#include <driver/ledc.h>
#include <esp_adc/adc_oneshot.h>

#define POWER_HOLD_GPIO 4
#define BATTERY_ADC_CHANNEL ADC_CHANNEL_2

#define LCD_BL_LEDC_TIMER LEDC_TIMER_3
#define LCD_BL_LEDC_MODE LEDC_HIGH_SPEED_MODE
#define LCD_BL_LEDC_CHANNEL LEDC_CHANNEL_7
#define LCD_BL_LEDC_DUTY_RES LEDC_TIMER_9_BIT
#define LCD_BL_LEDC_DUTY_BITS 9
#define LCD_BL_LEDC_FREQUENCY 256
#define LCD_BL_LEDC_OFFSET 40

static adc_oneshot_unit_handle_t adc1_handle = NULL;

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
    // Set the power hold pin to keep the device from powering down straight away
    gpio_reset_pin(POWER_HOLD_GPIO);
    gpio_set_direction(POWER_HOLD_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(POWER_HOLD_GPIO, 1);

    ESP_ERROR_CHECK(brightness_init());

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

esp_err_t power_backlight_on(uint8_t brightness)
{
    if (brightness < BACKLIGHT_MIN) {
        brightness = BACKLIGHT_MIN;
    } else if (brightness > BACKLIGHT_MAX) {
        brightness = BACKLIGHT_MAX;
    }

    const uint32_t scaled_brightness
        = 1 + ((brightness - BACKLIGHT_MIN) * 254) / (BACKLIGHT_MAX - BACKLIGHT_MIN);
    uint_fast16_t offset = LCD_BL_LEDC_OFFSET;
    if (offset) {
        offset = offset * 259 >> 8;
    }
    uint32_t duty = scaled_brightness * (257 - offset);
    duty += offset * 255;
    duty += 1 << (15 - LCD_BL_LEDC_DUTY_BITS);
    duty >>= 16 - LCD_BL_LEDC_DUTY_BITS;

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
