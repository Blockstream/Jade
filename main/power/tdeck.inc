#include "jade_assert.h"

#include <driver/gpio.h>
#include <esp_rom_sys.h>
#include <esp_adc/adc_cali.h>
#include <esp_adc/adc_cali_scheme.h>
#include <esp_adc/adc_oneshot.h>
#include <esp_sleep.h>

#ifdef CONFIG_JADE_USE_USB_JTAG_SERIAL
#include <driver/usb_serial_jtag.h>
#else
#include "tusb.h"
#endif

#define BOARD_POWERON_GPIO  10
#define BACKLIGHT_GPIO      42
#define BACKLIGHT_STEPS     16

// Implemented in input/tdeck.inc - the keyboard task owns the i2c bus
void tdeck_set_keyboard_backlight(uint8_t value);

#define BATTERY_ADC_CHANNEL ADC_CHANNEL_3
#define BATTERY_ADC_ATTEN   ADC_ATTEN_DB_12
#define BATTERY_ADC_SAMPLES 8
#define BATTERY_EMA_ALPHA   0.3f

// Voltage divider ratio is 2.0 (100k/100k) plus ~10% correction for
// undervoltage while the display loads the rail (as per other t-deck
// firmwares, eg. meshtastic)
#define BATTERY_VDIV_MULTIPLIER 2.11f

// Above this the sense node is being held up by the charger with the
// battery full (charge terminated) rather than actively charging
#define BATTERY_CHARGED_MILLIVOLTS 4300

static bool usb_connected(void)
{
#ifdef CONFIG_JADE_USE_USB_JTAG_SERIAL
    // TinyUSB is not initialised in this mode - infer usb connection
    // from the usb-serial-jtag peripheral instead
    return usb_serial_jtag_is_connected();
#else
    return tud_mounted() && !tud_suspended();
#endif
}

static adc_oneshot_unit_handle_t adc1_handle = NULL;
static adc_cali_handle_t adc1_cali_chan0_handle = NULL;
static float ema_voltage = 0.0f;
static uint8_t bl_level = 0;

// The backlight dimmer starts at full brightness on a rising edge after
// being off, and each short low pulse steps it down one level (wrapping
// back to max). Holding the line low for >2.5ms shuts it down.
static void set_backlight(uint8_t value)
{
    if (value > BACKLIGHT_STEPS) {
        value = BACKLIGHT_STEPS;
    }
    if (value == 0) {
        gpio_set_level(BACKLIGHT_GPIO, 0);
        esp_rom_delay_us(3000);
        bl_level = 0;
        return;
    }
    if (bl_level == 0) {
        gpio_set_level(BACKLIGHT_GPIO, 1);
        esp_rom_delay_us(30);
        bl_level = BACKLIGHT_STEPS;
    }
    const int num = (BACKLIGHT_STEPS + bl_level - value) % BACKLIGHT_STEPS;
    for (int i = 0; i < num; i++) {
        gpio_set_level(BACKLIGHT_GPIO, 0);
        esp_rom_delay_us(1);
        gpio_set_level(BACKLIGHT_GPIO, 1);
        esp_rom_delay_us(1);
    }
    bl_level = value;
}

esp_err_t power_init(void)
{
    gpio_set_direction(BOARD_POWERON_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(BOARD_POWERON_GPIO, 1);

    gpio_set_direction(BACKLIGHT_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(BACKLIGHT_GPIO, 0);

    adc_oneshot_unit_init_cfg_t init_config1 = { .unit_id = ADC_UNIT_1 };
    ESP_ERROR_CHECK(adc_oneshot_new_unit(&init_config1, &adc1_handle));
    JADE_ASSERT(adc1_handle);

    adc_oneshot_chan_cfg_t config = { .atten = BATTERY_ADC_ATTEN, .bitwidth = ADC_BITWIDTH_DEFAULT };
    ESP_ERROR_CHECK(adc_oneshot_config_channel(adc1_handle, BATTERY_ADC_CHANNEL, &config));

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

esp_err_t power_shutdown(void)
{
    esp_deep_sleep_start();
    return ESP_OK;
}

esp_err_t power_screen_on(void) { return ESP_OK; }
esp_err_t power_screen_off(void) { return ESP_OK; }

esp_err_t power_backlight_on(uint8_t brightness)
{
    // Brightness is a level BACKLIGHT_MIN (1) to BACKLIGHT_MAX (5),
    // mapped linearly onto dimmer steps 1 to BACKLIGHT_STEPS.
    if (brightness < BACKLIGHT_MIN) {
        brightness = BACKLIGHT_MIN;
    } else if (brightness > BACKLIGHT_MAX) {
        brightness = BACKLIGHT_MAX;
    }
    const uint8_t scaled
        = 1 + ((BACKLIGHT_STEPS - 1) * (brightness - BACKLIGHT_MIN)) / (BACKLIGHT_MAX - BACKLIGHT_MIN);
    set_backlight(scaled);

    // Have the keyboard backlight track the screen backlight (levels 1-5 -> 51-255)
    tdeck_set_keyboard_backlight(brightness * 51);
    return ESP_OK;
}

esp_err_t power_backlight_off(void)
{
    set_backlight(0);
    tdeck_set_keyboard_backlight(0);
    return ESP_OK;
}

esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

uint16_t power_get_vbat(void)
{
    JADE_ASSERT(adc1_handle);

    // Average several samples to smooth adc noise
    int raw_sum = 0;
    for (int i = 0; i < BATTERY_ADC_SAMPLES; ++i) {
        int raw_adc;
        ESP_ERROR_CHECK(adc_oneshot_read(adc1_handle, BATTERY_ADC_CHANNEL, &raw_adc));
        raw_sum += raw_adc;
    }

    int voltage;
    const int raw_avg = raw_sum / BATTERY_ADC_SAMPLES;
    if (adc1_cali_chan0_handle) {
        ESP_ERROR_CHECK(adc_cali_raw_to_voltage(adc1_cali_chan0_handle, raw_avg, &voltage));
    } else {
        voltage = (raw_avg * 3300) / 4095;
    }

    const float ema_v = (ema_voltage > 0) ? ema_voltage : (float)voltage;
    ema_voltage = (BATTERY_EMA_ALPHA * voltage) + ((1.0f - BATTERY_EMA_ALPHA) * ema_v);
    return (uint16_t)(ema_voltage * BATTERY_VDIV_MULTIPLIER);
}

uint8_t power_get_battery_status(void)
{
    const uint16_t vbat = power_get_vbat();
    if (vbat > 4000) return 5;
    if (vbat > 3800) return 4;
    if (vbat > 3600) return 3;
    if (vbat > 3400) return 2;
    if (vbat > 3200) return 1;
    return 0;
}

bool power_get_battery_charging(void)
{
    // No charger status line on the t-deck - infer charging from usb
    // power being present while the battery is not yet full
    return usb_connected() && power_get_vbat() < BATTERY_CHARGED_MILLIVOLTS;
}

uint16_t power_get_ibat_charge(void) { return 0; }
uint16_t power_get_ibat_discharge(void) { return 0; }
uint16_t power_get_vusb(void) { return 0; }
uint16_t power_get_iusb(void) { return 0; }
uint16_t power_get_temp(void) { return 0; }

void disable_usb_host(void) {}
void enable_usb_host(void) {}

bool usb_is_powered(void) { return usb_connected(); }
