// Waveshare S3 Touch LCD 3.5 implementation
// Has an AXP2101 PMU and a TCA9554 io-expander which share the i2c pins with
// both the touch controller and the camera's sccb.  The touchscreen owns the
// only bus on those pins: the pmu and the camera attach to it (see below and
// camera.c), so the bus used here to configure the pmu is released straight away.
//
#include "power/i2c.inc"
#include <driver/gpio.h>
#include <driver/ledc.h>
#include <esp_sleep.h>
#include <freertos/idf_additions.h>

#include "button_gpio.h"
#include "iot_button.h"
#include "power.h"
#include "soc/gpio_num.h"
#include "tusb.h"

#define AXP2101_ADDR 0x34
#define TCA9554_ADDR 0x20

#define LCD_BL_LEDC_TIMER LEDC_TIMER_0
#define LCD_BL_LEDC_MODE LEDC_LOW_SPEED_MODE

#define LCD_BL_LEDC_CHANNEL LEDC_CHANNEL_0
#define LCD_BL_LEDC_DUTY_RES LEDC_TIMER_10_BIT
#define LCD_BL_LEDC_DUTY (1024)
#define LCD_BL_LEDC_FREQUENCY (10000)

static i2c_master_dev_handle_t axp2101 = NULL;
static i2c_master_dev_handle_t tca9554 = NULL;

// The pmu shares the i2c pins with the touchscreen and the camera, so it
// cannot own a bus of its own.  Instead the touchscreen code hands us its bus
// while it exists (see power_i2c_bus_attach()/power_i2c_bus_detach()) and we
// attach the pmu to it - the i2c driver serialises access between devices.
// Until the bus is available we report the last reading.
static SemaphoreHandle_t pmu_mutex = NULL;
static i2c_master_dev_handle_t axp2101_shared = NULL;
static uint16_t cached_vbat = 0;
static uint8_t cached_soc = 0;
static bool cached_charging = false;
static bool cached_vbus = true;

void power_i2c_bus_attach(i2c_master_bus_handle_t bus)
{
    JADE_ASSERT(bus);
    JADE_ASSERT(pmu_mutex);
    xSemaphoreTake(pmu_mutex, portMAX_DELAY);
    if (!axp2101_shared) {
        const i2c_device_config_t cfg = {
            .dev_addr_length = I2C_ADDR_BIT_LEN_7, .device_address = AXP2101_ADDR, .scl_speed_hz = CONFIG_I2C_MASTER_CLK
        };
        I2C_LOG_ANY_ERROR(i2c_master_bus_add_device(bus, &cfg, &axp2101_shared));
    }
    xSemaphoreGive(pmu_mutex);
}

void power_i2c_bus_detach(void)
{
    JADE_ASSERT(pmu_mutex);
    xSemaphoreTake(pmu_mutex, portMAX_DELAY);
    if (axp2101_shared) {
        I2C_LOG_ANY_ERROR(i2c_master_bus_rm_device(axp2101_shared));
        axp2101_shared = NULL;
    }
    xSemaphoreGive(pmu_mutex);
}

// Returns false (leaving 'out' untouched) if the bus is not currently ours
static bool pmu_read(const uint8_t reg, uint8_t* out, const size_t len)
{
    JADE_ASSERT(out);
    if (!pmu_mutex) {
        return false;
    }
    bool ok = false;
    xSemaphoreTake(pmu_mutex, portMAX_DELAY);
    if (axp2101_shared) {
        ok = _power_master_read_slave(axp2101_shared, reg, out, len) == ESP_OK;
    }
    xSemaphoreGive(pmu_mutex);
    return ok;
}

static void tca9554_init(void)
{
    // Set expander pins P0 and P1 as outputs, drive both low, then release P1
    // (display/peripheral power sequencing - same sequence the vendor demo uses)
    _power_write_command(tca9554, 0x03, 0xFC);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(tca9554, 0x01, 0x00);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(tca9554, 0x01, 0x02);
}

static void axp2101_init(void)
{
    static const uint8_t settings[][2] = {
        { 0x22, 0x06 }, // PWRON > OFFLEVEL as POWEROFF source
        { 0x27, 0x10 }, // hold 4s to power off via PWRON
        { 0x80, 0x01 }, // disable all DCs except DC1
        { 0x90, 0x00 }, // disable all LDOs
        { 0x91, 0x00 }, // disable all LDOs
        { 0x82, 0x12 }, // DC1 3.3v
        { 0x92, 0x1C }, // ALDO1 3.3v
        { 0x96, 0x0A }, // BLDO1 1.5v (camera DVDD)
        { 0x97, 0x17 }, // BLDO2 2.8v (camera AVDD)
        { 0x90, 0x31 }, // enable ALDO1, BLDO1, BLDO2
        { 0x64, 0x02 }, // charge voltage 4.1v
        { 0x61, 0x02 }, // precharge current 50ma
        { 0x62, 0x0A }, // charge current 400ma
        { 0x63, 0x01 }, // charge termination current 25ma
        { 0x30, 0x1D }, // enable VBAT/VBUS/VSYS/TDIE adc
    };

    for (size_t i = 0; i < sizeof(settings) / sizeof(settings[0]); ++i) {
        _power_write_command(axp2101, settings[i][0], settings[i][1]);
    }
}

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
    JADE_ASSERT(!pmu_mutex);
    pmu_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(pmu_mutex);

    I2C_CHECK_RET(_power_i2c_init());
    I2C_CHECK_RET(_power_i2c_attach_device(TCA9554_ADDR, &tca9554));
    I2C_CHECK_RET(_power_i2c_attach_device(AXP2101_ADDR, &axp2101));

    tca9554_init();
    axp2101_init();

    vTaskDelay(100 / portTICK_PERIOD_MS);
    // Release the bus so the touchscreen can create its own on these pins.
    // Since IDF 5.5 the i2c bus cannot be deleted while devices are attached.
    I2C_CHECK_RET(i2c_master_bus_rm_device(tca9554));
    I2C_CHECK_RET(i2c_master_bus_rm_device(axp2101));
    I2C_CHECK_RET(_i2c_deinit(NULL));

    // Use the BOOT button as a sleep/wakeup button
    ESP_ERROR_CHECK(boot_button_init());
    // Initialise backlight brightness
    ESP_ERROR_CHECK(brightness_init());

    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
    // NOTE: cannot use the pmu soft-poweroff as the i2c bus has been released
    esp_deep_sleep_start();
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
    const uint32_t duty = (brightness * (LCD_BL_LEDC_DUTY - 1)) / 5;
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

// Camera rails (BLDO1/BLDO2) are left enabled from power_init()
esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

uint16_t power_get_vbat(void)
{
    // 14-bit adc value split over two registers, lsb is 1mv
    uint8_t buf[2] = { 0, 0 };
    if (pmu_read(0x34, buf, sizeof(buf))) {
        cached_vbat = ((buf[0] & 0x3F) << 8) | buf[1];
    }
    return cached_vbat;
}

uint8_t power_get_battery_status(void)
{
    uint8_t soc = 0;
    if (pmu_read(0xA4, &soc, sizeof(soc))) {
        cached_soc = soc;
    }
    if (cached_soc > 90) {
        return 5;
    } else if (cached_soc > 70) {
        return 4;
    } else if (cached_soc > 50) {
        return 3;
    } else if (cached_soc > 30) {
        return 2;
    } else if (cached_soc > 10) {
        return 1;
    }
    return 0;
}

bool power_get_battery_charging(void)
{
    uint8_t status = 0;
    if (pmu_read(0x01, &status, sizeof(status))) {
        // status2 bits [6:5]: 01 = charging
        cached_charging = ((status >> 5) & 0x03) == 0x01;
    }
    return cached_charging;
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
    uint8_t status = 0;
    if (pmu_read(0x00, &status, sizeof(status))) {
        // status1 bit 5: vbus present and good
        cached_vbus = (status & (1 << 5)) != 0;
    }
    return cached_vbus;
}
