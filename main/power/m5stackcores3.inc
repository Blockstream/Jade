// M5StackCores3 implementation
// M5 Core S3 has AXP2101
//
#include "power/i2c.inc"
#include <esp_sleep.h>

#define AXP2101_ADDR 0x34
#define AW9523_ADDR 0x58

static i2c_master_dev_handle_t axp2101 = NULL;
static i2c_master_dev_handle_t aw9523 = NULL;

static void axp2101_init(void)
{
    _power_write_command(axp2101, 0x90, 0xBF); // AXP ALDO~4,BLDO0~2,DIDO1 Enable
    _power_write_command(axp2101, 0x94, 33 - 5); // camera
    _power_write_command(axp2101, 0x99, 0b11110 - 5); // DLDO1
}

static void aw9523_init(void)
{

    _power_write_command(aw9523, 0x7F, 0x00);
    vTaskDelay(30);
    _power_write_command(aw9523, 0x04, 0b11011000);
    vTaskDelay(30);
    _power_write_command(aw9523, 0x05, 0b01111100);
    vTaskDelay(30);
    _power_write_command(aw9523, 0x12, 0b11111111);
    vTaskDelay(30);
    _power_write_command(aw9523, 0x13, 0b11111111);
    vTaskDelay(30);
    _power_write_command(aw9523, 0x11, (1 << 4));
    vTaskDelay(30);
    _power_write_command(aw9523, 0x02, 0b00000101);
    vTaskDelay(30);
    _power_write_command(aw9523, 0x03, 0b00000011);
    vTaskDelay(30);
}

esp_err_t power_init(void)
{
    I2C_CHECK_RET(_power_i2c_init());
    I2C_CHECK_RET(_power_i2c_attach_device(AXP2101_ADDR, &axp2101));
    I2C_CHECK_RET(_power_i2c_attach_device(AW9523_ADDR, &aw9523));

    aw9523_init();
    axp2101_init();

    vTaskDelay(100 / portTICK_PERIOD_MS);
    I2C_CHECK_RET(_i2c_deinit(NULL));

    return ESP_OK;
}

void disable_usb_host(void) {}

void enable_usb_host(void) {}

esp_err_t power_shutdown(void) { return ESP_OK; }

esp_err_t power_screen_on(void) { return ESP_OK; }

esp_err_t power_backlight_on(const uint8_t brightness) { return ESP_OK; }

esp_err_t power_backlight_off(void) { return ESP_OK; }

esp_err_t power_camera_on(void) { return ESP_OK; }

esp_err_t power_camera_off(void) { return ESP_OK; }

uint16_t power_get_vbat(void) { return 0; }

uint8_t power_get_battery_status(void) { return 0; }

uint16_t power_get_ibat_charge(void) { return 0; }

uint16_t power_get_ibat_discharge(void) { return 0; }

bool power_get_battery_charging(void) { return 0; }

uint16_t power_get_vusb(void) { return 0; }

uint16_t power_get_iusb(void) { return 0; }

uint16_t power_get_temp(void) { return 0; }

bool usb_is_powered(void) { return false; }
