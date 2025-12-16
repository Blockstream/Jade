// twatchs3 implementation
// twatchs3 has AXP2101
//
#include "power/i2c.inc"

#define AXP2101_ADDR 0x34
static i2c_master_dev_handle_t axp2101 = NULL;

static void axp2101_init(void)
{
    // initial stuff
    // Set vbus voltage limit to 4.36v
    _power_write_command(axp2101, 0x15, 6);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    // Set input current limit to 100ma.
    _power_write_command(axp2101, 0x16, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    // Set input current limit to 100ma.
    _power_write_command(axp2101, 0x24, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);

    // FIXME: disable things we do not need
    // TFT backlight
    _power_write_command(axp2101, 0x92, 28);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x93, 28);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    // touch screen driver ALDO3
    _power_write_command(axp2101, 0x94, 28);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x95, 28);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x97, 28);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x80, 1);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x90, 1 + 2 + 4 + 8 + 32);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x91, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);

    // FIXME: implement setbit and clearbit
    _power_write_command(axp2101, 0x40, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x41, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x42, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x48, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x49, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x4A, 0);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x61, 2);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x62, 4);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x63, 1);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    // FIXME: clearbit
    _power_write_command(axp2101, 0x64, 4);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    _power_write_command(axp2101, 0x6A, 7);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    // FIXME: implement setbit
}

esp_err_t power_init(void)
{
    I2C_CHECK_RET(_power_i2c_init());
    I2C_CHECK_RET(_power_i2c_attach_device(AXP2101_ADDR, &axp2101));

    axp2101_init();

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
