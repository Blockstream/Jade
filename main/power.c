#include "power.h"
#include "jade_assert.h"
#include <driver/adc_common.h>
#include <sdkconfig.h>

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
// Code common to JADE v1 and v1.1 - ie. using AXP
#include <driver/i2c.h>

#define I2C_BATTERY_PORT I2C_NUM_0

#define ACK_CHECK_EN 0x1 /*!< I2C master will check ack from slave*/
#define ACK_CHECK_DIS 0x0 /*!< I2C master will not check ack from slave */
#define ACK_VAL 0x0 /*!< I2C ack value */
#define NACK_VAL 0x1 /*!< I2C nack value */

#define I2C_CHECK_RET(expr)                                                                                            \
    do {                                                                                                               \
        const esp_err_t res = (expr);                                                                                  \
        if (res != ESP_OK) {                                                                                           \
            JADE_LOGE("i2c call returned: %u", res);                                                                   \
            return res;                                                                                                \
        }                                                                                                              \
    } while (false)
#define I2C_LOG_ANY_ERROR(expr)                                                                                        \
    do {                                                                                                               \
        const esp_err_t res = (expr);                                                                                  \
        if (res != ESP_OK) {                                                                                           \
            JADE_LOGE("i2c call returned: %u", res);                                                                   \
        }                                                                                                              \
    } while (false)

static esp_err_t master_write_slave(uint8_t address, uint8_t* data_wr, size_t size)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();

    I2C_LOG_ANY_ERROR(i2c_master_start(cmd));
    I2C_LOG_ANY_ERROR(i2c_master_write_byte(cmd, (address << 1) | I2C_MASTER_WRITE, true));
    I2C_LOG_ANY_ERROR(i2c_master_write(cmd, data_wr, size, true));
    I2C_LOG_ANY_ERROR(i2c_master_stop(cmd));

    const esp_err_t ret = i2c_master_cmd_begin(I2C_BATTERY_PORT, cmd, 1000 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(ret);

    i2c_cmd_link_delete(cmd);
    return ret;
}

static esp_err_t master_read_slave(uint8_t address, uint8_t register_address, uint8_t* data_rd, size_t size)
{
    if (size == 0) {
        return ESP_OK;
    }

    I2C_CHECK_RET(master_write_slave(address, &register_address, 1));

    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    I2C_LOG_ANY_ERROR(i2c_master_start(cmd));
    I2C_LOG_ANY_ERROR(i2c_master_write_byte(cmd, (address << 1) | I2C_MASTER_READ, ACK_CHECK_EN));
    if (size > 1) {
        I2C_LOG_ANY_ERROR(i2c_master_read(cmd, data_rd, size - 1, ACK_VAL));
    }

    I2C_LOG_ANY_ERROR(i2c_master_read_byte(cmd, data_rd + size - 1, NACK_VAL));
    I2C_LOG_ANY_ERROR(i2c_master_stop(cmd));

    const esp_err_t ret = i2c_master_cmd_begin(I2C_BATTERY_PORT, cmd, 1000 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(ret);

    i2c_cmd_link_delete(cmd);
    return ret;
}

static esp_err_t write_command(uint8_t reg, uint8_t val)
{
    uint8_t arr[] = { reg, val };
    I2C_CHECK_RET(master_write_slave(0x34, arr, 2));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return ESP_OK;
}

// Logical commands - some differ between Jade_v1 and Jade_v1.1
static esp_err_t power_enable_adcs(void) { return write_command(0x82, 0xff); }
static esp_err_t power_enable_charging(void) { return write_command(0x33, 0xc0); }
static esp_err_t power_setup_pek(void) { return write_command(0x36, 0x5c); }

static esp_err_t power_enable_dc_dc1(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return write_command(0x12, 0x01);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return write_command(0x12, 0x4d);
#endif
}

static esp_err_t power_open_drain_gpio(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return write_command(0x95, 0x85);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return write_command(0x95, 0x05);
#endif
}

#ifdef CONFIG_BOARD_TYPE_JADE
static esp_err_t power_enable_dc_dc2(void) { return write_command(0x10, 0xff); }
static esp_err_t power_set_camera_voltage(void) { return write_command(0x28, 0xf0); }
static esp_err_t power_enable_coulomb_counter(void) { return write_command(0xb8, 0x80); }
static esp_err_t power_set_v_off(void) { return write_command(0x31, 0x04); }
#endif // CONFIG_BOARD_TYPE_JADE

#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
static esp_err_t power_gpio0_to_ldo(void) { return write_command(0x90, 0x02); }
static esp_err_t power_vbus_hold_limit(void) { return write_command(0x30, 0x80); }
static esp_err_t power_temperature_protection(void) { return write_command(0x39, 0xfc); }
static esp_err_t power_bat_detection(void) { return write_command(0x32, 0x46); }

static esp_err_t power_display_on(void)
{
    uint8_t buf1;
    master_read_slave(0x34, 0x96, &buf1, 1);
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return write_command(0x96, buf1 | 0x02);
}

static esp_err_t power_display_off(void)
{
    uint8_t buf1;
    master_read_slave(0x34, 0x96, &buf1, 1);
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return write_command(0x96, buf1 & (~0x02));
}
#endif // CONFIG_BOARD_TYPE_JADE_V1_1

esp_err_t power_backlight_on(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return write_command(0x91, 0xc0);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return write_command(0x90, 0x02);
#endif
}

esp_err_t power_backlight_off(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return write_command(0x91, 0x00);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return write_command(0x90, 0x01);
#endif
}

// Exported funtions
esp_err_t power_init(void)
{
    const i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = CONFIG_AXP_SDA,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_io_num = CONFIG_AXP_SCL,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = 400000,
        .clk_flags = 0,
    };

    I2C_CHECK_RET(i2c_param_config(I2C_BATTERY_PORT, &conf));
    I2C_CHECK_RET(i2c_driver_install(I2C_BATTERY_PORT, conf.mode, 0, 0, 0));

    // Set ADC to All Enable
    // Enable Bat,ACIN,VBUS,APS adc
    power_enable_adcs();

    // Bat charge voltage to 4.2, Current 100MA
    power_enable_charging();

    // Disble Ext, LDO2, LDO3. DCDC3, enable DCDC1
    power_enable_dc_dc1();

    // 128ms power on, 4s power off
    power_setup_pek();

    // GPIO4 NMOS output | GPIO3 NMOS output
    power_open_drain_gpio();

#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    // Set GPIO0 to LDO
    power_gpio0_to_ldo();

    // Disable vbus hold limit
    power_vbus_hold_limit();

    // Set temperature protection
    power_temperature_protection();

    // Enable bat detection
    power_bat_detection();

#else // ie. CONFIG_BOARD_TYPE_JADE
    power_set_camera_voltage();
    power_enable_dc_dc2();
    power_enable_coulomb_counter();
    power_set_v_off();
#endif

#ifndef CONFIG_ESP32_NO_BLOBS
    /**
     * There is a bug around using GPIO36/39 with ADC/WiFi (BLE) with sleep mode.
     * We use:
     * PIN 36: Camera D6
     * PIN 39: v1.0 - Camera D4, v1.1 - wheel-next, M5Stack - wheel-prev
     *
     * This conflict can cause 'button-release' events to be missed, and hence the fw thinks the hw button
     * is being held pressed, when it has in fact been released.
     *
     * From espressif docs:
     * Please do not use the interrupt of GPIO36 and GPIO39 when using ADC or Wi-Fi with sleep mode enabled.
     * Please refer to the comments of adc1_get_raw. Please refer to section 3.11 of
     * ‘ECO_and_Workarounds_for_Bugs_in_ESP32’ for the description of this issue.
     * As a workaround, call adc_power_acquire() in the app. This will result in higher power consumption
     * (by ~1mA), but will remove the glitches on GPIO36 and GPIO39.
     */
    adc_power_acquire();
#endif // CONFIG_ESP32_NO_BLOBS

    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
    return write_command(0x32, 0x80);
    return ESP_OK;
}

esp_err_t power_screen_on(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    // Reset display
    power_display_on();
    vTaskDelay(10 / portTICK_PERIOD_MS);
    power_display_off();
    vTaskDelay(20 / portTICK_PERIOD_MS);
    power_display_on();
    vTaskDelay(200 / portTICK_PERIOD_MS);
#endif
    return power_backlight_off();
}

esp_err_t power_screen_off(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    power_display_off();
#endif
    return power_backlight_off();
}

esp_err_t power_camera_on(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    uint8_t buf1;
    master_read_slave(0x34, 0x96, &buf1, 1);
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return write_command(0x96, buf1 | 0x01);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return write_command(0x96, 0x03);
#endif
}

esp_err_t power_camera_off(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    uint8_t buf1;
    master_read_slave(0x34, 0x96, &buf1, 1);
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return write_command(0x96, buf1 & (~0x01));
#else // ie. CONFIG_BOARD_TYPE_JADE
    return write_command(0x96, 0x01);
#endif
}

uint16_t power_get_vbat(void)
{
    uint16_t vbat = 0;
    uint8_t buf1, buf2;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x78, &buf1, 1));
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x79, &buf2, 1));
    vbat = ((buf1 << 4) + buf2) * 1.1;
    return vbat;
}

uint8_t power_get_battery_status(void)
{
    const uint16_t vbat = power_get_vbat();
    if (vbat > 4000) {
        return 5;
    } else if (vbat > 3850) {
        return 4;
    } else if (vbat > 3700) {
        return 3;
    } else if (vbat > 3550) {
        return 2;
    } else if (vbat > 3400) {
        return 1;
    }
    return 0;
}

bool power_get_battery_charging(void)
{
    bool charging = false;
    uint8_t buf;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x01, &buf, 1));
    charging = (buf & 0b01000000) >> 6;
    return charging;
}

uint16_t power_get_ibat_charge(void)
{
    uint16_t ibat = 0;
    uint8_t buf1, buf2;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x7A, &buf1, 1));
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x7B, &buf2, 1));
    ibat = (buf1 << 5) + buf2;
    return ibat;
}

uint16_t power_get_ibat_discharge(void)
{
    uint16_t ibat = 0;
    uint8_t buf1, buf2;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x7C, &buf1, 1));
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x7D, &buf2, 1));
    ibat = (buf1 << 5) + buf2;
    return ibat;
}

uint16_t power_get_vusb(void)
{
    uint16_t vusb = 0;
    uint8_t buf1, buf2;
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x56, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x57, &buf2, 1));
#else // ie. CONFIG_BOARD_TYPE_JADE
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x5a, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x5b, &buf2, 1));
#endif
    vusb = ((buf1 << 4) + buf2) * 1.7;
    return vusb;
}

uint16_t power_get_iusb(void)
{
    uint16_t iusb = 0;
    uint8_t buf1, buf2;
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x58, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x59, &buf2, 1));
#else // ie. CONFIG_BOARD_TYPE_JADE
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x5c, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x5d, &buf2, 1));
#endif
    iusb = ((buf1 << 4) + buf2) * 0.375;
    return iusb;
}

uint16_t power_get_temp(void)
{
    uint16_t temp = 0;
    uint8_t buf1, buf2;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x5e, &buf1, 1));
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x5f, &buf2, 1));
    temp = ((buf1 << 4) + buf2) * 0.1 - 144.7;
    return temp;
}

bool usb_connected(void)
{
    bool is_usb_connected = false;
    uint8_t buf;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x00, &buf, 1));
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    is_usb_connected = buf & 0b10000000;
#else
    is_usb_connected = buf & 0b00100000;
#endif
    return is_usb_connected;
}

#else // ie. not CONFIG_BOARD_TYPE_JADE or CONFIG_BOARD_TYPE_JADE_V1_1
// Stubs for non-Jade hw boards (ie. no AXP)
#include <esp_sleep.h>

esp_err_t power_init(void) { return ESP_OK; }

esp_err_t power_shutdown(void)
{
    // If we don't have AXP, use esp_deep_sleep
    esp_deep_sleep_start();
    return ESP_OK;
}

esp_err_t power_screen_on(void) { return ESP_OK; }
esp_err_t power_screen_off(void) { return ESP_OK; }

esp_err_t power_backlight_on(void) { return ESP_OK; }
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

bool usb_connected(void) { return true; }

#endif
