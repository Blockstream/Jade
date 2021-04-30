#include "power.h"
#include "jade_assert.h"
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
static esp_err_t power_enable_adcs() { return write_command(0x82, 0xff); }
static esp_err_t power_enable_charging() { return write_command(0x33, 0xc0); }
static esp_err_t power_setup_pek() { return write_command(0x36, 0x5c); }

static esp_err_t power_enable_dc_dc1()
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return write_command(0x12, 0x01);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return write_command(0x12, 0x4d);
#endif
}

static esp_err_t power_open_drain_gpio()
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return write_command(0x95, 0x85);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return write_command(0x95, 0x05);
#endif
}

#ifdef CONFIG_BOARD_TYPE_JADE
static esp_err_t power_enable_dc_dc2() { return write_command(0x10, 0xff); }
static esp_err_t power_set_camera_voltage() { return write_command(0x28, 0xf0); }
static esp_err_t power_enable_coulomb_counter() { return write_command(0xb8, 0x80); }
static esp_err_t power_set_v_off() { return write_command(0x31, 0x04); }
#endif // CONFIG_BOARD_TYPE_JADE

#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
static esp_err_t power_gpio0_to_ldo() { return write_command(0x90, 0x02); }
static esp_err_t power_vbus_hold_limit() { return write_command(0x30, 0x80); }
static esp_err_t power_temperature_protection() { return write_command(0x39, 0xfc); }
static esp_err_t power_bat_detection() { return write_command(0x32, 0x46); }

static esp_err_t power_display_on()
{
    uint8_t buf1;
    master_read_slave(0x34, 0x96, &buf1, 1);
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return write_command(0x96, buf1 | 0x02);
}

static esp_err_t power_display_off()
{
    uint8_t buf1;
    master_read_slave(0x34, 0x96, &buf1, 1);
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return write_command(0x96, buf1 & (~0x02));
}
#endif // CONFIG_BOARD_TYPE_JADE_V1_1

static esp_err_t power_backlight_on()
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return write_command(0x91, 0xc0);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return write_command(0x90, 0x02);
#endif
}

static esp_err_t power_backlight_off()
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return write_command(0x91, 0x00);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return write_command(0x90, 0x01);
#endif
}

// Exported funtions
esp_err_t power_init()
{
    i2c_config_t conf;
    conf.mode = I2C_MODE_MASTER;
    conf.sda_io_num = CONFIG_AXP_SDA;
    conf.sda_pullup_en = GPIO_PULLUP_ENABLE;
    conf.scl_io_num = CONFIG_AXP_SCL;
    conf.scl_pullup_en = GPIO_PULLUP_ENABLE;
    conf.master.clk_speed = 400000;

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
    // Set screen blck (GPIO0-LED) to 3.0V
    power_backlight_on();

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

    return ESP_OK;
}

esp_err_t power_shutdown()
{
    return write_command(0x32, 0x80);
    return ESP_OK;
}

esp_err_t power_screen_on()
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
    return power_backlight_on();
}

esp_err_t power_screen_off()
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    power_display_off();
#endif
    return power_backlight_off();
}

esp_err_t power_camera_on()
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

esp_err_t power_camera_off()
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

uint16_t power_get_vbat()
{
    uint16_t vbat = 0;
    uint8_t buf1, buf2;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x78, &buf1, 1));
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x79, &buf2, 1));
    vbat = ((buf1 << 4) + buf2) * 1.1;
    return vbat;
}

uint8_t power_get_battery_status()
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

bool power_get_battery_charging()
{
    bool charging = false;
    uint8_t buf;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x01, &buf, 1));
    charging = (buf & 0b01000000) >> 6;
    return charging;
}

uint16_t power_get_ibat_charge()
{
    uint16_t ibat = 0;
    uint8_t buf1, buf2;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x7A, &buf1, 1));
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x7B, &buf2, 1));
    ibat = (buf1 << 5) + buf2;
    return ibat;
}

uint16_t power_get_ibat_discharge()
{
    uint16_t ibat = 0;
    uint8_t buf1, buf2;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x7C, &buf1, 1));
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x7D, &buf2, 1));
    ibat = (buf1 << 5) + buf2;
    return ibat;
}

uint16_t power_get_vusb()
{
    uint16_t vusb = 0;
    uint8_t buf1, buf2;
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    ESP_ERROR_CHECK(master_read_slave(0x34, 0x56, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(master_read_slave(0x34, 0x57, &buf2, 1));
#else // ie. CONFIG_BOARD_TYPE_JADE
    ESP_ERROR_CHECK(master_read_slave(0x34, 0x5a, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(master_read_slave(0x34, 0x5b, &buf2, 1));
#endif
    vusb = ((buf1 << 4) + buf2) * 1.7;
    return vusb;
}

uint16_t power_get_iusb()
{
    uint16_t iusb = 0;
    uint8_t buf1, buf2;
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    ESP_ERROR_CHECK(master_read_slave(0x34, 0x58, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(master_read_slave(0x34, 0x59, &buf2, 1));
#else // ie. CONFIG_BOARD_TYPE_JADE
    ESP_ERROR_CHECK(master_read_slave(0x34, 0x5c, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(master_read_slave(0x34, 0x5d, &buf2, 1));
#endif
    iusb = ((buf1 << 4) + buf2) * 0.375;
    return iusb;
}

uint16_t power_get_temp()
{
    uint16_t temp = 0;
    uint8_t buf1, buf2;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x5e, &buf1, 1));
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x5f, &buf2, 1));
    temp = ((buf1 << 4) + buf2) * 0.1 - 144.7;
    return temp;
}

bool usb_connected()
{
    bool is_usb_connected = false;
    uint8_t buf;
    I2C_LOG_ANY_ERROR(master_read_slave(0x34, 0x00, &buf, 1));
    is_usb_connected = buf & 0b00100000;
    return is_usb_connected;
}

#else // ie. not CONFIG_BOARD_TYPE_JADE or CONFIG_BOARD_TYPE_JADE_V1_1
// Stubs for non-Jade hw boards (ie. no AXP)
#include <esp_sleep.h>

esp_err_t power_init() { return ESP_OK; }

esp_err_t power_shutdown()
{
    // If we don't have AXP, use esp_deep_sleep
    esp_deep_sleep_start();
    return ESP_OK;
}

esp_err_t power_screen_on() { return ESP_OK; }
esp_err_t power_screen_off() { return ESP_OK; }

esp_err_t power_camera_on() { return ESP_OK; }
esp_err_t power_camera_off() { return ESP_OK; }

uint16_t power_get_vbat() { return 0; }
uint8_t power_get_battery_status() { return 0; }
bool power_get_battery_charging() { return false; }
uint16_t power_get_ibat_charge() { return 0; }
uint16_t power_get_ibat_discharge() { return 0; }
uint16_t power_get_vusb() { return 0; }
uint16_t power_get_iusb() { return 0; }
uint16_t power_get_temp() { return 0; }

bool usb_connected() { return true; }

#endif
