#include "power.h"
#include "jade_assert.h"
#include <sdkconfig.h>

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)                                            \
    || defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS) || defined(CONFIG_BOARD_TYPE_M5_BLACK_GRAY)                           \
    || defined(CONFIG_BOARD_TYPE_M5_FIRE)
// Code common to all devices that communicate with a PMU via i2c
#include <driver/i2c.h>

static SemaphoreHandle_t i2c_mutex = NULL;

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

// NOTE: i2c_mutex must be claimed before calling
static esp_err_t _power_master_write_slave(uint8_t address, uint8_t* data_wr, size_t size)
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

// NOTE: i2c_mutex must be claimed before calling
static esp_err_t _power_master_read_slave(uint8_t address, uint8_t register_address, uint8_t* data_rd, size_t size)
{
    if (size == 0) {
        return ESP_OK;
    }

    I2C_CHECK_RET(_power_master_write_slave(address, &register_address, 1));

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

#endif

#if defined(CONFIG_HAS_AXP)
// Some common functions used when AXP192 is present
static esp_err_t _power_write_command(uint8_t reg, uint8_t val)
{
    uint8_t arr[] = { reg, val };
    I2C_CHECK_RET(_power_master_write_slave(0x34, arr, 2));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return ESP_OK;
}
#endif

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
// Code common to JADE v1 and v1.1 - ie. using AXP
#include <esp_private/adc_share_hw_ctrl.h>

// Logical commands - some differ between Jade_v1 and Jade_v1.1
static esp_err_t _power_enable_adcs(void) { return _power_write_command(0x82, 0xff); }
static esp_err_t _power_enable_charging(void) { return _power_write_command(0x33, 0xc0); }
static esp_err_t _power_setup_pek(void) { return _power_write_command(0x36, 0x5c); }

static esp_err_t _power_enable_dc_dc1(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return _power_write_command(0x12, 0x01);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return _power_write_command(0x12, 0x4d);
#endif
}

static esp_err_t _power_open_drain_gpio(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return _power_write_command(0x95, 0x85);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return _power_write_command(0x95, 0x05);
#endif
}

#ifdef CONFIG_BOARD_TYPE_JADE
static esp_err_t _power_enable_dc_dc2(void) { return _power_write_command(0x10, 0xff); }
static esp_err_t _power_set_camera_voltage(void) { return _power_write_command(0x28, 0xf0); }
static esp_err_t _power_enable_coulomb_counter(void) { return _power_write_command(0xb8, 0x80); }
static esp_err_t _power_set_v_off(void) { return _power_write_command(0x31, 0x04); }
#endif // CONFIG_BOARD_TYPE_JADE

#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
static esp_err_t _power_gpio0_to_ldo(void) { return _power_write_command(0x90, 0x02); }
static esp_err_t _power_vbus_hold_limit(void) { return _power_write_command(0x30, 0x80); }
static esp_err_t _power_temperature_protection(void) { return _power_write_command(0x39, 0xfc); }
static esp_err_t _power_bat_detection(void) { return _power_write_command(0x32, 0x46); }

static esp_err_t _power_display_on(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(0x96, buf1 | 0x02);
}

static esp_err_t _power_display_off(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(0x96, buf1 & (~0x02));
}
#endif // CONFIG_BOARD_TYPE_JADE_V1_1

esp_err_t power_backlight_on(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return _power_write_command(0x91, 0xc0);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return _power_write_command(0x90, 0x02);
#endif
}

esp_err_t power_backlight_off(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return _power_write_command(0x91, 0x00);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return _power_write_command(0x90, 0x01);
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

    // Create i2c mutex semaphore
    i2c_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(i2c_mutex);

    // Set ADC to All Enable
    // Enable Bat,ACIN,VBUS,APS adc
    _power_enable_adcs();

    // Bat charge voltage to 4.2, Current 100MA
    _power_enable_charging();

    // Disble Ext, LDO2, LDO3. DCDC3, enable DCDC1
    _power_enable_dc_dc1();

    // 128ms power on, 4s power off
    _power_setup_pek();

    // GPIO4 NMOS output | GPIO3 NMOS output
    _power_open_drain_gpio();

#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    // Set GPIO0 to LDO
    _power_gpio0_to_ldo();

    // Disable vbus hold limit
    _power_vbus_hold_limit();

    // Set temperature protection
    _power_temperature_protection();

    // Enable bat detection
    _power_bat_detection();

#else // ie. CONFIG_BOARD_TYPE_JADE
    _power_set_camera_voltage();
    _power_enable_dc_dc2();
    _power_enable_coulomb_counter();
    _power_set_v_off();
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
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    const esp_err_t ret = _power_write_command(0x32, 0x80);
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ret;
}

esp_err_t power_screen_on(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    // Reset display
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    _power_display_on();
    vTaskDelay(10 / portTICK_PERIOD_MS);
    _power_display_off();
    vTaskDelay(20 / portTICK_PERIOD_MS);
    _power_display_on();
    vTaskDelay(200 / portTICK_PERIOD_MS);
    JADE_SEMAPHORE_GIVE(i2c_mutex);
#endif
    // We don't actually want to enable the backlight at this point
    return power_backlight_off();
}

esp_err_t power_screen_off(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    _power_display_off();
    JADE_SEMAPHORE_GIVE(i2c_mutex);
#endif
    return power_backlight_off();
}

esp_err_t power_camera_on(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    const esp_err_t ret = _power_write_command(0x96, buf1 | 0x01);
#else // ie. CONFIG_BOARD_TYPE_JADE
    const esp_err_t ret = _power_write_command(0x96, 0x03);
#endif
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ret;
}

esp_err_t power_camera_off(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    const esp_err_t ret = _power_write_command(0x96, buf1 & (~0x01));
#else // ie. CONFIG_BOARD_TYPE_JADE
    const esp_err_t ret = _power_write_command(0x96, 0x01);
#endif
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ret;
}

uint16_t power_get_vbat(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x78, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x79, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t vbat = ((buf1 << 4) + buf2) * 1.1;
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
    uint8_t buf;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x01, &buf, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const bool charging = (buf & 0b01000000) >> 6;
    return charging;
}

uint16_t power_get_ibat_charge(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x7A, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x7B, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t ibat = (buf1 << 5) + buf2;
    return ibat;
}

uint16_t power_get_ibat_discharge(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x7C, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x7D, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t ibat = (buf1 << 5) + buf2;
    return ibat;
}

uint16_t power_get_vusb(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x56, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x57, &buf2, 1));
#else // ie. CONFIG_BOARD_TYPE_JADE
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5a, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5b, &buf2, 1));
#endif
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t vusb = ((buf1 << 4) + buf2) * 1.7;
    return vusb;
}

uint16_t power_get_iusb(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x58, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x59, &buf2, 1));
#else // ie. CONFIG_BOARD_TYPE_JADE
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5c, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5d, &buf2, 1));
#endif
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t iusb = ((buf1 << 4) + buf2) * 0.375;
    return iusb;
}

uint16_t power_get_temp(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5e, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5f, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t temp = ((buf1 << 4) + buf2) * 0.1 - 144.7;
    return temp;
}

bool usb_connected(void)
{
    uint8_t buf;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x00, &buf, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    const bool is_usb_connected = buf & 0b10000000;
#else
    const bool is_usb_connected = buf & 0b00100000;
#endif
    return is_usb_connected;
}
#elif defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS) // M5StickC-Plus has AXP192, but configured differently to the Jade

static esp_err_t _power_enable_coulomb_counter(void) { return _power_write_command(0xb8, 0x80); }

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

    // Create i2c mutex semaphore
    i2c_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(i2c_mutex);

    _power_enable_coulomb_counter();

    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    const esp_err_t ret = _power_write_command(0x32, 0x80);
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ret;
}

static esp_err_t _power_display_on(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(0x96, buf1 | 0x02);
}

static esp_err_t _power_display_off(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(0x96, buf1 & (~0x02));
}

esp_err_t power_screen_on(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(0x12, buf1 | 0x08);
}

esp_err_t power_screen_off(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(0x12, buf1 & (~0x08));
}

esp_err_t power_backlight_on(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(0x12, buf1 | 0x04);
}

esp_err_t power_backlight_off(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(0x12, buf1 & (~0x04));
}

esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

uint16_t power_get_vbat(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x78, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x79, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t vbat = ((buf1 << 4) + buf2) * 1.1;
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

uint16_t power_get_ibat_charge(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x7A, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x7B, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t ibat = (buf1 << 5) + buf2;
    return ibat;
}

uint16_t power_get_ibat_discharge(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x7C, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x7D, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t ibat = (buf1 << 5) + buf2;
    return ibat;
}

bool power_get_battery_charging(void)
{
    uint8_t buf;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x01, &buf, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const bool charging = (buf & 0b01000000) >> 6;
    return charging;
}

uint16_t power_get_vusb(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5a, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5b, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t vusb = ((buf1 << 4) + buf2) * 1.7;
    return vusb;
}

uint16_t power_get_iusb(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5c, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5d, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t iusb = ((buf1 << 4) + buf2) * 0.375;
    return iusb;
}

uint16_t power_get_temp(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5e, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x5f, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t temp = ((buf1 << 4) + buf2) * 0.1 - 144.7;
    return temp;
}

bool usb_connected(void)
{
    uint8_t buf;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x34, 0x00, &buf, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    const bool is_usb_connected = buf & 0b00100000;
    return is_usb_connected;
}

#elif defined(CONFIG_BOARD_TYPE_M5_BLACK_GRAY)                                                                         \
    || defined(CONFIG_BOARD_TYPE_M5_FIRE) // M5Stack Basic with IP5303 Power PMU
#include <esp_sleep.h>

esp_err_t power_init(void)
{

    const i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = 21,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_io_num = 22,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = 400000,
        .clk_flags = 0,
    };

    I2C_CHECK_RET(i2c_param_config(I2C_BATTERY_PORT, &conf));
    I2C_CHECK_RET(i2c_driver_install(I2C_BATTERY_PORT, conf.mode, 0, 0, 0));

    // Create i2c mutex semaphore
    i2c_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(i2c_mutex);

    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
    // If we don't have a PMU, use esp_deep_sleep
    esp_deep_sleep_start();
    return ESP_OK;
}

esp_err_t power_screen_on(void) { return ESP_OK; }
esp_err_t power_screen_off(void) { return ESP_OK; }

esp_err_t power_backlight_on(void) { return ESP_OK; }
esp_err_t power_backlight_off(void) { return ESP_OK; }

esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

uint16_t power_get_vbat(void)
{
    uint8_t buf;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x75, 0x78, &buf, 1));
    ;
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    switch (buf & 0xF0) {
    case 0x00:
        return 4150;
    case 0x80:
        return 3900;
    case 0xC0:
        return 3700;
    case 0xE0:
        return 3500;
    default:
        return 3400;
    }
}

uint8_t power_get_battery_status(void)
{
    uint8_t buf;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x75, 0x78, &buf, 1));
    ;
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    // IP5306 only offers battery level in 25% increments, as opposed to the Jade's UI which displays it in 20%. (So
    // skip just 2)
    switch (buf & 0xF0) {
    case 0x00:
        return 5;
    case 0x80:
        return 4;
    case 0xC0:
        return 3;
    case 0xE0:
        return 1;
    default:
        return 0;
    }
}

bool power_get_battery_charging(void)
{
    uint8_t chargedata;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x75, 0x70, &chargedata, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return (chargedata & 0x08) && power_get_battery_status() != 5;
}
uint16_t power_get_ibat_charge(void) { return 0; }
uint16_t power_get_ibat_discharge(void) { return 0; }
uint16_t power_get_vusb(void) { return 0; }
uint16_t power_get_iusb(void) { return 0; }
uint16_t power_get_temp(void) { return 0; }

bool usb_connected(void)
{
    uint8_t chargedata, chargedata2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x75, 0x70, &chargedata, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(0x75, 0x71, &chargedata2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ((chargedata & 0x08) || (chargedata2 & 0x08));
}

#else // ie. not CONFIG_BOARD_TYPE_JADE or CONFIG_BOARD_TYPE_JADE_V1_1, M5Stack or M5Stick
// Stubs for other hw boards (ie. no power management)
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
