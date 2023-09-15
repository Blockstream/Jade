#include "power.h"
#include "jade_assert.h"
#include <sdkconfig.h>

#define AW9523_ADDR 0x58
#define AXP192_ADDR 0x34
#define AXP2101_ADDR 0x34

#if defined(CONFIG_HAS_IP5306) || defined(CONFIG_HAS_AXP)
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
// Some common functions used when AXP192 or AXP2101 are present
static esp_err_t _power_write_command(uint8_t address, uint8_t reg, uint8_t val)
{
    uint8_t arr[] = { reg, val };
    I2C_CHECK_RET(_power_master_write_slave(address, arr, 2));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return ESP_OK;
}
#endif

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1) // Retail Jades have AXP192, but configured
                                                                            // differently to things like M5StickCPlus
// Code common to JADE v1 and v1.1 - ie. using AXP
#include <esp_private/adc_share_hw_ctrl.h>

// Logical commands - some differ between Jade_v1 and Jade_v1.1
static esp_err_t _power_enable_adcs(void) { return _power_write_command(AXP192_ADDR, 0x82, 0xff); }
static esp_err_t _power_enable_charging(void) { return _power_write_command(AXP192_ADDR, 0x33, 0xc0); }
static esp_err_t _power_setup_pek(void) { return _power_write_command(AXP192_ADDR, 0x36, 0x5c); }

static esp_err_t _power_enable_dc_dc1(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return _power_write_command(AXP192_ADDR, 0x12, 0x01);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return _power_write_command(AXP192_ADDR, 0x12, 0x4d);
#endif
}

static esp_err_t _power_open_drain_gpio(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return _power_write_command(AXP192_ADDR, 0x95, 0x85);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return _power_write_command(AXP192_ADDR, 0x95, 0x05);
#endif
}

#ifdef CONFIG_BOARD_TYPE_JADE
static esp_err_t _power_enable_dc_dc2(void) { return _power_write_command(AXP192_ADDR, 0x10, 0xff); }
static esp_err_t _power_set_camera_voltage(void) { return _power_write_command(AXP192_ADDR, 0x28, 0xf0); }
static esp_err_t _power_enable_coulomb_counter(void) { return _power_write_command(AXP192_ADDR, 0xb8, 0x80); }
static esp_err_t _power_set_v_off(void) { return _power_write_command(AXP192_ADDR, 0x31, 0x04); }
#endif // CONFIG_BOARD_TYPE_JADE

#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
static esp_err_t _power_set_dc_dc1_voltage(void) { return _power_write_command(AXP192_ADDR, 0x26, 0x68); } // 3.3v
static esp_err_t _power_gpio0_to_ldo(void) { return _power_write_command(AXP192_ADDR, 0x90, 0x02); }
static esp_err_t _power_vbus_hold_limit(void) { return _power_write_command(AXP192_ADDR, 0x30, 0x80); }
static esp_err_t _power_temperature_protection(void) { return _power_write_command(AXP192_ADDR, 0x39, 0xfc); }
static esp_err_t _power_bat_detection(void) { return _power_write_command(AXP192_ADDR, 0x32, 0x46); }

static esp_err_t _power_display_on(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(AXP192_ADDR, 0x96, buf1 | 0x02);
}

static esp_err_t _power_display_off(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(AXP192_ADDR, 0x96, buf1 & (~0x02));
}
#endif // CONFIG_BOARD_TYPE_JADE_V1_1

esp_err_t power_backlight_on(uint8_t brightness)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    // MIN    -> 1 -> 8  (1000) -> 0x80 - 2.6v
    // DIM    -> 2 -> 9  (1001) -> 0x90 - 2.7v
    // MEDIUM -> 3 -> 10 (1010) -> 0xa0 - 2.8v
    // BRIGHT -> 4 -> 11 (1011) -> 0xb0 - 2.9v
    // MAX    -> 5 -> 12 (1100) -> 0xc0 - 3.0v
    if (brightness < BACKLIGHT_MIN) {
        brightness = BACKLIGHT_MIN;
    } else if (brightness > BACKLIGHT_MAX) {
        brightness = BACKLIGHT_MAX;
    }
    return _power_write_command(AXP192_ADDR, 0x91, ((brightness + 7) << 4));
#else // ie. CONFIG_BOARD_TYPE_JADE
    // dimming not supported - just full on
    return _power_write_command(AXP192_ADDR, 0x90, 0x02);
#endif
}

esp_err_t power_backlight_off(void)
{
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    return _power_write_command(AXP192_ADDR, 0x91, 0x00);
#else // ie. CONFIG_BOARD_TYPE_JADE
    return _power_write_command(AXP192_ADDR, 0x90, 0x01);
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
    // Set the DC-DC1 voltage appropriately
    _power_set_dc_dc1_voltage();

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

#ifdef CONFIG_BT_ENABLED
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
    adc_lock_acquire(ADC_UNIT_1);
#endif // CONFIG_BT_ENABLED

    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    const esp_err_t ret = _power_write_command(AXP192_ADDR, 0x32, 0x80);
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
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    const esp_err_t ret = _power_write_command(AXP192_ADDR, 0x96, buf1 | 0x01);
#else // ie. CONFIG_BOARD_TYPE_JADE
    const esp_err_t ret = _power_write_command(AXP192_ADDR, 0x96, 0x03);
#endif
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ret;
}

esp_err_t power_camera_off(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    const esp_err_t ret = _power_write_command(AXP192_ADDR, 0x96, buf1 & (~0x01));
#else // ie. CONFIG_BOARD_TYPE_JADE
    const esp_err_t ret = _power_write_command(AXP192_ADDR, 0x96, 0x01);
#endif
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ret;
}

uint16_t power_get_vbat(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x78, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x79, &buf2, 1));
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
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x01, &buf, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const bool charging = (buf & 0b01000000) >> 6;
    return charging;
}

uint16_t power_get_ibat_charge(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x7A, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x7B, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t ibat = (buf1 << 5) + buf2;
    return ibat;
}

uint16_t power_get_ibat_discharge(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x7C, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x7D, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t ibat = (buf1 << 5) + buf2;
    return ibat;
}

uint16_t power_get_vusb(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x56, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x57, &buf2, 1));
#else // ie. CONFIG_BOARD_TYPE_JADE
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5a, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5b, &buf2, 1));
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
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x58, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x59, &buf2, 1));
#else // ie. CONFIG_BOARD_TYPE_JADE
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5c, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5d, &buf2, 1));
#endif
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t iusb = ((buf1 << 4) + buf2) * 0.375;
    return iusb;
}

uint16_t power_get_temp(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5e, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5f, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t temp = ((buf1 << 4) + buf2) * 0.1 - 144.7;
    return temp;
}

bool usb_connected(void)
{
    uint8_t buf;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x00, &buf, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    const bool is_usb_connected = buf & 0b10000000;
#else
    const bool is_usb_connected = buf & 0b00100000;
#endif
    return is_usb_connected;
}
#elif defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS)                                                                        \
    || defined(CONFIG_BOARD_TYPE_M5_CORE2) // M5StickC-Plus has AXP192, but configured differently to the Jade

static esp_err_t _power_enable_coulomb_counter(void) { return _power_write_command(AXP192_ADDR, 0xb8, 0x80); }

#if defined(CONFIG_BOARD_TYPE_M5_CORE2)

#define AXP192_GPIO0_SET_LEVEL (0x9400)
#define AXP192_GPIO1_SET_LEVEL (0x9401)
#define AXP192_GPIO2_SET_LEVEL (0x9402)
#define AXP192_GPIO4_SET_LEVEL (0x9601)
#define AXP192_LDO2_ENABLE (0x1200)
#define AXP192_LDO2_SET_VOLTAGE (0x2800)

#define CONFIG_AXP192_DCDC1_VOLTAGE_BIT60 (0x68)
#define CONFIG_AXP192_DCDC3_VOLTAGE_BIT60 (0x54)

#define CONFIG_AXP192_LDO23_VOLTAGE (0x00)
#define CONFIG_AXP192_GPIO0_LDOIO0_VOLTAGE (0x00)

#define CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT6 (0x40)
#define CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT4 (0x10)
#define CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT3 (0x00)
#define CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT2 (0x04)
#define CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT1 (0x02)
#define CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT0 (0x01)

#define CONFIG_AXP192_DCDC13_LDO23_CONTROL                                                                             \
    (CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT6 | CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT4                                 \
        | CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT3 | CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT2                            \
        | CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT1 | CONFIG_AXP192_DCDC13_LDO23_CONTROL_BIT0)

#define CONFIG_AXP192_EXTEN_DCDC2_CONTROL_BIT2 (0x04)
#define CONFIG_AXP192_EXTEN_DCDC2_CONTROL_BIT0 (0x01)

#define CONFIG_AXP192_EXTEN_DCDC2_CONTROL                                                                              \
    (CONFIG_AXP192_EXTEN_DCDC2_CONTROL_BIT2 | CONFIG_AXP192_EXTEN_DCDC2_CONTROL_BIT0)

#define CONFIG_AXP192_GPIO0_CONTROL (0x07)
#define CONFIG_AXP192_GPIO1_CONTROL (0x00)
#define CONFIG_AXP192_GPIO2_CONTROL (0x00)

#define CONFIG_AXP192_GPIO43_FUNCTION_CONTROL_BIT10 (0x01)
#define CONFIG_AXP192_GPIO43_FUNCTION_CONTROL_BIT32 (0x04)
#define CONFIG_AXP192_GPIO43_FUNCTION_CONTROL_BIT7 (0x80)

#define CONFIG_AXP192_GPIO43_FUNCTION_CONTROL                                                                          \
    (CONFIG_AXP192_GPIO43_FUNCTION_CONTROL_BIT7 | CONFIG_AXP192_GPIO43_FUNCTION_CONTROL_BIT32                          \
        | CONFIG_AXP192_GPIO43_FUNCTION_CONTROL_BIT10)

#define CONFIG_AXP192_ADC_ENABLE_1_BIT7 (0x80)
#define CONFIG_AXP192_ADC_ENABLE_1_BIT6 (0x40)
#define CONFIG_AXP192_ADC_ENABLE_1_BIT5 (0x20)
#define CONFIG_AXP192_ADC_ENABLE_1_BIT4 (0x10)
#define CONFIG_AXP192_ADC_ENABLE_1_BIT3 (0x08)
#define CONFIG_AXP192_ADC_ENABLE_1_BIT2 (0x04)
#define CONFIG_AXP192_ADC_ENABLE_1_BIT1 (0x02)
#define CONFIG_AXP192_ADC_ENABLE_1_BIT0 (0x01)

#define CONFIG_AXP192_ADC_ENABLE_1                                                                                     \
    (CONFIG_AXP192_ADC_ENABLE_1_BIT7 | CONFIG_AXP192_ADC_ENABLE_1_BIT6 | CONFIG_AXP192_ADC_ENABLE_1_BIT5               \
        | CONFIG_AXP192_ADC_ENABLE_1_BIT4 | CONFIG_AXP192_ADC_ENABLE_1_BIT3 | CONFIG_AXP192_ADC_ENABLE_1_BIT2          \
        | CONFIG_AXP192_ADC_ENABLE_1_BIT1 | CONFIG_AXP192_ADC_ENABLE_1_BIT0)

#define CONFIG_AXP192_CHARGE_CONTROL_1_BIT7 (0x80)
#define CONFIG_AXP192_CHARGE_CONTROL_1_BIT65 (0x40)
#define CONFIG_AXP192_CHARGE_CONTROL_1_BIT30 (0x00)
#define CONFIG_AXP192_CHARGE_CONTROL_1_BIT4 (0x10)

#define CONFIG_AXP192_CHARGE_CONTROL_1                                                                                 \
    (CONFIG_AXP192_CHARGE_CONTROL_1_BIT7 | CONFIG_AXP192_CHARGE_CONTROL_1_BIT65 | CONFIG_AXP192_CHARGE_CONTROL_1_BIT4  \
        | CONFIG_AXP192_CHARGE_CONTROL_1_BIT30)

#define CONFIG_AXP192_BATTERY_CHARGE_CONTROL (0x00)
#define AXP192_DCDC1_VOLTAGE (0x26)
#define AXP192_DCDC3_VOLTAGE (0x27)
#define AXP192_LDO23_VOLTAGE (0x28)

#define AXP192_GPIO0_CONTROL (0x90)
#define AXP192_GPIO1_CONTROL (0x92)
#define AXP192_GPIO2_CONTROL (0x93)
#define AXP192_GPIO0_LDOIO0_VOLTAGE (0x91)
#define AXP192_DCDC13_LDO23_CONTROL (0x12)
#define AXP192_EXTEN_DCDC2_CONTROL (0x10)
#define AXP192_GPIO43_FUNCTION_CONTROL (0x95)
#define AXP192_ADC_ENABLE_1 (0x82)
#define AXP192_CHARGE_CONTROL_1 (0x33)
#define AXP192_BATTERY_CHARGE_CONTROL (0x35)
#endif

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

#if defined(CONFIG_BOARD_TYPE_M5_CORE2)

    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_DCDC1_VOLTAGE, CONFIG_AXP192_DCDC1_VOLTAGE_BIT60));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_DCDC3_VOLTAGE, CONFIG_AXP192_DCDC3_VOLTAGE_BIT60));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_LDO23_VOLTAGE, CONFIG_AXP192_LDO23_VOLTAGE));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_GPIO0_LDOIO0_VOLTAGE, CONFIG_AXP192_GPIO0_LDOIO0_VOLTAGE));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_DCDC13_LDO23_CONTROL, CONFIG_AXP192_DCDC13_LDO23_CONTROL));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_EXTEN_DCDC2_CONTROL, CONFIG_AXP192_EXTEN_DCDC2_CONTROL));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_GPIO0_CONTROL, CONFIG_AXP192_GPIO0_CONTROL));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_GPIO1_CONTROL, CONFIG_AXP192_GPIO1_CONTROL));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_GPIO2_CONTROL, CONFIG_AXP192_GPIO2_CONTROL));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(
        _power_write_command(AXP192_ADDR, AXP192_GPIO43_FUNCTION_CONTROL, CONFIG_AXP192_GPIO43_FUNCTION_CONTROL));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_ADC_ENABLE_1, CONFIG_AXP192_ADC_ENABLE_1));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_CHARGE_CONTROL_1, CONFIG_AXP192_CHARGE_CONTROL_1));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    ESP_ERROR_CHECK(
        _power_write_command(AXP192_ADDR, AXP192_BATTERY_CHARGE_CONTROL, CONFIG_AXP192_BATTERY_CHARGE_CONTROL));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    vTaskDelay(100 / portTICK_PERIOD_MS);

    uint8_t buf1;
    // M-Bus Power
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, AXP192_GPIO0_SET_LEVEL >> 8, &buf1, 1));
    buf1 |= 0b00000001;
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_GPIO0_SET_LEVEL >> 8, buf1));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    // Enable LED
    // doesn't seem necessary
    /*
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, AXP192_GPIO1_SET_LEVEL >> 8, &buf1, 1));
    buf1 &= ~0b00000010;
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_GPIO1_SET_LEVEL >> 8, buf1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    */

    // disable speaker
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, AXP192_GPIO2_SET_LEVEL >> 8, &buf1, 1));
    buf1 &= ~0b00000100;
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_GPIO2_SET_LEVEL >> 8, buf1));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    // Set LDO2 LCD&TP voltage
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, AXP192_LDO2_SET_VOLTAGE >> 8, &buf1, 1));
    buf1 &= ~0xF0;
    buf1 |= 0xF0;
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_LDO2_SET_VOLTAGE >> 8, buf1));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    // Enable LDO2
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, AXP192_LDO2_ENABLE >> 8, &buf1, 1));
    buf1 |= 0b00000100;
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_LDO2_ENABLE >> 8, buf1));
    vTaskDelay(20 / portTICK_PERIOD_MS);

    // LCD reset
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, AXP192_GPIO4_SET_LEVEL >> 8, &buf1, 1));
    buf1 &= ~0b00000010;
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_GPIO4_SET_LEVEL >> 8, buf1));
    vTaskDelay(100 / portTICK_PERIOD_MS);

    // LCD hold
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, AXP192_GPIO4_SET_LEVEL >> 8, &buf1, 1));
    buf1 |= 0b00000010;
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(_power_write_command(AXP192_ADDR, AXP192_GPIO4_SET_LEVEL >> 8, buf1));
    vTaskDelay(100 / portTICK_PERIOD_MS);
#endif

    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
#if defined(CONFIG_BOARD_TYPE_M5_CORE2)
    return ESP_OK;
#endif
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    const esp_err_t ret = _power_write_command(AXP192_ADDR, 0x32, 0x80);
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ret;
}

esp_err_t power_screen_on(void)
{
#if defined(CONFIG_BOARD_TYPE_M5_CORE2)
    return ESP_OK;
#endif
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
#if defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS)
    return _power_write_command(AXP192_ADDR, 0x12, buf1 | 0x08);
#elif defined(CONFIG_BOARD_TYPE_M5_CORE2)
    return _power_write_command(AXP192_ADDR, 0x12, buf1 | 0x04);
#endif
}

esp_err_t power_screen_off(void)
{
#if defined(CONFIG_BOARD_TYPE_M5_CORE2)
    return ESP_OK;
#endif
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
#if defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS)
    return _power_write_command(AXP192_ADDR, 0x12, buf1 & (~0x08));
#elif defined(CONFIG_BOARD_TYPE_M5_CORE2)
    return _power_write_command(AXP192_ADDR, 0x12, buf1 & (~0x04));
#endif
}

esp_err_t power_backlight_on(uint8_t brightness)
{
#if defined(CONFIG_BOARD_TYPE_M5_CORE2)
    return ESP_OK;
#endif
    uint8_t buf1;
#if defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS)
    // dimming not supported - just full on
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(AXP192_ADDR, 0x12, buf1 | 0x04);
#endif
    if (brightness < BACKLIGHT_MIN) {
        brightness = BACKLIGHT_MIN;
    } else if (brightness > BACKLIGHT_MAX) {
        brightness = BACKLIGHT_MAX;
    }
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x27, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(AXP192_ADDR, 0x27, ((brightness + 7) << 4));
}

esp_err_t power_backlight_off(void)
{
#if defined(CONFIG_BOARD_TYPE_M5_CORE2)
    return ESP_OK;
#endif
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(AXP192_ADDR, 0x12, buf1 & (~0x04));
}

esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

uint16_t power_get_vbat(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x78, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x79, &buf2, 1));
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
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x7A, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x7B, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t ibat = (buf1 << 5) + buf2;
    return ibat;
}

uint16_t power_get_ibat_discharge(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x7C, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x7D, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t ibat = (buf1 << 5) + buf2;
    return ibat;
}

bool power_get_battery_charging(void)
{
    uint8_t buf;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x01, &buf, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const bool charging = (buf & 0b01000000) >> 6;
    return charging;
}

uint16_t power_get_vusb(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5a, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5b, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t vusb = ((buf1 << 4) + buf2) * 1.7;
    return vusb;
}

uint16_t power_get_iusb(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5c, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5d, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t iusb = ((buf1 << 4) + buf2) * 0.375;
    return iusb;
}

uint16_t power_get_temp(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5e, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x5f, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t temp = ((buf1 << 4) + buf2) * 0.1 - 144.7;
    return temp;
}

bool usb_connected(void)
{
    uint8_t buf;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x00, &buf, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    const bool is_usb_connected = buf & 0b00100000;
    return is_usb_connected;
}

#elif defined(CONFIG_HAS_IP5306) // Board with IP5303 Power PMU
#include <esp_sleep.h>

esp_err_t power_init(void)
{

    const i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = CONFIG_IP5306_SDA,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_io_num = CONFIG_IP5306_SCL,
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

esp_err_t power_backlight_on(const uint8_t brightness) { return ESP_OK; }
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

#elif defined(CONFIG_BOARD_TYPE_M5_CORES3) // M5 Core S3 has AXP2101
// FIXME:
// static esp_err_t _power_enable_coulomb_counter(void) { return _power_write_command(AXP2101_ADDR, 0xb8, 0x80); }
/*
static void aw9523_init(void)
{
    //   bus_i2c_write(AXP2101_ADDR, 0x90, 1, cfg | 0x80, 1);
    //_power_write_command(AXP2101_ADDR, 0x90, buf1 | 0x80);

    // aw9523 reset
    _power_write_command(AW9523_ADDR, 0x7F, 0x00);
    // default settings
    //_power_write_command(AW9523_ADDR, 0x04, 0b11011000);
    _power_write_command(AW9523_ADDR, 0x90, 0b10111111);
    _power_write_command(AW9523_ADDR, 0x04, 0b00011000);
    _power_write_command(AW9523_ADDR, 0x05, 0b00001100);
    //_power_write_command(AW9523_ADDR, 0x05, 0b01111100);
    _power_write_command(AW9523_ADDR, 0x12, 0b11111111);
    _power_write_command(AW9523_ADDR, 0x13, 0b11111111);
    _power_write_command(AW9523_ADDR, 0x11, 0b00010000);
    _power_write_command(AW9523_ADDR, 0x02, 0b00000101);
    _power_write_command(AW9523_ADDR, 0x03, 0b00000011);
    // _power_write_command(AW9523_ADDR, 0x03, 0b10000000);

    // this was also commented below all
    // aw9523 reset
    bus_i2c_write(AW9523_ADDR, 0x7F, 1, 0x00, 1);
    vTaskDelay(30);
    // aw9523 default seetting
    bus_i2c_write(AW9523_ADDR, 0x04, 1, 0b11011000, 1);
    bus_i2c_write(AW9523_ADDR, 0x05, 1, 0b01111100, 1);
    bus_i2c_write(AW9523_ADDR, 0x12, 1, 0b11111111, 1);
    bus_i2c_write(AW9523_ADDR, 0x13, 1, 0b11111111, 1);
    bus_i2c_write(AW9523_ADDR, 0x11, 1, (1 << 4), 1);
    bus_i2c_write(AW9523_ADDR, 0x02, 1, 0b00000101, 1);
    bus_i2c_write(AW9523_ADDR, 0x03, 1, 0b00000011, 1);
}
*/

static void VBUS_boost(bool set)
{
    uint8_t buf1;
    if (set) {
        // 1
        _power_write_command(AXP2101_ADDR, 0xF0, 0x06);
        // 2
        I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0xF1, &buf1, 1));
        buf1 = buf1 | (1U << 2);
        _power_write_command(AXP2101_ADDR, 0xF1, buf1);
        // 3
        _power_write_command(AXP2101_ADDR, 0xFF, 0x01);
        // 4
        _power_write_command(AXP2101_ADDR, 0x20, 0x01);
        // 5
        _power_write_command(AXP2101_ADDR, 0xFF, 0x00);
        // 6
        I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0xF1, &buf1, 1));
        buf1 = buf1 & ~(1U << 2);
        _power_write_command(AXP2101_ADDR, 0xF1, buf1);
        // 7
        _power_write_command(AXP2101_ADDR, 0xF0, 0x00);

        // enable boost
        _power_write_command(AW9523_ADDR, 0x02, 0b00000110);

    } else {
        // disable boost
        _power_write_command(AW9523_ADDR, 0x02, 0b00000100);

        // 1
        _power_write_command(AXP2101_ADDR, 0xF0, 0x06);
        // 2
        I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0xF1, &buf1, 1));
        buf1 = buf1 | (1U << 2);
        _power_write_command(AXP2101_ADDR, 0xF1, buf1);
        // 3
        _power_write_command(AXP2101_ADDR, 0xFF, 0x01);
        // 4
        _power_write_command(AXP2101_ADDR, 0x20, 0x00);
        // 5
        _power_write_command(AXP2101_ADDR, 0xFF, 0x00);
        // 6
        I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0xF1, &buf1, 1));
        buf1 = buf1 & ~(1U << 2);
        _power_write_command(AXP2101_ADDR, 0xF1, buf1);
        // 7
        _power_write_command(AXP2101_ADDR, 0xF0, 0x00);
    }
}

static void setUsbOtgEn(bool set)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AW9523_ADDR, 0x02, &buf1, 1));
    if (set) {
        buf1 |= 0b00100000;
    } else {
        buf1 &= ~0b00100000;
    }
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(_power_write_command(AW9523_ADDR, 0x02, buf1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
}

static void setBoostEn(bool set)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AW9523_ADDR, 0x03, &buf1, 1));
    if (set) {
        buf1 |= 0b00000010;
    } else {
        buf1 &= ~0b00000010;
    }
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(_power_write_command(AW9523_ADDR, 0x03, buf1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
}

static void setBusOutEn(bool set)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AW9523_ADDR, 0x02, &buf1, 1));
    if (set) {
        buf1 |= 0b00000010;
    } else {
        buf1 &= ~0b00000010;
    }
    vTaskDelay(20 / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(_power_write_command(AW9523_ADDR, 0x02, buf1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
}

static void setBoostBusOutEn(bool set)
{
    setBoostEn(set);
    // delay is required to prevent reverse current flow from VBUS to BUS_OUT
    if (!set) {
        vTaskDelay(250 / portTICK_PERIOD_MS);
    }
    setBusOutEn(set);
}

static esp_err_t _power_enable_charging(void) { return _power_write_command(AXP2101_ADDR, 0x33, 0xc0); }

static void AW9523_init(void)
{
    _power_write_command(AW9523_ADDR, 0x04, 0b01111000);
    _power_write_command(AW9523_ADDR, 0x05, 0b01011000);
    _power_write_command(AW9523_ADDR, 0x12, 0b11111110);
    _power_write_command(AW9523_ADDR, 0x13, 0b11111000);
    _power_write_command(AW9523_ADDR, 0x11, (1 << 4));

    /* Pull up p0_1 p0_2 */
    // _power_write_command(AW9523_ADDR, 0x02, 0b00000110);
    /* Pull up p1_7 p1_5 */
    _power_write_command(AW9523_ADDR, 0x03, 0b10100000);

    /* Pull down p0_1 */
    _power_write_command(AW9523_ADDR, 0x02, 0b00000100);
}

static void axp2101_init(void)
{
    // AW9523_init();
    // This is used to turn on the CHG_LED not sure if needed for actually charging
    // _power_write_command(AXP2101_ADDR, 0x69, 0b00110101);
    // This i am not sure what it is at all
    //  _power_write_command(AXP2101_ADDR, 0x97, (0b11110 - 2));
    _power_write_command(AXP2101_ADDR, 0x90, 0xBF); // AXP ALDO~4,BLDO0~2,DIDO1 Enable
    _power_write_command(AXP2101_ADDR, 0x95, 0b00011100); // AXP ALDO4 voltage / SD card / 3.3 V

    _power_write_command(AW9523_ADDR, 0x02, 0b00000101); // P0
    _power_write_command(AW9523_ADDR, 0x04, 0b00011000);
    _power_write_command(AW9523_ADDR, 0x05, 0b00001100);
    _power_write_command(AW9523_ADDR, 0x11, 0b00010000);
    _power_write_command(AW9523_ADDR, 0x12, 0b11111111);
    _power_write_command(AW9523_ADDR, 0x13, 0b11111111);

    _power_enable_charging();

    _power_write_command(AXP2101_ADDR, 0x69, 0x11);
}

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

    //   _power_enable_coulomb_counter();
    axp2101_init();

    vTaskDelay(100 / portTICK_PERIOD_MS);

    // enable_usb_host();

    return ESP_OK;
}

void disable_usb_host(void)
{
    // FIXME: implement it
}

void enable_usb_host(void)
{

    /*
     *
     * we need either
     *
     *  setUsbOtgEn(true);        // USB_OTG_EN=1
            setBoostBusOutEn(false);

or

     setUsbOtgEn(true);       // USB_OTG_EN=1
            setBoostBusOutEn(true);  // BUS_OUT_EN,Boost=1*/
    // setBoostEn(true);
    // vTaskDelay(100 / portTICK_PERIOD_MS);
    // setUsbOtgEn(true);
    // VBUS_boost(true);
    // setBoostBusOutEn(false);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    // setUsbOtgEn(true);        // USB_OTG_EN=1
    vTaskDelay(100 / portTICK_PERIOD_MS);
    vTaskDelay(100 / portTICK_PERIOD_MS);
}

esp_err_t power_shutdown(void)
{
    uint8_t buf1;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x10, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    const esp_err_t ret = _power_write_command(AXP2101_ADDR, 0x10, buf1 | 0b00000001);
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ret;
}

esp_err_t power_screen_on(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    /* this seems the right command/data pair (doesn't work without) but I am not sure
     * it is the right one to turn the display on/off */
    const esp_err_t err = _power_write_command(AW9523_ADDR, 0x03, 0b00000011);
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return err;
}

esp_err_t power_screen_off(void)
{
    // FIXME: power off display for real
    printf("Power scren_off requested\n");
    return ESP_OK;
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(AXP2101_ADDR, 0x12, buf1 & (~0x08));
}

esp_err_t power_backlight_on(const uint8_t brightness)
{
    printf("Brightness is %d\n", brightness);
    // FIXME: power on backlight for real
    return ESP_OK;
    // dimming not supported - just full on
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(AXP2101_ADDR, 0x12, buf1 | 0x04);
}

esp_err_t power_backlight_off(void)
{
    printf("Brightness OFF \n");
    // FIXME: power off backlight for real
    return ESP_OK;
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(AXP2101_ADDR, 0x12, buf1 & (~0x04));
}

esp_err_t power_camera_on(void)
{
    // FIXME: power on camera for real
    printf("Powering camera on \n");
    return _power_write_command(AXP2101_ADDR, 0x94, 0b00011100);
}
esp_err_t power_camera_off(void)
{
    // FIXME: power off camera for real
    return ESP_OK;
}

uint16_t power_get_vbat(void)
{
    /* M5 uses 12 bits reading (from two 8 bytes buffers)
     * https://github.com/m5stack/M5CoreS3/blob/a9187b74aa3d6c90cc2cfc8f7e6d466ae3dd6cd7/src/AXP2101.cpp#L228 */
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x78, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x79, &buf2, 1));
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
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x7A, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x7B, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t ibat = (buf1 << 5) + buf2;
    return ibat;
}

uint16_t power_get_ibat_discharge(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x7C, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x7D, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t ibat = (buf1 << 5) + buf2;
    return ibat;
}

bool power_get_battery_charging(void)
{
    uint8_t buf;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x01, &buf, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const bool charging = (buf & 0b01000000) >> 6;
    return !charging;
}

uint16_t power_get_vusb(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x5a, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x5b, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t vusb = ((buf1 << 4) + buf2) * 1.7;
    return vusb;
}

uint16_t power_get_iusb(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x5c, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x5d, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t iusb = ((buf1 << 4) + buf2) * 0.375;
    return iusb;
}

uint16_t power_get_temp(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x5e, &buf1, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x5f, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t temp = ((buf1 << 4) + buf2) * 0.1 - 144.7;
    return temp;
}

bool usb_connected(void)
{
    uint8_t buf;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP2101_ADDR, 0x00, &buf, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    const bool is_usb_connected = buf & 0b00100000;
    return is_usb_connected;
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

esp_err_t power_backlight_on(const uint8_t brightness) { return ESP_OK; }
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
