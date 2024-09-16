// M5StickCPlus implmentation - also uses AXP192 but configured
// differently from Jade v1.x
// NOTE: also handles M5StackCore2 as similar enough ...
//
#include "power/i2c.inc"

#define AXP192_ADDR 0x34

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

static esp_err_t _power_enable_coulomb_counter(void) { return _power_write_command(AXP192_ADDR, 0xb8, 0x80); }

esp_err_t power_init(void)
{
    I2C_CHECK_RET(_power_i2c_init());

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

esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

#if defined(CONFIG_BOARD_TYPE_M5_CORE2)
#include <esp_sleep.h>
esp_err_t power_shutdown(void)
{
    esp_deep_sleep_start();
    return ESP_OK;
}

esp_err_t power_screen_on(void)
{
    return ESP_OK;
    // return _power_write_command(AXP192_ADDR, 0x12, buf1 | 0x04);  ??
}

esp_err_t power_backlight_on(uint8_t brightness) { return ESP_OK; }
esp_err_t power_backlight_off(void) { return ESP_OK; }

#else

esp_err_t power_shutdown(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    const esp_err_t ret = _power_write_command(AXP192_ADDR, 0x32, 0x80);
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ret;
}

esp_err_t power_screen_on(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(AXP192_ADDR, 0x12, buf1 | 0x08);
}

esp_err_t power_backlight_on(uint8_t brightness)
{
    uint8_t buf1;

    // dimming not supported - just full on
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(AXP192_ADDR, 0x12, buf1 | 0x04);
}

esp_err_t power_backlight_off(void)
{
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x12, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    return _power_write_command(AXP192_ADDR, 0x12, buf1 & (~0x04));
}
#endif // CONFIG_BOARD_TYPE_M5_CORE2

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
