// Jade v1.1 implmentation
//
#include "power/i2c.inc"
#include <esp_private/adc_share_hw_ctrl.h>

#define AXP192_ADDR 0x34

static esp_err_t _power_enable_adcs(void) { return _power_write_command(AXP192_ADDR, 0x82, 0xff); }
static esp_err_t _power_enable_charging(void) { return _power_write_command(AXP192_ADDR, 0x33, 0xc0); }
static esp_err_t _power_setup_pek(void) { return _power_write_command(AXP192_ADDR, 0x36, 0x5c); }

static esp_err_t _power_enable_dc_dc1(void) { return _power_write_command(AXP192_ADDR, 0x12, 0x01); }

static esp_err_t _power_open_drain_gpio(void) { return _power_write_command(AXP192_ADDR, 0x95, 0x85); }

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

esp_err_t power_backlight_on(uint8_t brightness)
{
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
}

esp_err_t power_backlight_off(void) { return _power_write_command(AXP192_ADDR, 0x91, 0x00); }

// Exported funtions
esp_err_t power_init(void)
{
    const i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = CONFIG_I2C_SDA,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_io_num = CONFIG_I2C_SCL,
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

#ifdef CONFIG_BT_ENABLED
    /**
     * There is a bug around using GPIO36/39 with ADC/WiFi (BLE) with sleep mode.
     * We use:
     * PIN 36: Camera D6
     * PIN 39: v1.1 - wheel-next
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
    // Reset display
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    _power_display_on();
    vTaskDelay(10 / portTICK_PERIOD_MS);
    _power_display_off();
    vTaskDelay(20 / portTICK_PERIOD_MS);
    _power_display_on();
    vTaskDelay(200 / portTICK_PERIOD_MS);
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    // We don't actually want to enable the backlight at this point
    return power_backlight_off();
}

esp_err_t power_camera_on(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    const esp_err_t ret = _power_write_command(AXP192_ADDR, 0x96, buf1 | 0x01);
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ret;
}

esp_err_t power_camera_off(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    uint8_t buf1;
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x96, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    const esp_err_t ret = _power_write_command(AXP192_ADDR, 0x96, buf1 & (~0x01));
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
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x56, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x57, &buf2, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const uint16_t vusb = ((buf1 << 4) + buf2) * 1.7;
    return vusb;
}

uint16_t power_get_iusb(void)
{
    uint8_t buf1, buf2;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x58, &buf1, 1));
    vTaskDelay(20 / portTICK_PERIOD_MS);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AXP192_ADDR, 0x59, &buf2, 1));
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

    const bool is_usb_connected = buf & 0b10000000;
    return is_usb_connected;
}
