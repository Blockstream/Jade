// T-Display S3 Pro Camera implementation using its SY6970 charger/power-path PMU.
//
// The PMU shares GPIO5/GPIO6 with the camera SCCB bus. It uses I2C0 because
// esp32-camera is configured to use this already-initialised port in camera.c.
//

#include "power/i2c.inc"
#include <esp_sleep.h>

#define SY6970_I2C_ADDRESS 0x6A

#define SY6970_REG_ADC_CONTROL 0x02
#define SY6970_REG_POWER_ON_CONFIG 0x03
#define SY6970_REG_CHARGE_TIMER_CONTROL 0x07
#define SY6970_REG_SYSTEM_STATUS 0x0B
#define SY6970_REG_BATTERY_VOLTAGE 0x0E

#define SY6970_ADC_ENABLE 0x80
#define SY6970_ADC_CONTINUOUS 0x40
#define SY6970_OTG_ENABLE 0x20
#define SY6970_WATCHDOG_TIMER_MASK 0x30

#define SY6970_VBUS_STATUS_MASK 0xE0
#define SY6970_VBUS_STATUS_SHIFT 5
#define SY6970_VBUS_STATUS_NONE 0
#define SY6970_VBUS_STATUS_OTG 7

#define SY6970_CHARGE_STATUS_MASK 0x18
#define SY6970_CHARGE_STATUS_SHIFT 3
#define SY6970_CHARGE_STATUS_PRECHARGE 1
#define SY6970_CHARGE_STATUS_FAST 2

#define SY6970_ADC_VALUE_MASK 0x7F
#define SY6970_BATTERY_VOLTAGE_BASE_MV 2304
#define SY6970_BATTERY_VOLTAGE_STEP_MV 20

static i2c_master_dev_handle_t sy6970 = NULL;

static esp_err_t sy6970_read_register(const uint8_t register_address, uint8_t* const value)
{
    JADE_ASSERT(value);

    return _power_master_read_slave(sy6970, register_address, value, sizeof(*value));
}

static esp_err_t sy6970_write_register(const uint8_t register_address, const uint8_t value)
{
    return _power_write_command(sy6970, register_address, value);
}

static esp_err_t sy6970_read_register_locked(const uint8_t register_address, uint8_t* const value)
{
    JADE_ASSERT(i2c_mutex);

    JADE_SEMAPHORE_TAKE(i2c_mutex);
    const esp_err_t ret = sy6970_read_register(register_address, value);
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    if (ret != ESP_OK) {
        JADE_LOGE("SY6970 read 0x%02x failed: %d", register_address, ret);
    }
    return ret;
}

static esp_err_t sy6970_update_bits(const uint8_t register_address, const uint8_t clear_mask, const uint8_t set_mask)
{
    JADE_ASSERT(i2c_mutex);

    JADE_SEMAPHORE_TAKE(i2c_mutex);

    uint8_t value;
    esp_err_t ret = sy6970_read_register(register_address, &value);
    if (ret == ESP_OK) {
        value = (value & ~clear_mask) | set_mask;
        ret = sy6970_write_register(register_address, value);
    }

    JADE_SEMAPHORE_GIVE(i2c_mutex);

    if (ret != ESP_OK) {
        JADE_LOGE("SY6970 update 0x%02x failed: %d", register_address, ret);
    }
    return ret;
}

static esp_err_t sy6970_get_vbus_status(uint8_t* const vbus_status)
{
    JADE_ASSERT(vbus_status);

    uint8_t status;
    const esp_err_t ret = sy6970_read_register_locked(SY6970_REG_SYSTEM_STATUS, &status);
    if (ret == ESP_OK) {
        *vbus_status = (status & SY6970_VBUS_STATUS_MASK) >> SY6970_VBUS_STATUS_SHIFT;
    }
    return ret;
}

esp_err_t power_init(void)
{
    if (CONFIG_I2C_SDA < 0 || CONFIG_I2C_SCL < 0) {
        JADE_LOGE("Invalid SY6970 I2C pins: %d/%d", CONFIG_I2C_SDA, CONFIG_I2C_SCL);
        return ESP_ERR_INVALID_ARG;
    }

    I2C_CHECK_RET(_power_i2c_init());
    I2C_CHECK_RET(_power_i2c_attach_device(SY6970_I2C_ADDRESS, &sy6970));

    // The SY6970 does not expose battery ADC values until conversion is
    // enabled. Preserve all factory charging settings.
    I2C_CHECK_RET(sy6970_update_bits(SY6970_REG_ADC_CONTROL, 0, SY6970_ADC_ENABLE | SY6970_ADC_CONTINUOUS));
    I2C_CHECK_RET(sy6970_update_bits(SY6970_REG_CHARGE_TIMER_CONTROL, SY6970_WATCHDOG_TIMER_MASK, 0));

    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
    esp_deep_sleep_start();
    return ESP_OK;
}

esp_err_t power_screen_on(void) { return ESP_OK; }
esp_err_t power_backlight_on(const uint8_t brightness) { return ESP_OK; }
esp_err_t power_backlight_off(void) { return ESP_OK; }
esp_err_t power_camera_on(void) { return ESP_OK; }
esp_err_t power_camera_off(void) { return ESP_OK; }

uint16_t power_get_vbat(void)
{
    uint8_t value;
    if (sy6970_read_register_locked(SY6970_REG_BATTERY_VOLTAGE, &value) != ESP_OK) {
        return 0;
    }
    return SY6970_BATTERY_VOLTAGE_BASE_MV + ((value & SY6970_ADC_VALUE_MASK) * SY6970_BATTERY_VOLTAGE_STEP_MV);
}

uint8_t power_get_battery_status(void)
{
    const uint16_t vbat = power_get_vbat();
    if (vbat > 4000) {
        return 5;
    } else if (vbat > 3800) {
        return 4;
    } else if (vbat > 3600) {
        return 3;
    } else if (vbat > 3400) {
        return 2;
    } else if (vbat > 3200) {
        return 1;
    }
    return 0;
}

bool power_get_battery_charging(void)
{
    uint8_t status;
    if (sy6970_read_register_locked(SY6970_REG_SYSTEM_STATUS, &status) != ESP_OK) {
        return false;
    }

    const uint8_t charge_status = (status & SY6970_CHARGE_STATUS_MASK) >> SY6970_CHARGE_STATUS_SHIFT;
    return charge_status == SY6970_CHARGE_STATUS_PRECHARGE || charge_status == SY6970_CHARGE_STATUS_FAST;
}

uint16_t power_get_ibat_charge(void) { return 0; }
uint16_t power_get_ibat_discharge(void) { return 0; }
uint16_t power_get_vusb(void) { return 0; }
uint16_t power_get_iusb(void) { return 0; }
uint16_t power_get_temp(void) { return 0; }

void disable_usb_host(void)
{
    (void)sy6970_update_bits(SY6970_REG_POWER_ON_CONFIG, SY6970_OTG_ENABLE, 0);
}

void enable_usb_host(void)
{
    uint8_t vbus_status;
    if (sy6970_get_vbus_status(&vbus_status) != ESP_OK) {
        return;
    }
    if (vbus_status != SY6970_VBUS_STATUS_NONE && vbus_status != SY6970_VBUS_STATUS_OTG) {
        JADE_LOGW("Cannot enable USB host while VBUS is connected (status %u)", vbus_status);
        return;
    }
    (void)sy6970_update_bits(SY6970_REG_POWER_ON_CONFIG, 0, SY6970_OTG_ENABLE);
}

bool usb_is_powered(void)
{
    uint8_t vbus_status;
    if (sy6970_get_vbus_status(&vbus_status) != ESP_OK) {
        // USB-storage mode enables OTG to drive VBUS for a connected device.
        // If the SY6970 status read fails, report the port as powered so the
        // USB-storage flow does not attempt to enter host mode.
        return true;
    }
    return vbus_status != SY6970_VBUS_STATUS_NONE && vbus_status != SY6970_VBUS_STATUS_OTG;
}
