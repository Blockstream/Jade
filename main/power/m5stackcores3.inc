// M5StackCores3 implmentation
// M5 Core S3 has AXP2101
//
#include "power/i2c.inc"
#include <esp_sleep.h>

#define AXP2101_ADDR 0x34
#define AW9523_ADDR 0x58

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
    I2C_CHECK_RET(_power_i2c_init());

    // _power_enable_coulomb_counter();
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
