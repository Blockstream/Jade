// M5PM1 PMU implementation (M5Stack StickS3)
//
// The StickS3 uses the M5PM1 PMIC (I2C addr 0x6E, SDA=G47/SCL=G48) rather than
// the AXP192/IP5306 that Jade normally targets.  The M5PM1 brings up the rails
// that power the ESP32 (L0/L1/L2) automatically, but the L3B rail - which powers
// the ST7789 LCD backlight, MIC and SPK - is gated by the PMIC's PYG2 output
// (GPIO2, see the "M5PM1" pinmap on docs.m5stack.com, "PYG2_L3B_EN", and the
// StickS3 M5PM1 tutorial) and is OFF until software drives it.
//
// IMPORTANT: PYG2 is an ACTIVE-HIGH rail enable - set the GPIO output HIGH to
// enable the L3B rail, LOW to cut it.  Empirically the M5PM1's GPIO_OUT
// register defaults to all-high on reset (L3B on); M5Unified/UIFlow never
// explicitly touch PYG2, relying on that default.  Explicitly writing 0x00
// kills the rail.  Verified by hardware test: writing 0x04 (PYG2 HIGH)
// restores the backlight.
//
// Reference: M5PM1_Datasheet_EN.pdf, M5PM1 Arduino lib (m5stack/M5PM1),
// M5Unified Board_StickS3.cpp.
//
#include "power/i2c.inc"
#include <esp_sleep.h>

#define M5PM1_ADDR 0x6E

#define M5PM1_REG_DEVICE_ID 0x00  // R  [7:0] device id
#define M5PM1_REG_PWR_CFG 0x06    // [4]LED_EN [3]BOOST [2]LDO3V3 [1]DCDC5V [0]CHG; clear on reset
#define M5PM1_REG_HOLD_CFG 0x07   // [6]BOOST [5]LDO [4..0]GPIO4..0 output-state hold; clear on reset
#define M5PM1_REG_I2C_CFG 0x09    // [4]SPD(1=400kHz) [3:0]I2C idle sleep timeout (0=disabled)
#define M5PM1_REG_WDT_CNT 0x0A    // watchdog countdown seconds (0=disabled)
#define M5PM1_REG_GPIO_MODE 0x10  // [4:0] direction, 1=output, 0=input
#define M5PM1_REG_GPIO_OUT 0x11   // [4:0] output level, 1=high, 0=low
#define M5PM1_REG_GPIO_DRV 0x13   // [4:0] drive, 1=open-drain, 0=push-pull
#define M5PM1_REG_GPIO_FUNC0 0x16 // 2 bits per GPIO0..3 func: 00=GPIO 01=IRQ 10=WAKE 11=special

#define M5PM1_PYG2 2 // GPIO2 output = L3B rail enable, ACTIVE-HIGH (1=rail on)
#define M5PM1_PYG3 3 // GPIO3 output = speaker amp pulse (hold low until audio used)

#define M5PM1_PWR_CFG_ENABLES 0x07 // CHG + DCDC5V + LDO3V3 (BOOST left off = EXT_5V input default)
#define M5PM1_HOLD_CFG 0x64        // hold LDO + BOOST rails and the PYG2 output state

static i2c_master_dev_handle_t m5pm1 = NULL;

// Best-effort register write: log failures but never fail the boot - the board
// must keep running (and stay USB-detectable) even if the PMIC is not responsive.
static esp_err_t m5pm1_write(const uint8_t reg, const uint8_t val)
{
    if (!m5pm1) {
        return ESP_OK;
    }

    esp_err_t rc = ESP_OK;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    rc = _power_write_command(m5pm1, reg, val);
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    if (rc != ESP_OK) {
        JADE_LOGE("m5pm1: i2c write reg 0x%02x failed: %u (%d)", reg, rc, rc);
    }
    return rc;
}

// Drive the L3B rail (PYG2/GPIO2) to power the LCD.  PYG2 is an active-high
// rail enable: HIGH supplies L3B, LOW cuts it.
static esp_err_t m5pm1_set_lcd_power(const bool enabled)
{
    (void)m5pm1_write(M5PM1_REG_GPIO_OUT, enabled ? (1 << M5PM1_PYG2) : 0x00);
    return ESP_OK; // best-effort: never fail the display init for a bad PMIC
}

esp_err_t power_init(void)
{
    esp_err_t rc = _power_i2c_init();
    if (rc != ESP_OK) {
        JADE_LOGE("m5pm1: i2c bus init failed (%u/%d) - continuing without PMU", rc, rc);
        return ESP_OK;
    }

    rc = _power_i2c_attach_device(M5PM1_ADDR, &m5pm1);
    if (rc != ESP_OK) {
        JADE_LOGE("m5pm1: attach at 0x%02x failed (%u/%d) - continuing without PMU", M5PM1_ADDR, rc, rc);
        m5pm1 = NULL;
        return ESP_OK;
    }

    // Disable the PMIC i2c idle sleep timeout and watchdog: without this the PMIC
    // could drop rails / reset the board once the app stops talking to it.
    (void)m5pm1_write(M5PM1_REG_I2C_CFG, 0x00);
    (void)m5pm1_write(M5PM1_REG_WDT_CNT, 0x00);

    // Keep core rails asserted and the PYG2 level stable across soft resets/OTA.
    (void)m5pm1_write(M5PM1_REG_PWR_CFG, M5PM1_PWR_CFG_ENABLES);
    (void)m5pm1_write(M5PM1_REG_HOLD_CFG, M5PM1_HOLD_CFG);

    // Configure the PMIC GPIOs used by this board (M5PM1 GPIO_FUNC0 = 0x00 => plain GPIO):
    //   PYG2 as push-pull output HIGH  -> L3B rail on (LCD backlight + MIC + SPK powered)
    //   PYG3 as push-pull output LOW   -> speaker amplifier held off during bring-up
    (void)m5pm1_write(M5PM1_REG_GPIO_FUNC0, 0x00);
    (void)m5pm1_write(M5PM1_REG_GPIO_DRV, 0x00);
    (void)m5pm1_write(M5PM1_REG_GPIO_MODE, (1 << M5PM1_PYG2) | (1 << M5PM1_PYG3));
    (void)m5pm1_write(M5PM1_REG_GPIO_OUT, 1 << M5PM1_PYG2); // PYG2 HIGH enables L3B, PYG3 LOW keeps SPK off

    // Read back the PMIC GPIO registers so boot logs prove whether the writes
    // stuck - expect FUNC0=0x00, MODE=0x0c, DRV=0x00, OUT=0x04 (PYG2 high = L3B on).
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    const uint8_t m5pm1_readback_regs[] = {
        M5PM1_REG_DEVICE_ID, M5PM1_REG_GPIO_FUNC0, M5PM1_REG_GPIO_MODE, M5PM1_REG_GPIO_DRV, M5PM1_REG_GPIO_OUT,
    };
    for (size_t i = 0; i < sizeof(m5pm1_readback_regs); i++) {
        uint8_t readback = 0;
        const esp_err_t rc = _power_master_read_slave(m5pm1, m5pm1_readback_regs[i], &readback, 1);
        if (rc == ESP_OK) {
            JADE_LOGI("m5pm1: reg 0x%02x = 0x%02x", m5pm1_readback_regs[i], readback);
        } else {
            JADE_LOGE("m5pm1: readback reg 0x%02x failed: %d", m5pm1_readback_regs[i], rc);
        }
    }
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
    // Drop the LCD rail, then sleep
    m5pm1_set_lcd_power(false);
    esp_deep_sleep_start();
    return ESP_OK;
}

esp_err_t power_screen_on(void) { return m5pm1_set_lcd_power(true); }

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

bool usb_is_powered(void) { return true; }

void disable_usb_host(void) {}
void enable_usb_host(void) {}