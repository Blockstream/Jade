// Jade v2 implementation
//
#include "jade_tasks.h"
#include "power/i2c.inc"

#define AW99703_ADDR 0x36
#define AW99703_REG_OP_MODE 0x02
#define AW99703_REG_LED_CHN 0x03
#define AW99703_REG_BOOST_CTRL1 0x04
#define AW99703_REG_BOOST_CTRL2 0x05
#define AW99703_REG_LED_BR_LSB 0x06
#define AW99703_REG_LED_BR_MSB 0x07
#define AW99703_REG_PWM_CTRL 0x08
#define AW99703_REG_FLAG_1 0x0E
#define AW99703_REG_FLAG_2 0x0F

#define PMIC_ADDR 0x66
#define PMIC_REG_BAT_VOLTS_0 0x00
#define PMIC_REG_BAT_VOLTS_1 0x01
#define PMIC_REG_BAT_VOLTS_2 0x02
#define PMIC_REG_BAT_VOLTS_3 0x03
#define PMIC_REG_ADC_0 0x04
#define PMIC_REG_ADC_1 0x05
#define PMIC_REG_POWER_OFF 0x10
#define PMIC_REG_OTG 0x11
#define PMIC_REG_DISABLE_DOWNLOAD 0xF1
#define PMIC_REG_DISABLE_RESET 0xF2

#define LCD_RST (gpio_num_t)46
#define HUSB320_ADDR 0x21
#define HUSB320_REG_TYPE 0x13
#define HUSB320_REG_STATUS 0x11
#define HUSB320_INT_PIN (gpio_num_t)18

#define HUSB320_REG_TYPE_SOURCE 0x08
#define HUSB320_REG_TYPE_HOST_MODE 0x10

#define HUSB320_REG_STATUS_VBUS_CONNECTED 0x08
#define HUSB320_REG_STATUS_POWER_HIGH 0x04 // 3A
#define HUSB320_REG_STATUS_POWER_LOW 0x02 // 1.5A

static SemaphoreHandle_t usb_semaphore;

static void IRAM_ATTR usb_gpio_isr_handler(void* arg)
{
    BaseType_t higherPriorityTaskWoken = pdFALSE;
    xSemaphoreGiveFromISR(usb_semaphore, &higherPriorityTaskWoken);
    if (higherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }
}

void usb_detection_task(void* param)
{
    while (1) {
        if (xSemaphoreTake(usb_semaphore, portMAX_DELAY) == pdTRUE) {
            JADE_SEMAPHORE_TAKE(i2c_mutex);
            // reset interrupts
            I2C_LOG_ANY_ERROR(_power_write_command(HUSB320_ADDR, 0x14, 0xff));
            I2C_LOG_ANY_ERROR(_power_write_command(HUSB320_ADDR, 0x15, 0xff));

            uint8_t usb_type;
            I2C_LOG_ANY_ERROR(_power_master_read_slave(HUSB320_ADDR, HUSB320_REG_TYPE, &usb_type, 1));

            if ((usb_type & HUSB320_REG_TYPE_SOURCE) == HUSB320_REG_TYPE_SOURCE) {
                // set to source mode
                I2C_LOG_ANY_ERROR(_power_write_command(PMIC_ADDR, PMIC_REG_OTG, 0x01));
            } else if ((usb_type & HUSB320_REG_TYPE_HOST_MODE) == HUSB320_REG_TYPE_HOST_MODE) {
                // set to sink mode
                I2C_LOG_ANY_ERROR(_power_write_command(PMIC_ADDR, PMIC_REG_OTG, 0x00));
            }
            JADE_SEMAPHORE_GIVE(i2c_mutex);
        }
    }
}

// Exported funtions
esp_err_t power_init(void)
{
    const i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = CONFIG_I2C_SDA,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_io_num = CONFIG_I2C_SCL,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = 100000,
        .clk_flags = 0,
    };
    I2C_CHECK_RET(i2c_param_config(I2C_BATTERY_PORT, &conf));
    I2C_CHECK_RET(i2c_driver_install(I2C_BATTERY_PORT, conf.mode, 0, 0, 0));

    // Create i2c mutex semaphore
    i2c_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(i2c_mutex);
    usb_semaphore = xSemaphoreCreateBinary();
    JADE_ASSERT(usb_semaphore);

    // do usb detection for power boost
    gpio_set_intr_type(HUSB320_INT_PIN, GPIO_INTR_NEGEDGE);
    I2C_CHECK_RET(gpio_install_isr_service(0));

    gpio_isr_handler_add(HUSB320_INT_PIN, usb_gpio_isr_handler, (void*)HUSB320_INT_PIN);
    I2C_CHECK_RET(_power_write_command(HUSB320_ADDR, 0x03, 0b01001100));
    uint8_t data;
    I2C_CHECK_RET(_power_master_read_slave(HUSB320_ADDR, 0x04, &data, 1));
    I2C_CHECK_RET(_power_write_command(HUSB320_ADDR, 0x04, data & 0b11111110));
    I2C_CHECK_RET(_power_write_command(HUSB320_ADDR, 0x05, 0b111011));
    // reset any interrupt if any
    I2C_CHECK_RET(_power_write_command(HUSB320_ADDR, 0x14, 0xff));
    I2C_CHECK_RET(_power_write_command(HUSB320_ADDR, 0x15, 0xff));
    I2C_CHECK_RET(_power_write_command(HUSB320_ADDR, 0x0E, 0b00011011));
    I2C_CHECK_RET(_power_write_command(HUSB320_ADDR, 0x0F, 0b00000000));

    const BaseType_t retval = xTaskCreatePinnedToCore(
        usb_detection_task, "usbdt", 1024 * 4, NULL, JADE_TASK_PRIO_IDLETIMER, NULL, JADE_CORE_GUI);

    if (retval != pdPASS) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
    power_camera_off();
    power_backlight_off();

    // Power off via the XXX
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_CHECK_RET(_power_write_command(PMIC_ADDR, PMIC_REG_POWER_OFF, 0x01));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    return ESP_OK;
}

esp_err_t power_screen_on(void)
{
    uint8_t val;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    // 500k 17.5v 0.9A
    I2C_LOG_ANY_ERROR(_power_write_command(AW99703_ADDR, AW99703_REG_BOOST_CTRL1, 0b00000000));

    // 10uH
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AW99703_ADDR, AW99703_REG_BOOST_CTRL2, &val, 1));
    I2C_LOG_ANY_ERROR(_power_write_command(AW99703_ADDR, AW99703_REG_BOOST_CTRL2, val | 0b11000000));

    // 20mA, led chn 1 enable
    I2C_LOG_ANY_ERROR(_power_write_command(AW99703_ADDR, AW99703_REG_LED_CHN, 0b10011001));
    I2C_LOG_ANY_ERROR(_power_write_command(AW99703_ADDR, AW99703_REG_PWM_CTRL, 0b00110011));

    // Backlight mode (backlight initially off)
    I2C_LOG_ANY_ERROR(_power_write_command(AW99703_ADDR, AW99703_REG_LED_BR_LSB, 0));
    I2C_LOG_ANY_ERROR(_power_write_command(AW99703_ADDR, AW99703_REG_LED_BR_MSB, 0));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(AW99703_ADDR, AW99703_REG_OP_MODE, &val, 1));
    I2C_LOG_ANY_ERROR(_power_write_command(AW99703_ADDR, AW99703_REG_OP_MODE, val | 0b00000101));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    return ESP_OK;
}

esp_err_t power_backlight_on(uint8_t brightness)
{
    // MIN    -> 1 -> 5,1 -> 41
    // DIM    -> 2 -> 67,2 -> 538
    // MEDIUM -> 3 -> 130,4 -> 1044
    // BRIGHT -> 4 -> 192,5 -> 1541
    // MAX    -> 5 -> 255,7 -> 2047
    if (brightness < BACKLIGHT_MIN) {
        brightness = BACKLIGHT_MIN;
    } else if (brightness > BACKLIGHT_MAX) {
        brightness = BACKLIGHT_MAX;
    }
    const uint8_t msb = 5 + 250 * (brightness - 1) / 4;
    const uint8_t lsb = 1 + 6 * (brightness - 1) / 4;

    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_write_command(AW99703_ADDR, AW99703_REG_LED_BR_LSB, lsb));
    I2C_LOG_ANY_ERROR(_power_write_command(AW99703_ADDR, AW99703_REG_LED_BR_MSB, msb));
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ESP_OK;
}

esp_err_t power_backlight_off(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_write_command(AW99703_ADDR, AW99703_REG_LED_BR_LSB, 0));
    I2C_LOG_ANY_ERROR(_power_write_command(AW99703_ADDR, AW99703_REG_LED_BR_MSB, 0));
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ESP_OK;
}

esp_err_t power_camera_on(void) { return ESP_OK; }

esp_err_t power_camera_off(void)
{
    esp_rom_gpio_pad_select_gpio(CONFIG_CAMERA_PWDN);
    gpio_set_direction(CONFIG_CAMERA_PWDN, GPIO_MODE_OUTPUT);
    gpio_set_level(CONFIG_CAMERA_PWDN, 1);
    return ESP_OK;
}

uint16_t power_get_vbat(void)
{
    uint8_t msb, lsb;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(PMIC_ADDR, PMIC_REG_BAT_VOLTS_0, &lsb, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(PMIC_ADDR, PMIC_REG_BAT_VOLTS_1, &msb, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    return (msb << 8) + lsb;
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
    // Connection offers power and battery not fully charged
    uint8_t usb_vbus_status;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(HUSB320_ADDR, HUSB320_REG_STATUS, &usb_vbus_status, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    const bool usb_powered = (usb_vbus_status & (HUSB320_REG_STATUS_POWER_HIGH | HUSB320_REG_STATUS_POWER_LOW));
    return usb_powered && power_get_vbat() < 4100;
}

uint16_t power_get_ibat_charge(void) { return 0; }

uint16_t power_get_ibat_discharge(void) { return 0; }

uint16_t power_get_vusb(void) { return 0; }

uint16_t power_get_iusb(void) { return 0; }

uint16_t power_get_temp(void) { return 0; }

bool usb_connected(void)
{
    uint8_t usb_type, usb_vbus_status;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(HUSB320_ADDR, HUSB320_REG_TYPE, &usb_type, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(HUSB320_ADDR, HUSB320_REG_STATUS, &usb_vbus_status, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    // Check we are 'vbus-connected' to a usb host
    return ((usb_type & HUSB320_REG_TYPE_HOST_MODE) == HUSB320_REG_TYPE_HOST_MODE)
        && ((usb_vbus_status & HUSB320_REG_STATUS_VBUS_CONNECTED) == HUSB320_REG_STATUS_VBUS_CONNECTED);
}
