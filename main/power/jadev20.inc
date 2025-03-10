// Jade v2 implementation
//
#include "jade_tasks.h"
#include "power/i2c.inc"
#include <driver/gpio.h>

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

#define STM32_ADDR 0x66
#define STM32_REG_BAT_VOLTS_0 0x00
#define STM32_REG_BAT_VOLTS_1 0x01
#define STM32_REG_BAT_VOLTS_2 0x02
#define STM32_REG_BAT_VOLTS_3 0x03
#define STM32_REG_ADC_0 0x04
#define STM32_REG_ADC_1 0x05
#define STM32_REG_BAT_STATUS 0x06
#define STM32_REG_POWER_OFF 0x10
#define STM32_REG_OTG 0x11
#define STM32_REG_DISABLE_DOWNLOAD 0xF1
#define STM32_REG_DISABLE_RESET 0xF2
#define STM32_REG_FW_VERSION 0xFE

#define STM32_REG_BAT_CHARGING_MASK 0x30
#define STM32_REG_BAT_CHARGING 0x10

#define SGM7220_ADDR 0x47
#define SGM7220_REG_TYPE 0x09

#define SGM7220_REG_TYPE_SHIFT 6
#define SGM7220_REG_TYPE_SOURCE 0x01
#define SGM7220_REG_TYPE_SINK 0x02

static i2c_master_dev_handle_t aw99703 = NULL;
static i2c_master_dev_handle_t stm32 = NULL;
static i2c_master_dev_handle_t sgm7220 = NULL;

#ifdef USB_DETECTION
#define USB_INT_PIN (gpio_num_t)18
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
    while (true) {
        if (xSemaphoreTake(usb_semaphore, portMAX_DELAY) == pdTRUE) {
            JADE_SEMAPHORE_TAKE(i2c_mutex);

            uint8_t usb_type;
            I2C_LOG_ANY_ERROR(_power_master_read_slave(sgm7220, SGM7220_REG_TYPE, &usb_type, 1));

            // Reset interrupts
            // The field may be cleared by a write of one. Writing of zeros to the field have no effect.
            I2C_LOG_ANY_ERROR(_power_write_command(sgm7220, SGM7220_REG_TYPE, (usb_type | (0x1 << 4))));

            usb_type >>= SGM7220_REG_TYPE_SHIFT;
            if (usb_type == SGM7220_REG_TYPE_SOURCE) {
                // set to source mode
                I2C_LOG_ANY_ERROR(_power_write_command(stm32, STM32_REG_OTG, 0x01));
            } else {
                // set to sink mode
                I2C_LOG_ANY_ERROR(_power_write_command(stm32, STM32_REG_OTG, 0x00));
            }
            JADE_SEMAPHORE_GIVE(i2c_mutex);
        }
    }
}
#endif // USB_DETECTION

// Exported funtions
esp_err_t power_init(void)
{
    I2C_CHECK_RET(_power_i2c_init());
    I2C_CHECK_RET(_power_i2c_attach_device(AW99703_ADDR, &aw99703));
    I2C_CHECK_RET(_power_i2c_attach_device(STM32_ADDR, &stm32));
    I2C_CHECK_RET(_power_i2c_attach_device(SGM7220_ADDR, &sgm7220));

    // Need read twice for some reason - first one always fails, second should work!
    uint8_t data;
    _power_master_read_slave(stm32, STM32_REG_FW_VERSION, &data, 1);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(stm32, STM32_REG_FW_VERSION, &data, 1));
    JADE_LOGI("STM32 fw version: %u", data);

    // set to sink mode by default
    I2C_LOG_ANY_ERROR(_power_write_command(stm32, STM32_REG_OTG, 0x00));

#ifdef USB_DETECTION
    usb_semaphore = xSemaphoreCreateBinary();
    JADE_ASSERT(usb_semaphore);

    // Do usb detection for power boost
    gpio_set_intr_type(USB_INT_PIN, GPIO_INTR_NEGEDGE);
    I2C_CHECK_RET(gpio_install_isr_service(0));
    gpio_isr_handler_add(USB_INT_PIN, usb_gpio_isr_handler, (void*)USB_INT_PIN);

    const BaseType_t retval = xTaskCreatePinnedToCore(
        usb_detection_task, "usbdt", 1024 * 4, NULL, JADE_TASK_PRIO_IDLETIMER, NULL, JADE_CORE_GUI);

    if (retval != pdPASS) {
        return ESP_FAIL;
    }
#endif

    uint8_t sgm_id[8] = { 0 };
    I2C_CHECK_RET(_power_master_read_slave(sgm7220, 0x00, &sgm_id[0], sizeof(sgm_id)));
    JADE_LOGI("SGM7220 Device ID: %02x %02x %02x %02x %02x %02x %02x %02x", sgm_id[7], sgm_id[6], sgm_id[5], sgm_id[4],
        sgm_id[3], sgm_id[2], sgm_id[1], sgm_id[0]);
    I2C_CHECK_RET(_power_write_command(sgm7220, 0x0A, 0x32));

#ifdef CONFIG_SECURE_BOOT
    // Ensure 'download mode' permanently disabled
    I2C_LOG_ANY_ERROR(_power_write_command(stm32, STM32_REG_DISABLE_DOWNLOAD, 0x01));
    I2C_LOG_ANY_ERROR(_power_write_command(stm32, STM32_REG_DISABLE_RESET, 0x01));
#endif

    return ESP_OK;
}

esp_err_t power_shutdown(void)
{
    power_camera_off();
    power_backlight_off();

    // Power off via the XXX
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_write_command(stm32, STM32_REG_POWER_OFF, 0x01));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    return ESP_OK;
}

esp_err_t power_screen_on(void)
{
    uint8_t val;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    // 500k 17.5v 0.9A
    I2C_LOG_ANY_ERROR(_power_write_command(aw99703, AW99703_REG_BOOST_CTRL1, 0b00000000));

    // 10uH
    I2C_LOG_ANY_ERROR(_power_master_read_slave(aw99703, AW99703_REG_BOOST_CTRL2, &val, 1));
    I2C_LOG_ANY_ERROR(_power_write_command(aw99703, AW99703_REG_BOOST_CTRL2, val | 0b11000000));

    // 20mA, led chn 1 enable
    I2C_LOG_ANY_ERROR(_power_write_command(aw99703, AW99703_REG_LED_CHN, 0b10011001));
    I2C_LOG_ANY_ERROR(_power_write_command(aw99703, AW99703_REG_PWM_CTRL, 0b00110011));

    // Backlight mode (backlight initially off)
    I2C_LOG_ANY_ERROR(_power_write_command(aw99703, AW99703_REG_LED_BR_LSB, 0));
    I2C_LOG_ANY_ERROR(_power_write_command(aw99703, AW99703_REG_LED_BR_MSB, 0));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(aw99703, AW99703_REG_OP_MODE, &val, 1));
    I2C_LOG_ANY_ERROR(_power_write_command(aw99703, AW99703_REG_OP_MODE, val | 0b00000101));
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
    I2C_LOG_ANY_ERROR(_power_write_command(aw99703, AW99703_REG_LED_BR_LSB, lsb));
    I2C_LOG_ANY_ERROR(_power_write_command(aw99703, AW99703_REG_LED_BR_MSB, msb));
    JADE_SEMAPHORE_GIVE(i2c_mutex);
    return ESP_OK;
}

esp_err_t power_backlight_off(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_write_command(aw99703, AW99703_REG_LED_BR_LSB, 0));
    I2C_LOG_ANY_ERROR(_power_write_command(aw99703, AW99703_REG_LED_BR_MSB, 0));
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
    I2C_LOG_ANY_ERROR(_power_master_read_slave(stm32, STM32_REG_BAT_VOLTS_0, &lsb, 1));
    I2C_LOG_ANY_ERROR(_power_master_read_slave(stm32, STM32_REG_BAT_VOLTS_1, &msb, 1));
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
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    uint8_t charging_status;
    // Bit5-Bit4: 0b00 Ready 0b01 Charging 0b10 Charge done 0b11 Fault
    I2C_LOG_ANY_ERROR(_power_master_read_slave(stm32, STM32_REG_BAT_STATUS, &charging_status, 1));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    return (charging_status & STM32_REG_BAT_CHARGING_MASK) == STM32_REG_BAT_CHARGING;
}

uint16_t power_get_ibat_charge(void) { return 0; }

uint16_t power_get_ibat_discharge(void) { return 0; }

uint16_t power_get_vusb(void) { return 0; }

uint16_t power_get_iusb(void) { return 0; }

uint16_t power_get_temp(void) { return 0; }

void disable_usb_host(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_write_command(stm32, STM32_REG_OTG, 0x00));
    JADE_SEMAPHORE_GIVE(i2c_mutex);
}

void enable_usb_host(void)
{
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_write_command(stm32, STM32_REG_OTG, 0x01));
    JADE_SEMAPHORE_GIVE(i2c_mutex);
}

bool usb_connected(void)
{
    uint8_t usb_type;
    JADE_SEMAPHORE_TAKE(i2c_mutex);
    I2C_LOG_ANY_ERROR(_power_master_read_slave(sgm7220, SGM7220_REG_TYPE, &usb_type, 1));
    I2C_LOG_ANY_ERROR(_power_write_command(sgm7220, SGM7220_REG_TYPE, (usb_type | (0x1 << 4))));
    JADE_SEMAPHORE_GIVE(i2c_mutex);

    // Check we are connected as a usb sink
    usb_type >>= SGM7220_REG_TYPE_SHIFT;
    return usb_type == SGM7220_REG_TYPE_SINK;
}
