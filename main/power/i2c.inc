// Code common to all devices that communicate with a PMU via i2c
//
#include <driver/i2c_master.h>

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

static i2c_master_bus_handle_t master_bus_handle = NULL;
static SemaphoreHandle_t i2c_mutex = NULL;

#define I2C_TIMEOUT -1

#define I2C_CHECK_RET(expr)                                                                                            \
    do {                                                                                                               \
        const esp_err_t res = (expr);                                                                                  \
        if (res != ESP_OK) {                                                                                           \
            JADE_LOGE("i2c call returned: %u (%d)", res, res);                                                         \
            return res;                                                                                                \
        }                                                                                                              \
    } while (false)

#define I2C_LOG_ANY_ERROR(expr)                                                                                        \
    do {                                                                                                               \
        const esp_err_t res = (expr);                                                                                  \
        if (res != ESP_OK) {                                                                                           \
            JADE_LOGE("i2c call returned: %u (%d)", res, res);                                                         \
        }                                                                                                              \
    } while (false)

esp_err_t _i2c_init_master(
    const i2c_port_t port_num, const int sda_io_num, const int scl_io_num, i2c_master_bus_handle_t* handle)
{
    JADE_INIT_OUT_PPTR(handle);

    i2c_master_bus_config_t master_bus_config = {
        .i2c_port = port_num,
        .sda_io_num = sda_io_num,
        .scl_io_num = scl_io_num,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    I2C_CHECK_RET(i2c_new_master_bus(&master_bus_config, handle));

    return ESP_OK;
}

esp_err_t _i2c_deinit(const i2c_master_bus_handle_t handle)
{
    // NULL handle implies default
    if (handle && handle != master_bus_handle) {
        I2C_CHECK_RET(i2c_del_master_bus(handle));
    } else {
        I2C_CHECK_RET(i2c_del_master_bus(master_bus_handle));
        master_bus_handle = NULL;
    }
    return ESP_OK;
}

static esp_err_t _power_i2c_init(void)
{
    JADE_ASSERT(!master_bus_handle);
    JADE_ASSERT(!i2c_mutex);

    I2C_CHECK_RET(_i2c_init_master(I2C_NUM_0, CONFIG_I2C_SDA, CONFIG_I2C_SCL, &master_bus_handle));

    // Create i2c mutex semaphore
    i2c_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(i2c_mutex);

    return ESP_OK;
}

// NOTE: _power_i2c_init() must have been called
// also: i2c_mutex must be claimed before calling if not in the parent init function
static esp_err_t _power_i2c_attach_device(const uint8_t address, i2c_master_dev_handle_t* device_handle_out)
{
    JADE_ASSERT(address);
    JADE_ASSERT(device_handle_out);

    JADE_ASSERT(master_bus_handle);

    i2c_device_config_t device_config
        = { .dev_addr_length = I2C_ADDR_BIT_LEN_7, .device_address = address, .scl_speed_hz = CONFIG_I2C_MASTER_CLK };
    I2C_CHECK_RET(i2c_master_bus_add_device(master_bus_handle, &device_config, device_handle_out));

    return ESP_OK;
}

// NOTE: i2c_mutex must be claimed before calling
static esp_err_t _power_master_write_slave(i2c_master_dev_handle_t device, const uint8_t* data, const size_t len)
{
    JADE_ASSERT(device);
    JADE_ASSERT(data);
    JADE_ASSERT(len);

    return i2c_master_transmit(device, data, len, I2C_TIMEOUT);
}

// NOTE: i2c_mutex must be claimed before calling
static esp_err_t _power_master_read_slave(
    i2c_master_dev_handle_t device, const uint8_t register_address, uint8_t* data, const size_t len)
{
    JADE_ASSERT(device);
    JADE_ASSERT(data);
    JADE_ASSERT(len);

    return i2c_master_transmit_receive(device, &register_address, sizeof(register_address), data, len, I2C_TIMEOUT);
}

static esp_err_t _power_write_command(i2c_master_dev_handle_t device, const uint8_t register_address, const uint8_t val)
{
    const uint8_t cmd[] = { register_address, val };
    return _power_master_write_slave(device, cmd, sizeof(cmd));
}