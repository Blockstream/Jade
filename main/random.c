#include "random.h"
#include "jade_assert.h"
#include "power.h"
#include "sensitive.h"
#include <bootloader_random.h>
#include <driver/adc.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <mbedtls/sha512.h>
#include <string.h>
#include <wally_crypto.h>

#include "esp32/rom/ets_sys.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/sens_reg.h"
#include <stdio.h>

#define STRENGTHEN_MILLISECONDS 1000

// these functions rely on cleanup being available
#define hasherstart(ctx)                                                                                               \
    do {                                                                                                               \
        const int _ret = mbedtls_sha512_starts_ret(&ctx, 0);                                                           \
        JADE_ASSERT(_ret == 0);                                                                                        \
    } while (false)
#define hasherfinish(ctx, _data)                                                                                       \
    do {                                                                                                               \
        const int _ret = mbedtls_sha512_finish_ret(&ctx, (unsigned char*)_data);                                       \
        JADE_ASSERT(_ret == 0);                                                                                        \
    } while (false)

#define call_uint16_t_func_to_hasher(ctx, _func)                                                                       \
    do {                                                                                                               \
        const uint16_t _tmp = _func();                                                                                 \
        const int _ret = mbedtls_sha512_update_ret(&ctx, (const unsigned char*)&_tmp, sizeof(_tmp));                   \
        JADE_ASSERT(_ret == 0);                                                                                        \
    } while (false)

#define add_bytes_to_hasher(ctx, _bytes, _len)                                                                         \
    do {                                                                                                               \
        const int _ret = mbedtls_sha512_update_ret(&ctx, (const unsigned char*)_bytes, _len);                          \
        JADE_ASSERT(_ret == 0);                                                                                        \
    } while (false)

static uint8_t entropy_state[SHA256_LEN];
static uint32_t rnd_counter;
static portMUX_TYPE rndmutex;

static uint16_t esp32_get_temperature()
{
    // taken from esp-idf components/esp32/test/test_tsens.c
    SET_PERI_REG_BITS(SENS_SAR_MEAS_WAIT2_REG, SENS_FORCE_XPD_SAR, 3, SENS_FORCE_XPD_SAR_S);
    SET_PERI_REG_BITS(SENS_SAR_TSENS_CTRL_REG, SENS_TSENS_CLK_DIV, 10, SENS_TSENS_CLK_DIV_S);
    CLEAR_PERI_REG_MASK(SENS_SAR_TSENS_CTRL_REG, SENS_TSENS_POWER_UP);
    CLEAR_PERI_REG_MASK(SENS_SAR_TSENS_CTRL_REG, SENS_TSENS_DUMP_OUT);
    SET_PERI_REG_MASK(SENS_SAR_TSENS_CTRL_REG, SENS_TSENS_POWER_UP_FORCE);
    SET_PERI_REG_MASK(SENS_SAR_TSENS_CTRL_REG, SENS_TSENS_POWER_UP);
    ets_delay_us(100);
    SET_PERI_REG_MASK(SENS_SAR_TSENS_CTRL_REG, SENS_TSENS_DUMP_OUT);
    ets_delay_us(5);
    return GET_PERI_REG_BITS2(SENS_SAR_SLAVE_ADDR3_REG, SENS_TSENS_OUT, SENS_TSENS_OUT_S);
}

// returns up to 32 bytes of randomness (optional), takes optionallly extra entropy
static void get_random_internal(uint8_t* bytes_out, size_t len, const uint8_t* additional, size_t addlen)
{
    JADE_ASSERT(len <= SHA256_LEN);
    JADE_ASSERT((bytes_out && len) || (!bytes_out && !len));
    JADE_ASSERT((additional && addlen) || (!additional && !addlen));

    // in this function we read sensors data to add additional entropy
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    uint8_t buf[SHA512_LEN];

    hasherstart(ctx);

    // NOTE: there appears to be a GPIO conflict between button-A and the hall
    // sensor on an M5Stack.  Skip trying to read that sensor for extra entropy.
    // Also, qemu emulator does not seem to support this sensor.
#if !defined(CONFIG_BOARD_TYPE_M5_FIRE) && !defined(CONFIG_BOARD_TYPE_M5_BLACK_GRAY)                                   \
    && !defined(CONFIG_FREERTOS_UNICORE)
    call_uint16_t_func_to_hasher(ctx, hall_sensor_read);
#endif

    // now we add some entropy from axp192 sensors data
    call_uint16_t_func_to_hasher(ctx, power_get_vbat);
    call_uint16_t_func_to_hasher(ctx, power_get_vusb);
    call_uint16_t_func_to_hasher(ctx, power_get_iusb);
    call_uint16_t_func_to_hasher(ctx, power_get_ibat_charge);
    call_uint16_t_func_to_hasher(ctx, power_get_ibat_discharge);
    call_uint16_t_func_to_hasher(ctx, power_get_temp);
    call_uint16_t_func_to_hasher(ctx, esp32_get_temperature);
    const uint32_t counter = xthal_get_ccount();

    add_bytes_to_hasher(ctx, &counter, sizeof(counter));

    if (additional && addlen) {
        add_bytes_to_hasher(ctx, additional, addlen);
    }

    portENTER_CRITICAL(&rndmutex);

    add_bytes_to_hasher(ctx, entropy_state, sizeof(entropy_state));
    add_bytes_to_hasher(ctx, &rnd_counter, sizeof(rnd_counter));

    ++rnd_counter;

    // add some data from the stack
    add_bytes_to_hasher(ctx, buf, sizeof(buf));

    // esp_fill_random is considered a prng when
    // RF subsystem (or bootloader_random) aren't enabled
    esp_fill_random(buf, sizeof(buf));
    add_bytes_to_hasher(ctx, buf, sizeof(buf));

    hasherfinish(ctx, buf);

    if (len) {
        JADE_ASSERT(len <= SHA256_LEN);
        // If desired, copy (up to) the first 32 bytes of the hash output as output.
        memcpy(bytes_out, buf, len);
    }

    // Store the last 32 bytes of the hash output as new RNG state.
    memcpy(entropy_state, buf + SHA256_LEN, SHA256_LEN);

    portEXIT_CRITICAL(&rndmutex);
    mbedtls_sha512_free(&ctx);

    // Since refeeding can be called from any task (including internal rtos tasks),
    // we cannot be sure the 'sensitive_stack' is set up, so use wally_bzero()
    // explicitly in this case.
    wally_bzero(buf, sizeof(buf));
}

void refeed_entropy(const unsigned char* additional, size_t len)
{
    JADE_ASSERT(additional);
    JADE_ASSERT(len);
    get_random_internal(NULL, 0, additional, len);
}

void get_random(unsigned char* bytes_out, size_t len)
{
    JADE_ASSERT(bytes_out);
    JADE_ASSERT(len);

    size_t filled = 0;
    while (filled != len) {
        const size_t towrite = len - filled > SHA256_LEN ? SHA256_LEN : len - filled;
        get_random_internal(bytes_out + filled, towrite, NULL, 0);
        filled += towrite;
    }
}

unsigned char get_uniform_random_byte(const unsigned char upper_bound)
{
    // Algorithm from GDK / from the PCG family of random generators
    const unsigned char lower_threshold = (unsigned char)-upper_bound % upper_bound;
    while (true) {
        unsigned char rnd;
        get_random(&rnd, 1);
        if (rnd >= lower_threshold) {
            return rnd % upper_bound;
        }
    }
}

// taken from core
static void random_sanity_check()
{
    uint64_t start = xthal_get_ccount();

    // This does not measure the quality of randomness, but it does test that
    // get_random overwrites all 64 bytes of the output given a maximum
    // number of tries.
    static const ssize_t MAX_TRIES = 1024;
    uint8_t data[SHA256_LEN];
    SENSITIVE_PUSH(data, sizeof(data));
    bool overwritten[SHA256_LEN] = { 0 }; /* Tracks which bytes have been overwritten at least once */
    int num_overwritten;
    int tries = 0;
    /* Loop until all bytes have been overwritten at least once, or max number tries reached */
    do {
        memset(data, 0, sizeof(data));
        get_random(data, sizeof(data));

        for (int x = 0; x < sizeof(data); ++x) {
            overwritten[x] |= (data[x] != 0);
        }

        num_overwritten = 0;
        for (int x = 0; x < sizeof(data); ++x) {
            if (overwritten[x]) {
                num_overwritten += 1;
            }
        }

        tries += 1;
    } while (num_overwritten < sizeof(data) && tries < MAX_TRIES);
    /* If this failed, bailed out after too many tries */
    JADE_ASSERT(num_overwritten == sizeof(data));

    // Check that xthal_get_ccount increases at least during a get_random call + 1ms sleep.
    vTaskDelay(1 / portTICK_PERIOD_MS);
    uint64_t stop = xthal_get_ccount();
    JADE_ASSERT(stop != start);

    // We called xthal_get_ccount. Use it as entropy.
    memcpy(data, &start, sizeof(start));
    memcpy(data + sizeof(start), &stop, sizeof(stop));

    refeed_entropy(data, sizeof(data));

    SENSITIVE_POP(data);
}

static void strengthen(const int64_t ms)
{
    mbedtls_sha512_context ctx_outer;
    mbedtls_sha512_context ctx_inner;
    mbedtls_sha512_init(&ctx_outer);
    mbedtls_sha512_init(&ctx_inner);

    hasherstart(ctx_outer);

    // Note: esp_timer_get_time() returns in usecs
    const int64_t stop = esp_timer_get_time() + (1000 * ms);

    uint8_t data[SHA512_LEN];
    SENSITIVE_PUSH(data, sizeof(data));

    get_random(data, sizeof(data));

    do {
        for (size_t i = 0; i < 1000; ++i) {
            hasherstart(ctx_inner);
            add_bytes_to_hasher(ctx_inner, data, sizeof(data));
            hasherfinish(ctx_inner, data);
            const uint32_t counter = xthal_get_ccount();
            add_bytes_to_hasher(ctx_outer, &counter, sizeof(counter));
        }

    } while (esp_timer_get_time() < stop);

    add_bytes_to_hasher(ctx_outer, data, sizeof(data));

    hasherfinish(ctx_outer, data);

    refeed_entropy(data, sizeof(data));
    SENSITIVE_POP(data);

    mbedtls_sha512_free(&ctx_outer);
    mbedtls_sha512_free(&ctx_inner);
}

void random_start_collecting()
{
    // from https://docs.espressif.com/projects/esp-idf/en/release-v4.1/api-reference/system/system.html
    // If the RF subsystem is not used by the program, the function bootloader_random_enable() can be
    // called to enable an entropy source.
    // Note: we need to call bootloader_random_disable() afterwards if we want
    // BLE or I2S peripherals (camera?) working later.

    bootloader_random_enable();
    esp_fill_random(entropy_state, sizeof(entropy_state));
    bootloader_random_disable();

    adc1_config_width(ADC_WIDTH_BIT_12);
    vPortCPUInitializeMutex(&rndmutex);
}

void random_full_initialization()
{
    strengthen(STRENGTHEN_MILLISECONDS);
    random_sanity_check();
}
