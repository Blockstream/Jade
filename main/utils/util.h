#ifndef UTIL_H_
#define UTIL_H_

static inline void uint32_to_be(const uint32_t val, uint8_t* buffer)
{
    buffer[0] = (val >> 24) & 0xFF;
    buffer[1] = (val >> 16) & 0xFF;
    buffer[2] = (val >> 8) & 0xFF;
    buffer[3] = val & 0xFF;
}

static inline void uint32_to_le(const uint32_t val, uint8_t* buffer)
{
    buffer[0] = val & 0xFF;
    buffer[1] = (val >> 8) & 0xFF;
    buffer[2] = (val >> 16) & 0xFF;
    buffer[3] = (val >> 24) & 0xFF;
}

#endif /* UTIL_H_ */
