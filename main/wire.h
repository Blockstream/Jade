#ifndef WIRE_H_
#define WIRE_H_

#include "freertos/FreeRTOS.h"
#include <stddef.h>
#include <stdint.h>

void handle_data(uint8_t* full_data_in, size_t* read_ptr, size_t new_data_len, TickType_t* last_processing_time,
    bool reject_incomplete);

#endif /* WIRE_H_ */
