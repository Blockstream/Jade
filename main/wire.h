#ifndef WIRE_H_
#define WIRE_H_

#include "process.h"
#include <stdint.h>

void handle_data(
    uint8_t* full_data_in, size_t initial_offset, size_t* read_ptr, bool reject_if_no_msg, uint8_t* data_out);

#endif /* WIRE_H_ */
