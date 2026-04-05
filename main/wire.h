#ifndef WIRE_H_
#define WIRE_H_

#include "freertos/FreeRTOS.h"
#include <stddef.h>
#include <stdint.h>

// Handle RPC message data from an external source.
// full_data_in must be a buffer of length MAX_INPUT_MSG_SIZE + 1.
// The first byte of full_data_in must be the input source (e.g. SOURCE_SERIAL).
// read_ptr must be the end index of all data in the buffer including new data.
// new_data_len is the size of new data written to the buffer before calling.
// Any valid messages that can be extracted from the data will be processed
// and removed from the buffer, leaving read_ptr at the new end index.
void handle_data(uint8_t* full_data_in, size_t* read_ptr, size_t new_data_len, TickType_t* last_processing_time);

#endif /* WIRE_H_ */
