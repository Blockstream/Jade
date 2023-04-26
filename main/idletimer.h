#ifndef IDLETIMER_H_
#define IDLETIMER_H_

#include <stdbool.h>
#include <stdint.h>

void idletimer_init(void);
void idletimer_set_min_timeout_secs(uint16_t min_timeout_secs);
void idletimer_register_activity(bool is_ui);

#endif /* IDLETIMER_H_ */
