#ifndef IDLETIMER_H_
#define IDLETIMER_H_

#include <stdint.h>

void idletimer_init(void);
void idletimer_set_min_timeout_secs(uint16_t min_timeout_secs);
void idletimer_register_activity(void);

#endif /* IDLETIMER_H_ */
