#ifndef QEMU_TCP_H
#define QEMU_TCP_H

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdbool.h>

bool qemu_tcp_init(TaskHandle_t* tcp_handle);

#endif /* QEMU_TCP_H */
