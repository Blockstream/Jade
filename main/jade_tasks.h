#ifndef JADE_TASKS_H_
#define JADE_TASKS_H_

#include <sdkconfig.h>

// Jade has primary and secondary cores, with certain tasks pinned to these cores
// In a uni-core configuration (eg qemu) there is no second core
// NOTE: the main task is automatically started on core 0 (JADE_CORE_PRIMARY)
#define JADE_CORE_PRIMARY 0

#ifdef CONFIG_FREERTOS_UNICORE
#define JADE_CORE_SECONDARY 0
#else
#define JADE_CORE_SECONDARY 1
#endif

#define JADE_CORE_GUI JADE_CORE_SECONDARY

// Task priorities
// NOTE: the automatically started main task has priority (tskIDLE_PRIORITY + 1)
#define JADE_TASK_PRIO_READER (tskIDLE_PRIORITY + 4)

#define JADE_TASK_PRIO_GUI (tskIDLE_PRIORITY + 3)
#define JADE_TASK_PRIO_WHEEL (tskIDLE_PRIORITY + 3)
#define JADE_TASK_PRIO_CAMERA (tskIDLE_PRIORITY + 3)
#define JADE_TASK_PRIO_USB (tskIDLE_PRIORITY + 3)

#define JADE_TASK_PRIO_WRITER (tskIDLE_PRIORITY + 2)

// The temporary task is an extension to the main task when an
// amount of additional stack space is temporarily required.
#define JADE_TASK_PRIO_TEMPORARY (tskIDLE_PRIORITY + 1)
// Main Task Priority : (tskIDLE_PRIORITY + 1)

#define JADE_TASK_PRIO_IDLETIMER (tskIDLE_PRIORITY)

#endif /* JADE_TASKS_H_ */
