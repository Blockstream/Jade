#ifndef _LIBJADE_H_
#define _LIBJADE_H_ 1

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef LIBJADE_API
#if defined(_WIN32)
#ifdef LIBJADE_BUILD
#define LIBJADE_API __declspec(dllexport)
#else
#define LIBJADE_API
#endif
#elif defined(__GNUC__) && defined(LIBJADE_BUILD)
#define LIBJADE_API __attribute__((visibility("default")))
#else
#define LIBJADE_API
#endif
#endif

/*
 * Start the global libjade instance.
 * Only one instance may be running at at time, however it can be stopped
 * and restarted as many times as required.
 */
LIBJADE_API void libjade_start(void);

/*
 * Stop the global libjade instance.
 */
LIBJADE_API void libjade_stop(void);

/*
 * Send a CBOR message to the global libjade instance.
 */
LIBJADE_API bool libjade_send(const uint8_t* data, size_t size);

/*
 * Receive a CBOR reply message from the global libjade instance.
 * `libjade_release` must be used to free any returned message.
 */
LIBJADE_API uint8_t* libjade_receive(unsigned int timeout, size_t* size_out);

/*
 * Free a CBOR message returned from `libjade_receive`.
 */
LIBJADE_API void libjade_release(uint8_t* data);

/*
 * Set the logging verbosity level for the global libjade instance.
 * levels are 0-4 in decreasing verbosity, or 5 to disable logging
 */
LIBJADE_API void libjade_set_log_level(int level);

#endif /* _LIBJADE_H_ */
