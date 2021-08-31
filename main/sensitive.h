#ifndef SENSITIVE_H_
#define SENSITIVE_H_

/* Specify memory areas as being sensitive, i.e. containing data that should
 * be zeroed after use. A stack of sensitive memory areas is maintained, callers
 * must push and pop items from the stack in order. Example:
 *
 * unsigned char private_key[PRIVATE_KEY_SIZE];
 * SENSITIVE_PUSH(private_key, sizeof(private_key));
 *
 * get_private_key(private_key);
 *
 * SENSITIVE_POP(private_key);
 *
 * The idea is that somewhere at the top level of the message handling loop
 * the code will call sensitive_assert_empty() after every function which will
 * catch any leaks. SENSITIVE_POP checks the address matches the top item on
 * the stack.
 *
 * sensitive_clear_stack() can be called by the ABORT logic, it pops every item
 * from the stack and zeroes it as it goes.
 *
 * More examples:
 *
 * -- leaky
 * void leaky(void)
 * {
 *     unsigned char buf[1024];
 *     SENSITIVE_PUSH(buf, sizeof(buf));
 * }
 *
 * void main(void)
 * {
 *     leaky();
 *     sensitive_assert_empty(); // this will abort (after zeroing the leaked buffer)
 * }
 *
 * -- wrong order
 * void wrong_order(void)
 * {
 *     unsigned char buf[1024];
 *     unsigned char buf2[1024];
 *     SENSITIVE_PUSH(buf, sizeof(buf));
 *     SENSITIVE_PUSH(buf2, sizeof(buf2));
 *     SENSITIVE_POP(buf); // this will abort (after zeroing both buffers)
 *     SENSITIVE_POP(buf2);
 * }
 *
 * -- abort
 * void abort(void)
 * {
 *     // Calling sensitive_clear_stack() will zero everything currently
 *     // on the stack and free the stack memory.  The sensitive-stack cannot
 *     // be used again after this call (unless/until sensitive_init() is called).
 *     sensitive_clear_stack();
 *     abort();
 * }
 */

void sensitive_push(const char* file, int line, void* addr, size_t size);
void sensitive_pop(const char* file, int line, void* addr);
void sensitive_clear_stack(void);
void sensitive_assert_empty(void);
void sensitive_init(void);

#define SENSITIVE_PUSH(addr, size) sensitive_push(__FILE__, __LINE__, addr, size)
#define SENSITIVE_POP(addr) sensitive_pop(__FILE__, __LINE__, addr)

#endif
