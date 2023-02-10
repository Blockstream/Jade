#include "wally_ext.h"
#include "jade_assert.h"
#include "jade_log.h"
#include "jade_wally_verify.h"
#include "malloc_ext.h"
#include "random.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdint.h>

/* index == 0 is reserved for idf internal use,
 * see https://docs.espressif.com/projects/esp-idf/en/v4.3.2/esp32/api-guides/thread-local-storage.html
 * and 1 is used by sensitive.c */
#define TLS_INDEX_WALLY 2
#if TLS_INDEX_WALLY >= CONFIG_FREERTOS_THREAD_LOCAL_STORAGE_POINTERS
#error "Error, CONFIG_FREERTOS_THREAD_LOCAL_STORAGE_POINTERS should be increased"
#endif

struct jade_wally_ctx {
    struct secp256k1_context_struct* secp_ctx;
    bool ctx_requires_delete;
};

void jade_wally_randomize_secp_ctx(void)
{
    /* randomize the secp ctx */
    uint8_t rnd[WALLY_SECP_RANDOMIZE_LEN];
    get_random(rnd, sizeof(rnd));

    JADE_WALLY_VERIFY(wally_secp_randomize(rnd, sizeof(rnd)));

    /* Note: we can't use sensitive as this may get called from threads
     * that haven't called sensitive_init, such as the one that calls into
     * ble_hs_pvcy_get_default_irk */
    JADE_WALLY_VERIFY(wally_bzero(rnd, sizeof(rnd)));
}

/* This callback appears to be called from the IDLE task, and *NOT* from the task
 * that the callback was registered from.
 * Avoided JADE_ASSERT() calls in this callback, as causing that kind of
 * chaos in the system IDLE task would probably not go down well. */
static void jade_wally_delete_cb(int index, void* ptr)
{
    JADE_LOGI("jade_wally_delete_cb() called for pointer %p (from tls index %d) by task '%s'", ptr, index,
        pcTaskGetName(NULL));

    if (!ptr) {
        JADE_LOGE("jade_wally_delete_cb() called with null ptr!  Doing nothing.");
        return;
    }

    if (index == TLS_INDEX_WALLY) {
        struct jade_wally_ctx* const ctx = ptr;
        if (ctx->secp_ctx) {
            /* We don't want to delete wally's internal secp ctx */
            if (ctx->ctx_requires_delete) {
                wally_secp_context_free(ctx->secp_ctx);
            }
        } else {
            JADE_LOGE("jade_wally_delete_cb() ctx->secp_ctx is NULL - Skipping call to free_context!");
        }
    } else {
        JADE_LOGE("jade_wally_delete_cb() called with index %u - Skipping call to free context!", index);
    }

    free(ptr);
}

static inline struct jade_wally_ctx* get_jade_wally_ctx(void)
{
    struct jade_wally_ctx* ctx = pvTaskGetThreadLocalStoragePointer(NULL, TLS_INDEX_WALLY);
    JADE_LOGD("get_ctx returned %p for task '%s'", ctx, pcTaskGetName(NULL));
    return ctx;
}

static void set_jade_wally_ctx(struct jade_wally_ctx** ptr, struct secp256k1_context_struct* secp_ctx)
{
    JADE_INIT_OUT_PPTR(ptr);

    JADE_LOGI("set_jade_wally_ctx() called by task '%s' with context %p", pcTaskGetName(NULL), secp_ctx);

    *ptr = JADE_MALLOC_PREFER_SPIRAM(sizeof(struct jade_wally_ctx));
    struct jade_wally_ctx* const ctx = *ptr;

    /* Flag an existing context as not requiring freeing, and that a new context does */
    if (secp_ctx) {
        /* Existing context, not owned here, do not free */
        ctx->secp_ctx = secp_ctx;
        ctx->ctx_requires_delete = false;
    } else {
        /* New context, owned here, will require freeing later */
        ctx->secp_ctx = wally_get_new_secp_context();
        ctx->ctx_requires_delete = true;
    }
    JADE_ASSERT(ctx->secp_ctx);

    vTaskSetThreadLocalStoragePointerAndDelCallback(NULL, TLS_INDEX_WALLY, ctx, &jade_wally_delete_cb);
    JADE_ASSERT(get_jade_wally_ctx());

    /* Randomize the new secp ctx */
    /* Note: wally will call jade_wally_get_secp_ctx (which calls in turn
     * set_jade_wally_ctx) within wally_secp_randomize but ctx now is set so it
     * won't recurse forever */
    jade_wally_randomize_secp_ctx();

    JADE_LOGI("set_jade_wally_ctx() set context %p (%p) for task '%s'", ctx, ctx->secp_ctx, pcTaskGetName(NULL));
}

/* This function will be set in wally as the function to fetch the secp context*/
static struct secp256k1_context_struct* jade_wally_get_secp_ctx(void)
{
    struct jade_wally_ctx* ctx = get_jade_wally_ctx();
    if (!ctx) {
        /* No ctx available, create a fresh one for this task */
        set_jade_wally_ctx(&ctx, NULL);
    }
    JADE_ASSERT(ctx);
    JADE_ASSERT(ctx->secp_ctx);
    return ctx->secp_ctx;
}

void jade_wally_init(void)
{
    JADE_WALLY_VERIFY(wally_init(0));
    size_t is_elements_build = 0;
    JADE_WALLY_VERIFY(wally_is_elements_build(&is_elements_build));
    JADE_ASSERT(is_elements_build == 1);

    struct wally_operations ops = {
        .struct_size = sizeof(struct wally_operations),
        .secp_context_fn = &jade_wally_get_secp_ctx,
    };

    /* To avoid having a secp ctx go to waste, reuse the wally default ctx
     * for the main task (wally_get_secp_context has to be called before
     * wally_set_operations is called) */
    struct jade_wally_ctx* ctx = NULL;
    set_jade_wally_ctx(&ctx, wally_get_secp_context());
    JADE_WALLY_VERIFY(wally_set_operations(&ops));
}
