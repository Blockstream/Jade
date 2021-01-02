#include "jlocale.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define FNV32_BASE ((uint32_t) 0x811c9dc5)
#define FNV32_PRIME ((uint32_t) 0x01000193)

#include "autogen_lang.c"

static uint32_t strhash(const char *str) {
    uint32_t c, hash = FNV32_BASE;
    while ((c = (unsigned char) *str++))
        hash = (hash * FNV32_PRIME) ^ c;

    return hash;
}

const locale_multilang_string_t *locale_get(const char *key) {
    uint32_t bucket = strhash(key) % BUCKETS_NUM;

    const locale_map_node_t *last = default_map.buckets[bucket];
    while (last) {
        if (strcmp(key, last->key) == 0) {
            return &last->value;
        }

        last = last->next;
    }

    return NULL;
}

const char *locale_get_lang(const char *key, jlocale_t lang) {
    const locale_multilang_string_t *str = locale_get(key);

    if (!str) {
        return NULL;
    }

    return str[lang];
}

const char *locale_lang_with_fallback(const locale_multilang_string_t *str, jlocale_t lang) {
    return (*str)[lang] ? (*str)[lang] : (*str)[LOCALE_EN];
}
