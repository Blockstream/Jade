#ifndef JLOCALE_H_
#define JLOCALE_H_

#include <stdint.h>
#include "autogen_lang.h"


typedef const char *locale_multilang_string_t[LOCALE_NUM_LANGUAGES];

typedef struct locale_map_node {
    const char *key;
    const locale_multilang_string_t value;

    const struct locale_map_node *next;
} locale_map_node_t;

typedef struct locale_map {
    const struct locale_map_node *buckets[BUCKETS_NUM];
} locale_map_t;

extern const locale_map_t default_map;


const locale_multilang_string_t *locale_get(const char *key);
const char *locale_get_lang(const char *key, jlocale_t lang);

const char *locale_lang_with_fallback(const locale_multilang_string_t *str, jlocale_t lang);


#endif /* JLOCALE_H_ */
