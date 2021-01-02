import os

default_locale = 'EN'
strings = {
    'string_a': {'EN': 'EN_AAAAAA', 'IT': 'IT_AAAAA'},
    'string_b': {'EN': 'EN_BBBBBB'},
    'tt2': {'EN': 'EN_BBBBBB'},
}

num_buckets = 16

FNV32_BASE = 0x811c9dc5
FNV32_PRIME = 0x01000193


# File doesn't exist or out of date
def needs_regen(path, compare_ts):
    return not os.path.isfile(path) \
        or os.path.getmtime(path) < compare_ts


def max_first(arr):
    m = -1
    obj = None

    for (l, o) in arr:
        if l > m:
            m = l
            obj = o

    return obj


extracted_langs = list(
    max_first(
        ((len(
            strings[key]), dict.keys(
                strings[key])) for key in strings)))
num_langs = len(extracted_langs)

strings_heap = b''
offset = 0

buckets = [[] for x in range(0, num_buckets)]


def hash_str(string):
    h = FNV32_BASE
    for c in string.encode('ASCII'):
        h = ((h * FNV32_PRIME) & 0xFFFFFFFF) ^ c

    return h


def get_offset(string):
    global strings_heap
    global offset

    enc = string.encode('ASCII')
    len_enc = len(enc)

    strings_heap += enc + b'\x00'
    offset += len_enc + 1

    return offset - len_enc - 1


class HeapObj:
    def __init__(self, key, values):
        self.key = get_offset(key)

        self.arr = []
        for lang in extracted_langs:
            val = values.get(lang)
            self.arr.append(get_offset(val) if val else -1)

    def to_c(self, name, prev):
        str_struct = '{{ {} }}'.format(
            ','.join(['0' if x == -1
                      else 'str_heap+{}'.format(x) for x in self.arr])
        )

        return 'static const locale_map_node_t node_{} = \
{{ .key = {}, .value = {}, .next = {} }};'.format(
            name, 'str_heap+{}'.format(self.key), str_struct,
            '&node_{}'.format(prev) if prev else '0')


for key in strings:
    if not strings[key].get(default_locale):
        raise ValueError(
            'Missing value for default locale in string `{}`'.format(key))

    obj = HeapObj(key, strings[key])
    b = hash_str(key) % num_buckets
    buckets[b].append(obj)

out_h_path = 'autogen_lang.h'
out_c_path = 'autogen_lang.c'
this_mtime = os.path.getmtime(__file__)

# For consistency, let's say if either file needs regenerating, we
# regenerate both - just to ensure we always have a matching pair.
if needs_regen(out_h_path, this_mtime) or needs_regen(out_c_path, this_mtime):
    with open(out_c_path, 'w+') as f:
        f.write('#include "jlocale.h"\n')

        str_heap_to_string = str(strings_heap)
        str_heap_to_string = str_heap_to_string.replace('\\x00', '\\0')
        f.write('static const char str_heap[] = "{}";\n'.format(
            str_heap_to_string[2:]))

        for b in range(0, num_buckets):
            for i, s in enumerate(buckets[b]):
                prev = '{}_{}'.format(b, i - 1) if i else None
                f.write(s.to_c('{}_{}'.format(b, i), prev))
                f.write('\n')

        f.write('const locale_map_t default_map = {')
        f.write('.buckets = {')
        for b in range(0, num_buckets):
            len_b = len(buckets[b])
            f.write('&node_{}_{},'.format(b, len_b - 1) if len_b else '0,')
        f.write('}};')

        f.close()

    # TODO: do not use relative paths...
    with open(out_h_path, 'w+') as f:
        f.write('#ifndef _AUTOGEN_LANG_H\n')
        f.write('#define _AUTOGEN_LANG_H\n')

        f.write('#define BUCKETS_NUM {}\n'.format(num_buckets))
        f.write('#define LOCALE_NUM_LANGUAGES {}\n'.format(num_langs))

        f.write('typedef enum locale {\n')
        for l in extracted_langs:
            f.write('\tLOCALE_{},\n'.format(l))

        f.write('} jlocale_t;\n')
        f.write('#endif //_AUTOGEN_LANG_H\n')
        f.close()
