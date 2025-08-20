# python make_icons.py | clang-format >icons.inc
for name in ['statusbar_large']:
    contents = open(f'../logo/{name}.bin.gz', 'rb').read()
    var = f'_binary_{name}_bin_gz'
    print(f'const uint8_t {var}_start[{len(contents)}] = {{')
    for n, b in enumerate(contents):
        sep = ', ' if n else ''
        print(f'{sep}{hex(b)}')
    print(f'}};\nconst uint8_t* {var}_end = {var}_start + {len(contents)};\n')
