#!/bin/bash
set -eo pipefail

if [[ -f build/old_jade.bin ]]; then
    if [[ ! -f build/bsdiff ]]; then
        gcc -O2 -DBSDIFF_EXECUTABLE -o build/bsdiff components/esp32_bsdiff/bsdiff.c
    fi
    # builds just the app
    idf.py app
    rm -fr build/patch.bin
    ./build/bsdiff build/old_jade.bin build/jade.bin build/patch.bin
    FULL_SIZE_NEW=$(stat --printf="%s" build/jade.bin)
    FULL_SIZE_PATCH=$(stat --printf="%s" build/patch.bin)
    OLD_VERSION=$(strings -n 6 build/old_jade.bin | head -4 | egrep "^[0-9]*\.[0-9]*\.[0-9]*" | head -1 || true)
    NEW_VERSION=$(strings -n 6 build/jade.bin | head -4 | egrep "^[0-9]*\.[0-9]*\.[0-9]*" | head -1 || true)
    OLD_BLD_TYPE="ble"
    if [[ $(strings -n 6 ./build/old_jade.bin | head -4 | grep NORADIO)  == "NORADIO" ]]; then
        OLD_BLD_TYPE="noradio"
    fi
    NEW_BLD_TYPE="ble"
    if [[ $(strings -n 6 ./build/jade.bin | head -4 | grep NORADIO)  == "NORADIO" ]]; then
        NEW_BLD_TYPE="noradio"
    fi
    PATCH_NAME=build/${NEW_VERSION}_${NEW_BLD_TYPE}_from_${OLD_VERSION}_${OLD_BLD_TYPE}_sizes_${FULL_SIZE_NEW}_${FULL_SIZE_PATCH}_patch.bin
    python -c "import zlib; import sys; open(sys.argv[2], 'wb').write(zlib.compress(open(sys.argv[1], 'rb').read(), 9))" build/patch.bin ${PATCH_NAME}
    ./jade_ota.py --skipble --fwfile=${PATCH_NAME}
else
    # flashes both bootloader and app
    idf.py flash
fi

cp build/jade.bin build/old_jade.bin
