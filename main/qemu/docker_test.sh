#!/usr/bin/env bash
set -e

. /root/esp/esp-idf/export.sh

cd /jade

rm -fr sdkconfig
cp configs/sdkconfig_qemu.defaults sdkconfig.defaults
idf.py all
virtualenv -p python3 /venv3
source /venv3/bin/activate
pip install -r requirements.txt
python ./fwprep.py build/jade.bin build
gcc -O2 -DBSDIFF_EXECUTABLE -o bsdiff components/esp32_bsdiff/bsdiff.c
./bsdiff build/jade.bin build/jade.bin /patch.bin
SIZE_BINARY=$(stat --printf="%s" build/jade.bin)
SIZE_PATCH=$(stat --printf="%s" /patch.bin)
python -c "import zlib; import sys; open(sys.argv[2], 'wb').write(zlib.compress(open(sys.argv[1], 'rb').read(), 9))" /patch.bin /patch_${SIZE_BINARY}_${SIZE_PATCH}.bin
./main/qemu/make-flash-img.sh
./main/qemu/qemu_ci_flash.sh
