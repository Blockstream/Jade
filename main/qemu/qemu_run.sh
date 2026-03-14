#!/usr/bin/env bash
#
if [ -z "${IDF_PATH}" ]; then
    pushd /opt/esp/idf && . ./export.sh && popd
fi

pkill -f qemu-system-xtensa || true

if [ "$1" = "--gdb" ]; then
    EXTRA_ARGS="-s -S"
    BG="&"
fi

qemu-system-xtensa $EXTRA_ARGS -nographic \
    -machine esp32 \
    -m 4M \
    -drive file=/flash_image.bin,if=mtd,format=raw \
    -nic user,model=open_eth,id=lo0,hostfwd=tcp:0.0.0.0:30122-:30122,hostfwd=tcp:0.0.0.0:30121-:30121 \
    -drive file=/qemu_efuse.bin,if=none,format=raw,id=efuse \
    -global driver=nvram.esp32.efuse,property=drive,value=efuse \
    -serial pty $BG
    #-serial mon:stdio

if [ "$1" = "--gdb" ]; then
    xtensa-esp32-elf-gdb /jade/build/jade.elf \
        -ex "target remote :1234" \
        -ex "monitor system_reset" \
        -ex "tb app_main" -ex "c" \
        -ex "b main.c:120"\
        -ex 'info b' -ex 'set print pretty on'
fi
