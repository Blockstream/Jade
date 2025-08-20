#!/bin/bash
set -eo pipefail

(cd main && clang-format -i *.c *.h */*.{c,h,inc})
pushd libjade
LIBJADE_SRCS=$(ls *.c *.h | grep -v miniz)
clang-format -i $LIBJADE_SRCS */*.h */*/*.h
popd

clang-format -i tools/bip85_rsa_key_gen/main.c

if [ -f /.dockerenv ]; then
    PATH=${PATH}:/root/.local/bin
fi

if [ -x "$(command -v pycodestyle)" ]; then
    pycodestyle --max-line-length=100 *.py jadepy/*.py tools/*.py
fi

KCONFIG_FILE=main/Kconfig.projbuild

if [ -x ${IDF_PATH}/tools/ci/check_kconfigs.py ]; then
    ${IDF_PATH}/tools/ci/check_kconfigs.py ${KCONFIG_FILE} || true
    mv ${KCONFIG_FILE}.new ${KCONFIG_FILE}
fi
