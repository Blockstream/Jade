#!/bin/bash
set -eo pipefail

have_cmd()
{
    command -v "$1" > /dev/null 2>&1
}

CLANG_FORMAT=clang-format-19
if ! have_cmd ${CLANG_FORMAT}; then
    echo "ERROR: ${CLANG_FORMAT} command not found, please install it"
    exit 1
fi
(cd main && ${CLANG_FORMAT} -i *.c *.h */*.{c,h,inc})
pushd libjade
LIBJADE_SRCS=$(ls *.c *.h | grep -v miniz)
${CLANG_FORMAT} -i $LIBJADE_SRCS */*.h */*/*.h
popd

${CLANG_FORMAT} -i tools/bip85_rsa_key_gen/main.c

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
