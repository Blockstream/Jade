#!/bin/bash
set -eo pipefail

(cd main && clang-format -i *.c *.h */*.{c,h,inc})

clang-format -i tools/bip85_rsa_key_gen/main.c

if [ -f /.dockerenv ]; then
    PATH=${PATH}:/root/.local/bin
fi

if [ -x "$(command -v pycodestyle)" ]; then
    pycodestyle --max-line-length=100 *.py jadepy/*.py tools/*.py
fi

KCONFIG_FILE=main/Kconfig.projbuild

${IDF_PATH}/tools/ci/check_kconfigs.py ${KCONFIG_FILE} || true
mv ${KCONFIG_FILE}.new ${KCONFIG_FILE}
