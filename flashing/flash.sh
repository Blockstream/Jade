#!/usr/bin/env bash
set -eo pipefail

export FLASHROOT="${FLASHROOT:-/tmp/jade}"

if  [ ! -d "${FLASHROOT}" ]; then
    echo "Script run with invalid FLASHROOT, ${FLASHROOT}"
    exit 1
fi

${FLASHROOT}/flashing/flash_jade.sh
