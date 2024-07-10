#!/bin/bash

HWDIRS="jade jade1.1 jade2.0 jadedev jade1.1dev jade2.0dev"

STAGING="staging"
UPLOAD="upload"
WORKING_DIR="${STAGING}/${UPLOAD}"

if [ -z "${1}" ]
then
  echo "Usage ${0} <stable-version> [ <beta version> ]"
  exit 1
fi
VER_STABLE="${1}"
VER_BETA="${2}"

# Relative paths from where it will be referenced in
# jade/release/staging/upload/<hw flavour>
MKINDEX="../../../tools/mkindex.py"

pushd "${WORKING_DIR}"
for hwdir in ${HWDIRS}
do
  echo "Generating index file for ${hwdir}"
  "${MKINDEX}" "${hwdir}" "${VER_STABLE}" "${VER_BETA}"
done
popd
