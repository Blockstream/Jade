#!/bin/bash

HWDIRS="jade jade1.1 jade2.0 jadedev jade1.1dev jade2.0dev"

STAGING="staging"
UPLOAD="upload"
FWSVR_MIRROR="fwsvr_mirror"

# Path relative to 'staging' dir
CHECKSVR="../scripts/checkfwsvr.sh"

if [ -z "${1}" ]
then
  echo "Usage ${0} <version>"
  exit 1
fi
VER_DIR="${1}"

# Ensure 'staging' exists
mkdir -p "${STAGING}"
pushd "${STAGING}"

if [ -f "${VER_DIR}" ]
then
  echo "Error: ${VER_DIR} file exists - must be removed or renamed"
  exit 2
fi

if [ -d "${VER_DIR}" ]
then
  echo "Warning: ${VER_DIR} directory exists"
else
  mkdir -p "${VER_DIR}"
  echo "Created directory ${VER_DIR}"
fi

# Ensure each subdirectory exists
pushd "${VER_DIR}"
for hwdir in ${HWDIRS}
do
  if [ -d "${hwdir}" ]
  then
    echo "Warning: ${hwdir} directory exists"
  else
    mkdir -p "${hwdir}"
    echo "Created directory ${hwdir}"
  fi
done

popd

echo "Refreshing fwsvr mirror and creating upload area"
"${CHECKSVR}"

rm -rf "${UPLOAD}"
cp -R "${FWSVR_MIRROR}" "${UPLOAD}"
popd
