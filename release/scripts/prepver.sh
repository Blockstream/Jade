#!/bin/bash

HWDIRS="jade jade1.1 jadedev jade1.1dev"

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

echo "Refreshing fwsvr mirror and creating upload area"
"${CHECKSVR}"

rm -rf "${UPLOAD}"
cp -R "${FWSVR_MIRROR}" "${UPLOAD}"
popd
