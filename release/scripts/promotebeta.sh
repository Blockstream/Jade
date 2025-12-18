#!/bin/bash

HWDIRS="jade jade1.1 jade2.0 jade2.0c jadedev jade1.1dev jade2.0dev jade2.0cdev"

STAGING="staging"
UPLOAD="upload"
WORKING_DIR="${STAGING}/${UPLOAD}"

pushd "${WORKING_DIR}"
for hwdir in ${HWDIRS}
do
  pushd "${hwdir}"
  cat LATEST PREVIOUS > PREVIOUS.tmp
  mv PREVIOUS.tmp PREVIOUS
  cp BETA LATEST
  popd
done
popd
