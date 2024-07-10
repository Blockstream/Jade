#!/bin/bash

LOCAL_DIR="${1:-fwsvr_mirror}"
MISSING="missing.log"

FWSERVER="https://jadefw.blockstream.com/bin"

HWDIRS="jade jade1.1 jade2.0 jadedev jade1.1dev jade2.0dev"
INDEXES="LATEST BETA PREVIOUS"
INDEX_JSON="index.json"

# jq filter: <roots>/<release types>/<fw types>/<filename>
INDEX_JSON_FILENAME_FILTER=".[] | .[] | .[] | .filename"

if [ -d "${LOCAL_DIR}" ]
then
  rm -rf "${LOCAL_DIR}"
fi

mkdir "${LOCAL_DIR}"
pushd "${LOCAL_DIR}"

echo "Pulling fw server files into $(pwd)"
for hwdir in ${HWDIRS}
do
  mkdir "${hwdir}"
  pushd "${hwdir}"
  FWLOCATION="${FWSERVER}/${hwdir}"

  for index in "${INDEX_JSON}" ${INDEXES}
  do
    wget "${FWLOCATION}"/"${index}"
    if [ $? -ne 0 ]
    then
      echo "Missing: ${hwdir} - ${index}" >> ../"${MISSING}"
    else
      if [ "${index}" == "${INDEX_JSON}" ]
      then
        FWFILES=$(jq -r "${INDEX_JSON_FILENAME_FILTER}" "${INDEX_JSON}")
      else
        FWFILES=$(cat ${index})
      fi

      for fwfile in ${FWFILES}
      do
        if [ ! -f "${fwfile}" ]
        then
          if [ "${index}" != "${INDEX_JSON}" ]
          then
            echo "Missing from ${INDEX_JSON}: ${hwdir} - ${index} - ${fwfile}" >> ../"${MISSING}"
          fi

          mkdir -p $(dirname "${fwfile}")
          wget -O "${fwfile}" "${FWLOCATION}/${fwfile}"
          if [ $? -ne 0 ]
          then
            echo "Missing: ${hwdir} - ${index} - ${fwfile}" >> ../"${MISSING}"
          fi
          wget "${FWLOCATION}/${fwfile}.hash"
        fi
      done
    fi
  done
  popd
done
popd

if [ -f "${LOCAL_DIR}"/"${MISSING}" ]
then
  cat "${LOCAL_DIR}"/"${MISSING}"
  exit 1
fi
echo "ALL GOOD!"

