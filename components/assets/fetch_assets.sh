#!/bin/bash

# Exclude certain issuers - simple regexes in 'exclude' file
exclude_issuers()
{
    ASSETS_FILE="${1}"
    EXCLUDE_ISSUERS_FILE="${2}"
    local TMPFILE="jq.out.tmp"

    for exclude_issuer in $(cat "${EXCLUDE_ISSUERS_FILE}")
    do
        echo "Excluding: ${exclude_issuer}"
        jq --arg excluded "${exclude_issuer}" 'with_entries(select(.value.entity.domain | test($excluded) | not))' "${ASSETS_FILE}" > "${TMPFILE}"
        mv "${TMPFILE}" "${ASSETS_FILE}"
    done
}


# 1. Mainnet assets file
wget -O ./tmp_assets.json https://assets.blockstream.info/
exclude_issuers ./tmp_assets.json ./excluded_issuers.txt
python3 -m json.tool --sort-keys ./tmp_assets.json ./asset_data.json
rm ./tmp_assets.json

# 1. Testnet assets file
wget -O ./tmp_assets_testnet.json https://assets-testnet.blockstream.info/
exclude_issuers ./tmp_assets_testnet.json ./excluded_issuers_testnet.txt
python3 -m json.tool --sort-keys ./tmp_assets_testnet.json ./asset_data_testnet.json
rm ./tmp_assets_testnet.json
