#!/bin/bash

# 1. Mainnet assets file
wget -O ./tmp_assets.json https://assets.blockstream.info/
python3 -m json.tool --sort-keys ./tmp_assets.json ./asset_data.json
rm ./tmp_assets.json

# 1. Testnet assets file
wget -O ./tmp_assets_testnet.json https://assets-testnet.blockstream.info/
python3 -m json.tool --sort-keys ./tmp_assets_testnet.json ./asset_data_testnet.json
rm ./tmp_assets_testnet.json
