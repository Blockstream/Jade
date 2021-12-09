Jade h/coded asset registry data.

To update:
1. Run `fetch_assets.sh`
  This will download the assets json from https://assets.blockstream.info/ and https://assets-testnet.blockstream.info/
  and write json files sorted by asset-id, for adding to the repo.
2. Build
 - gen_assets.py should be invoked for each sorted input file
 - it creates files in the build dir called 'asset_data.inc' and 'asset_data_testnet.inc'
 - these files are included into assets.c (in this directory) and compiled

NOTE: the prettified json files `asset_data.json` and `asset_data_testnet.json` are considered
the source files and should be checked into the repo.
