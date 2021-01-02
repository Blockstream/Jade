Jade h/coded asset registry data.

To update:
1. Download json file from https://assets.blockstream.info/
  eg. `wget -O assets.json https://assets.blockstream.info/`
2. pretty-print and order the data that into this directory as 'asset_data.json'
  eg. `python3 -m json.tool --sort-keys assets.json components/assets/asset_data.json`
3. Build
 - gen_assets.py should be invoked.
 - it creates a file in the build dir called 'asset_data.inc'
 - this file is included into assets.c (in this directory) and compiled

NOTE: the prettified json file `components/assets/asset_data.json` is considered
the source file and should be checked into the repo.
