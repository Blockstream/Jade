import sys
import logging
import json
import os

# Enable logging
logger = logging.getLogger('gen_assets')
logger.setLevel(logging.DEBUG)


# Read json file downloaded from asset registry
# https://assets.blockstream.info/
def read_input_file(filename):
    # Load json input file into dict
    logger.debug(f'Reading file: {filename}')
    with open(input_file, 'r') as f:
        assets = json.load(f)

    logger.info(f'Read {len(assets)} assets')
    return assets


# Write an asset entry into the output file.
# Returns how many rows were written (usually 1, or 0 on error)
def write_asset(asset, f):
    try:
        assetid = asset['asset_id']
        ticker = asset['ticker']
        issuer = asset['entity']['domain']
        precision = asset['precision']

        # Not sure what the expected maximum precision value is - will cap at
        # single-digit here just as a sanity check.  If we exceed that we will
        # also need to check buffer sizes etc. in ui/sign_tx.c where we print
        # the scaled number as a string (currently that asserts if > 9).
        # NOTE: 'ticker' is allowed to be null/None/'' and is passed as NULL
        if assetid and issuer and precision >= 0 and precision < 10:
            ticker = f'"{ticker}"' if ticker else 'NULL'
            f.write(f'ASSET_INFO("{assetid}", {ticker}, "{issuer}", {precision}),\n')
            return 1

    except Exception as e:
        logger.error(e)

    logger.error(f'Skipping: {asset}')
    return 0


# Write the assets as a file suitable for inclusion in assets.c
def write_output_file(assets, filename):
    with open(filename, 'w') as f:
        # Header comment
        f.write('/**\n')
        f.write('* DO NOT EDIT - auto-generated from asset data\n')
        f.write('* Intended for inclusion in assets.c\n')
        f.write('**/\n\n')

        # Write assets
        return sum(map(lambda a: write_asset(a, f), assets.values()))


# Can be run as a utility
if __name__ == '__main__':
    jadehandler = logging.StreamHandler()
    logger.addHandler(jadehandler)

    # Must be passed input json file (eg. downloaded from https://assets.blockstream.info/)
    # and the output header/include file to create, for inclusion in assets.c
    if len(sys.argv) != 3:
        print('Usage: python', sys.argv[0], '<input json> <ouput file>')
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Load input file
    assets = read_input_file(input_file)
    assert len(assets) > 0

    # Write output file
    written = write_output_file(assets, output_file)
    skipped = len(assets) - written

    logger.info(f'Written {written} assets')

    assert skipped == 0, f'Skipped {skipped} assets'
