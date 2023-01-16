#!/usr/bin/env python

import os
import sys
import time
import json
import logging
import argparse
import requests

from jadepy import JadeAPI, JadeError
from tools import fwtools

FWSERVER_URL_ROOT = 'https://jadefw.blockstream.com/bin'
FWSERVER_INDEX_FILE = 'index.json'

# Enable jade logging
jadehandler = logging.StreamHandler()
logger = logging.getLogger('jade')
logger.setLevel(logging.DEBUG)
logger.addHandler(jadehandler)
device_logger = logging.getLogger('jade-device')
device_logger.setLevel(logging.DEBUG)
device_logger.addHandler(jadehandler)


# Parse the index file and select firmware to download
def get_fw_metadata(verinfo, release_data):
    # Select firmware from list of available
    def _full_fw_label(fw):
        return f'{fw["version"]} - {fw["config"]}'

    def _delta_fw_label(fw):
        return _full_fw_label(fw).ljust(18) + f'FROM  {fw["from_version"]} - {fw["from_config"]}'

    def _delta_appropriate(fw):
        return fw['from_version'] == verinfo['JADE_VERSION'] and \
               fw['from_config'].lower() == verinfo['JADE_CONFIG'].lower()

    print(f'Current Jade fw: {verinfo["JADE_VERSION"]} - {verinfo["JADE_CONFIG"].lower()}')
    print('-')

    i = 0
    print('Delta patches (faster)')
    deltas = list(filter(_delta_appropriate, release_data.get('delta', [])))
    for i, label in enumerate((_delta_fw_label(fw) for fw in deltas), i + 1):  # 1 based index
        print(f'{i})'.ljust(3), label)
    print('-')

    print('Full firmware images')
    fullfws = release_data.get('full', [])
    for i, label in enumerate((_full_fw_label(fw) for fw in fullfws), i + 1):  # continue numbering
        print(f'{i})'.ljust(3), label)
    print('-')

    numdeltas = len(deltas)
    while True:
        selectedfw = input('Select firmware: ')
        if selectedfw.isdigit():
            selectedfw = int(selectedfw)
            if selectedfw > 0 and selectedfw <= i:
                selectedfw -= 1  # zero-based index
                if selectedfw < numdeltas:
                    # delta firmware
                    selectedfw = deltas[selectedfw]
                else:
                    selectedfw -= numdeltas
                    selectedfw = fullfws[selectedfw]
                return selectedfw


# Download compressed firmware file from Firmware Server using 'requests'
def download_file(verinfo, release):
    # Workout hw_target subdir
    hw_target = {'JADE': 'jade', 'JADE_V1.1': 'jade1.1'}.get(verinfo['BOARD_TYPE'])
    build_type = {'SB': '', 'DEV': 'dev'}.get(verinfo['JADE_FEATURES'])
    if hw_target is None or build_type is None:
        logger.error(f'Unsupported hardware: {verinfo["BOARD_TYPE"]} / {verinfo["JADE_FEATURES"]}')
        return None
    hw_target += build_type

    # GET the index file from the firmware server which lists the
    # available firmwares
    url = f'{FWSERVER_URL_ROOT}/{hw_target}/{FWSERVER_INDEX_FILE}'
    logger.info(f'Downloading firmware index file {url}')
    rslt = requests.get(url)
    assert rslt.status_code == 200, f'Cannot download index file {url}: {rslt.status_code}'

    # Get the filename of the firmware to download
    release_data = json.loads(rslt.text).get(release)
    if not release_data:
        logger.warning(f'No suitable firmware for tag: {release}')
        return None, None, None

    fwdata = get_fw_metadata(verinfo, release_data)
    fwname = fwdata['filename']

    # GET the selected firmware from the server
    url = f'{FWSERVER_URL_ROOT}/{hw_target}/{fwname}'
    logger.info(f'Downloading firmware {url}')
    rslt = requests.get(f'{FWSERVER_URL_ROOT}/{hw_target}/{fwname}')
    assert rslt.status_code == 200, f'Cannot download firmware file {url}: {rslt.status_code}'

    fwcmp = rslt.content
    logger.info(f'Downloaded {len(fwcmp)} byte firmware')

    # Optionally save the file locally
    write_file = input('Save local copy of downloaded firmware? [y/N]').strip()
    if write_file == 'y' or write_file == 'Y':
        fwtools.write(fwcmp, os.path.basename(fwname))

    # Return
    return fwdata['fwsize'], fwdata.get('patch_size'), fwcmp


# Use a local (previously downloaded) firmware file.
# Must have the name unchanged from download.
# Handles full firmwares and also compressed firmware patches.
def get_local_fwfile(fwfilename):
    # Load the firmware file
    assert os.path.exists(fwfilename) and os.path.isfile(
            fwfilename), f'Compressed firmware file not found: {fwfilename}'

    # Read the fw file
    fwcmp = fwtools.read(fwfilename)

    # Use fwtools to parse the filename and deduce whether this is
    # a full firmware file or a firmware delta/patch.
    fwtype, fwinfo, fwinfo2 = fwtools.parse_compressed_filename(fwfilename)
    assert (fwtype == fwtools.FWFILE_TYPE_PATCH) == (fwinfo2 is not None)

    return fwinfo.fwsize, fwinfo2.fwsize if fwinfo2 else None, fwcmp


# Takes the compressed firmware data to upload, the expected length of the
# final (uncompressed) firmware, the length of the uncompressed diff/patch
# (if this is a patch to apply to the current running firmware), and whether
# to apply the test mnemonic rather than using normal pinserver authentication.
def ota(jade, verinfo, fwcompressed, fwlength, patchlen=None):
    logger.info(f'Running OTA on: {verinfo}')
    chunksize = int(verinfo['JADE_OTA_MAX_CHUNK'])
    assert chunksize > 0

    if verinfo['JADE_STATE'] not in ['READY', 'UNINIT']:
        # The network to use is deduced from the version-info
        print('Please ensure Jade is unlocked')
        network = 'testnet' if verinfo.get('JADE_NETWORKS') == 'TEST' else 'mainnet'
        while not jade.auth_user(network, epoch=int(time.time())):
            print('Please try again')

    start_time = time.time()
    last_time = start_time
    last_written = 0

    # Callback to log progress
    def _log_progress(written, compressed_size):
        nonlocal last_time
        nonlocal last_written

        current_time = time.time()
        secs = current_time - last_time
        total_secs = current_time - start_time
        bytes_ = written - last_written
        last_rate = bytes_ / secs
        avg_rate = written / total_secs
        progress = (written / compressed_size) * 100
        secs_remaining = (compressed_size - written) / avg_rate
        template = '{0:.2f} b/s - progress {1:.2f}% - {2:.2f} seconds left'
        print(template.format(last_rate, progress, secs_remaining))
        print('Written {0}b in {1:.2f}s'.format(written, total_secs))

        last_time = current_time
        last_written = written

    print('Please approve the firmware update on the Jade device')
    try:
        result = jade.ota_update(fwcompressed, fwlength, chunksize,
                                 patchlen=patchlen, cb=_log_progress)
        assert result is True
        print(f'Total OTA time: {time.time() - start_time}s')
    except JadeError as err:
        logger.error(f'OTA failed or abandoned: {err}')
        print('OTA incomplete')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--serialport',
                        action='store',
                        dest='serialport',
                        help='Serial port or device',
                        default=None)

    srcgrp = parser.add_mutually_exclusive_group()
    srcgrp.add_argument('--release',
                        action='store',
                        dest='release',
                        choices=['previous', 'stable', 'beta'],
                        help='Use previous or beta versions, if available.  Defaults to stable.',
                        default=None)

    srcgrp.add_argument('--fwfile',
                        action='store',
                        dest='fwfile',
                        help='Local (previously downloaded) file to OTA - full or patch',
                        default=None)

    parser.add_argument('--log',
                        action='store',
                        dest='loglevel',
                        help='Jade logging level',
                        choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'],
                        default='ERROR')

    args = parser.parse_args()
    jadehandler.setLevel(getattr(logging, args.loglevel))
    logger.debug(f'args: {args}')

    # Connect to Jade over serial
    with JadeAPI.create_serial(device=args.serialport) as jade:
        # Get the version info
        verinfo = jade.get_version_info()

    # Get the file to OTA
    if args.fwfile:
        # Can't check that local file is appropriate for connected hw
        # OTA should reject/fail if not appropriate.
        # File must have the name unchanged from download.
        fwlen, patchlen, fwcmp = get_local_fwfile(args.fwfile)
    else:
        # File download should only offer appropriate fw
        # OTA should reject/fail if not appropriate.
        release = args.release or 'stable'  # defaults to latest/stable
        fwlen, patchlen, fwcmp = download_file(verinfo, release)

    if fwcmp is None:
        print('No firmware available')
        sys.exit(2)

    print(f'Got fw {"patch" if patchlen else "file"} of length {len(fwcmp)} '
          f'with expected uncompressed final fw length {fwlen}')

    # OTA file to connected Jade hw
    upload = input('Upload fw to connected Jade [Y/n]').strip()
    if upload == 'y' or upload == 'Y' or upload == '':
        logger.info('Jade OTA over serial')
        with JadeAPI.create_serial(device=args.serialport) as jade:
            ota(jade, verinfo, fwcmp, fwlen, patchlen)
    else:
        logger.info('Skipping upload')
