#!/usr/bin/env python

import os
import sys
import time
import json
import hashlib
import logging
import argparse
import subprocess

from jadepy import JadeAPI
from tools import fwtools

TEST_MNEMONIC = 'fish inner face ginger orchard permit useful method fence \
kidney chuckle party favorite sunset draw limb science crane oval letter \
slot invite sadness banana'

BLE_TEST_PASSKEYFILE = 'ble_test_passkey.txt'

FWSERVER_URL_ROOT = 'https://jadefw.blockstream.com/bin'
FWSERVER_INDEX_FILE = 'index.json'

DEFAULT_FIRMWARE_FILE = 'build/jade.bin'
COMP_FW_DIR = 'build'

# Enable jade debug logging
jadehandler = logging.StreamHandler()

logger = logging.getLogger('jadepy.jade')
logger.setLevel(logging.DEBUG)
logger.addHandler(jadehandler)

device_logger = logging.getLogger('jadepy.jade-device')
device_logger.setLevel(logging.DEBUG)
device_logger.addHandler(jadehandler)


# Manage bt agent
def start_agent(passkey_file):
    logger.info(f'Starting bt-agent with passkey file: {passkey_file}')
    command = ['/usr/bin/bt-agent', '-c', 'DisplayYesNo', '-p', passkey_file]
    btagent = subprocess.Popen(command,
                               shell=False,
                               stdout=subprocess.DEVNULL)
    logger.info(f'Started bt-agent with process id: {btagent.pid}')
    return btagent


def kill_agent(btagent):
    command = f'kill -HUP {btagent.pid}'
    subprocess.run(command,
                   shell=True,
                   stdout=subprocess.DEVNULL)
    logger.info(f'Killed bt-agent {btagent.pid}')


# Parse the index file and select firmware to download
def get_fw_metadata(release_data):
    # Select firmware from list of available
    def _full_fw_label(fw):
        return f'{fw["version"]} - {fw["config"]}'

    def _delta_fw_label(fw, width):
        return _full_fw_label(fw).ljust(width) + f'FROM  {fw["from_version"]} - {fw["from_config"]}'

    print('Full firmwares')
    fullfws = release_data.get('full', [])
    for i, label in enumerate((_full_fw_label(fw) for fw in fullfws), 1):  # 1 based index
        print(f'{i})'.ljust(3), label)
    print('-')

    print('Delta patches')
    deltas = release_data.get('delta', [])
    just = max(len(name) for name in map(_full_fw_label, deltas)) + 2 if deltas else 0
    for i, label in enumerate((_delta_fw_label(fw, just) for fw in deltas), i + 1):  # continue
        print(f'{i})'.ljust(4), label)
    print('-')

    selectedfw = int(input('Select firmware: '))
    assert selectedfw > 0 and selectedfw <= i, f'Selected firmware not valid: {selectedfw}'
    selectedfw -= 1  # zero-based index

    numfullfws = len(fullfws)
    selectedfw = fullfws[selectedfw] if selectedfw < numfullfws else deltas[selectedfw - numfullfws]
    return selectedfw


# Download compressed firmware file from Firmware Server using 'requests'
def download_file(hw_target, write_compressed, release):
    import requests

    # GET the index file from the firmware server which lists the
    # available firmwares
    url = f'{FWSERVER_URL_ROOT}/{hw_target}/{FWSERVER_INDEX_FILE}'
    logger.info(f'Downloading firmware index file {url}')
    rslt = requests.get(url)
    assert rslt.status_code == 200, f'Cannot download index file {url}: {rslt.status_code}'

    # Get the filename of the firmware to download
    release_data = json.loads(rslt.text).get(release)
    if not release_data:
        return None, None, None

    fwdata = get_fw_metadata(release_data)
    fwname = fwdata['filename']
    fwhash = fwdata.get('fwhash')
    cmphash = fwdata.get('cmphash')

    # GET the selected firmware from the server
    url = f'{FWSERVER_URL_ROOT}/{hw_target}/{fwname}'
    logger.info(f'Downloading firmware {url}')
    rslt = requests.get(f'{FWSERVER_URL_ROOT}/{hw_target}/{fwname}')
    assert rslt.status_code == 200, f'Cannot download firmware file {url}: {rslt.status_code}'

    fwcmp = rslt.content
    logger.info(f'Downloaded {len(fwcmp)} byte firmware')

    # Check the downloaded file hash if available
    if cmphash:
        # Compute the sha256 hash of the downloaded file
        cmphasher = hashlib.sha256()
        cmphasher.update(fwcmp)
        assert cmphasher.digest() == bytes.fromhex(cmphash)
        logger.info(f'Downloaded file hash verified')

    # If passed --write-compressed we write a copy of the compressed file
    if write_compressed:
        cmpfilename = f'{COMP_FW_DIR}/{os.path.basename(fwname)}'
        fwtools.write(fwcmp, cmpfilename)
        if fwhash:
            fwtools.write(fwhash, cmpfilename + ".hash", text=True)

    # Return
    return fwdata['fwsize'], fwdata.get('patch_size'), fwhash, fwcmp


# Download compressed firmware file from Firmware Server using GDK
def download_file_gdk(hw_target, write_compressed, release):
    import greenaddress as gdk
    import base64

    gdk.init({})
    session = gdk.Session({'name': 'mainnet'})

    # GET the index file from the firmware server which lists the
    # available firmwares
    url = f'{FWSERVER_URL_ROOT}/{hw_target}/{FWSERVER_INDEX_FILE}'
    logger.info(f'Downloading firmware index file {url} using gdk')
    params = {'method': 'GET', 'urls': [url]}
    rslt = gdk.http_request(session.session_obj, json.dumps(params))
    rslt = json.loads(rslt)
    assert 'body' in rslt, f'Cannot download index file {url}: {rslt.get("error")}'

    # Get the filename of the firmware to download
    release_data = json.loads(rslt['body']).get(release)
    if not release_data:
        return None, None, None

    fwdata = get_fw_metadata(release_data)
    fwname = fwdata['filename']
    fwhash = fwdata.get('fwhash')

    # GET the selected firmware from the server in base64 encoding
    url = f'{FWSERVER_URL_ROOT}/{hw_target}/{fwname}'
    logger.info(f'Downloading firmware {url} using gdk')
    params = {'method': 'GET', 'urls': [url], 'accept': 'base64'}
    rslt = gdk.http_request(session.session_obj, json.dumps(params))
    rslt = json.loads(rslt)
    assert 'body' in rslt, f'Cannot download firmware file {url}: {rslt.get("error")}'

    fw_b64 = rslt['body']
    fwcmp = base64.b64decode(fw_b64)
    logger.info(f'Downloaded {len(fwcmp)} byte firmware')

    # If passed --write-compressed we write a copy of the compressed file
    if write_compressed:
        cmpfilename = f'{COMP_FW_DIR}/{os.path.basename(fwname)}'
        fwtools.write(fwcmp, cmpfilename)
        if fwhash:
            fwtools.write(fwhash, cmpfilename + ".hash", text=True)

    # Return
    return fwdata['fwsize'], fwdata.get('patch_size'), fwhash, fwcmp


# Use a local uncompressed full firmware file - can deduce the compressed firmware
# filename to use, and can write a copy of that file if requested.
# NOTE: only handles full firmwares - does not support patches (which are always compressed)
def get_local_uncompressed_fwfile(fwfilename, write_compressed):
    # Load the uncompressed firmware file
    assert os.path.exists(fwfilename) and os.path.isfile(
            fwfilename), f'Uncompressed firmware file not found: {fwfilename}'

    # Read the fw file and get the hash
    firmware = fwtools.read(fwfilename)
    fwlen = len(firmware)
    fwhash = hashlib.sha256(firmware).hexdigest()

    # Compress the firmware for upload
    fwcmp = fwtools.compress(firmware)

    # Use fwtools to deduce the filename used for the compressed firmware
    cmpfilename = fwtools.get_firmware_compressed_filepath(firmware, COMP_FW_DIR)
    fwtype, fwinfo, fwinfo2 = fwtools.parse_compressed_filename(cmpfilename)
    assert fwtype == fwtools.FWFILE_TYPE_FULL and fwinfo2 is None and fwinfo.fwsize == fwlen

    # If passed --write-compressed we create the compressed file now
    if write_compressed:
        logger.info('Writing compressed firmware file')
        fwtools.write(fwcmp, cmpfilename)

    return fwlen, None, fwhash, fwcmp


# Use a local firmware file - the compressed firmware file.
# Handles full firmwares and also compressed firmware patches.
def get_local_compressed_fwfile(fwfilename):
    # Load the uncompressed firmware file
    assert os.path.exists(fwfilename) and os.path.isfile(
            fwfilename), f'Compressed firmware file not found: {fwfilename}'

    # Read the fw file
    fwcmp = fwtools.read(fwfilename)
    fwhash = None
    try:
        fwhash = fwtools.read(fwfilename + ".hash", text=True)
    except Exception as e:
        logger.warning('Hash file no present or not valid')

    # Use fwtools to parse the filename and deduce whether this is
    # a full firmware file or a firmware delta/patch.
    fwtype, fwinfo, fwinfo2 = fwtools.parse_compressed_filename(fwfilename)
    assert (fwtype == fwtools.FWFILE_TYPE_PATCH) == (fwinfo2 is not None)

    return fwinfo.fwsize, fwinfo2.fwsize if fwinfo2 else None, fwhash, fwcmp


# Returns whether we have ble and the id of the jade
def get_bleid(jade):
    info = jade.get_version_info()
    has_radio = info['JADE_CONFIG'] == 'BLE'
    id = info['EFUSEMAC'][6:]
    return has_radio, id


# Takes the compressed firmware data to upload, the expected length of the
# final (uncompressed) firmware, the length of the uncompressed diff/patch
# (if this is a patch to apply to the current running firmware), and whether
# to apply the test mnemonic rather than using normal pinserver authentication.
def ota(jade, fwcompressed, fwlength, fwhash, patchlen=None, pushmnemonic=False):
    info = jade.get_version_info()
    logger.info(f'Running OTA on: {info}')
    has_pin = info['JADE_HAS_PIN']
    has_radio = info['JADE_CONFIG'] == 'BLE'
    id = info['EFUSEMAC'][6:]

    chunksize = int(info['JADE_OTA_MAX_CHUNK'])
    assert chunksize > 0

    # Can set the mnemonic in debug, to ensure OTA is allowed
    if pushmnemonic:
        ret = jade.set_mnemonic(TEST_MNEMONIC)
        assert ret is True
    elif has_pin:
        # The network to use is deduced from the version-info
        network = 'testnet' if info.get('JADE_NETWORKS') == 'TEST' else 'mainnet'
        ret = jade.auth_user(network)
        assert ret is True

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
        logger.info(template.format(last_rate, progress, secs_remaining))
        logger.info('Written {0}b in {1:.2f}s'.format(written, total_secs))

        last_time = current_time
        last_written = written

    result = jade.ota_update(fwcompressed, fwlength, chunksize, fwhash,
                             patchlen=patchlen, cb=_log_progress)
    assert result is True

    logger.info(f'Total ota time in secs: {time.time() - start_time}')

    # Pause to allow for post-ota reboot
    time.sleep(5)

    # Return whether we have ble and the id of the jade
    return has_radio, id


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--skipserial',
                        action='store_true',
                        dest='skipserial',
                        help='Skip testing over serial connection',
                        default=False)
    parser.add_argument('--serialport',
                        action='store',
                        dest='serialport',
                        help='Serial port or device',
                        default=None)

    blegrp = parser.add_mutually_exclusive_group()
    blegrp.add_argument('--skipble',
                        action='store_true',
                        dest='skipble',
                        help='Skip testing over BLE connection',
                        default=False)
    blegrp.add_argument('--bleidfromserial',
                        action='store_true',
                        dest='bleidfromserial',
                        help='Fetch BLE id from serial connection (implied if not --skipserial)',
                        default=False)
    blegrp.add_argument('--bleid',
                        action='store',
                        dest='bleid',
                        help='BLE device serial number or id',
                        default=None)

    agtgrp = parser.add_mutually_exclusive_group()
    agtgrp.add_argument('--noagent',
                        action='store_true',
                        dest='noagent',
                        help='Do not run the BLE passkey agent',
                        default=False)
    agtgrp.add_argument('--agentkeyfile',
                        action='store',
                        dest='agentkeyfile',
                        help='Use the specified BLE passkey agent key file',
                        default=BLE_TEST_PASSKEYFILE)

    srcgrp = parser.add_mutually_exclusive_group()
    srcgrp.add_argument('--download-firmware',
                        action='store_true',
                        dest='downloadfw',
                        help='Download the firmware from the firmware server',
                        default=False)
    srcgrp.add_argument('--download-firmware-gdk',
                        action='store_true',
                        dest='downloadgdk',
                        help='Download the firmware from the firmware server using gdk',
                        default=False)
    srcgrp.add_argument('--fwfile-uncompressed',
                        action='store',
                        dest='fwfile_uncompressed',
                        help='Uncompressed local file to OTA - full fw only',
                        default=DEFAULT_FIRMWARE_FILE)
    srcgrp.add_argument('--fwfile',
                        action='store',
                        dest='fwfile',
                        help='Compressed local file to OTA - full or patch',
                        default=None)

    # These only apply to firmware downloading
    parser.add_argument('--hw-target',
                        action='store',
                        dest='hwtarget',
                        help='Hardware target for downloading firmware.  Defaults to jade',
                        choices=['jade', 'jadedev', 'jade1.1', 'jade1.1dev'],
                        default=None)
    parser.add_argument('--release',
                        action='store',
                        dest='release',
                        choices=['previous', 'stable', 'beta'],
                        help='Use previous or beta versions, if available.  Defaults to stable.',
                        default=None)

    # Generic
    parser.add_argument('--write-compressed',
                        action='store_true',
                        dest='writecompressed',
                        help='Create/write copy of compressed firmware file',
                        default=False)
    parser.add_argument('--push-mnemonic',
                        action='store_true',
                        dest='pushmnemonic',
                        help='Sets a test mnemonic - only works with debug build of Jade',
                        default=False)
    parser.add_argument('--log',
                        action='store',
                        dest='loglevel',
                        help='Jade logging level',
                        choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'],
                        default='INFO')

    args = parser.parse_args()
    jadehandler.setLevel(getattr(logging, args.loglevel))
    logger.debug(f'args: {args}')
    manage_agents = args.agentkeyfile and not args.skipble and not args.noagent
    downloading = args.downloadfw or args.downloadgdk

    if args.skipserial and args.skipble:
        logger.warning('The fw file will be downloaded/verified but the actual OTA will be skipped')

    if args.bleid and not args.skipserial:
        logger.error('Can only supply ble-id when skipping serial tests')
        sys.exit(1)

    if args.fwfile and args.writecompressed:
        logger.error('Cannot write compressed fw file when reading from compressed fw file')
        sys.exit(1)

    if args.release and not downloading:
        logger.error('Can only specify release when downloading fw from server')
        sys.exit(1)

    if args.hwtarget and not downloading:
        logger.error('Can only supply hardware target when downloading fw from server')
        sys.exit(1)

    if downloading and not args.hwtarget:
        args.hwtarget = 'jade'   # default to prod jade

    if downloading and not args.release:
        args.release = 'stable'  # default to latest/stable

    # Create target dir if not present
    if args.writecompressed and not os.path.isdir(COMP_FW_DIR):
        os.mkdir(COMP_FW_DIR)

    # Get the file to OTA
    if args.downloadfw:
        fwlen, patchlen, fwhash, fwcmp = download_file(args.hwtarget, args.writecompressed,
                                                       args.release)
    elif args.downloadgdk:
        fwlen, patchlen, fwhash, fwcmp = download_file_gdk(args.hwtarget, args.writecompressed,
                                                           args.release)
    elif args.fwfile:
        assert not args.writecompressed
        fwlen, patchlen, fwhash, fwcmp = get_local_compressed_fwfile(args.fwfile)
    else:
        # Default case, as 'uncompressed fw file' has a default value if not passed explicitly
        fwlen, patchlen, fwhash, fwcmp = get_local_uncompressed_fwfile(args.fwfile_uncompressed,
                                                                       args.writecompressed)

    if fwcmp is None:
        logger.error('No firmware available')
        sys.exit(2)

    logger.info(f'Got fw {"patch" if patchlen else "file"} of length {len(fwcmp)} '
                f'with expected uncompressed final fw length {fwlen}')

    if fwhash is not None:
        logger.info(f'Final fw hash: {fwhash}')
        fwhash = bytes.fromhex(fwhash)

    # If ble, start the agent to supply the required passkey for authentication
    # and encryption - don't bother if not.
    # Note: passkey in the agent passkey file must match the fixed test passkey
    #       in jade source if we want the connection to succeed.
    btagent = None
    if manage_agents:
        btagent = start_agent(args.agentkeyfile)

    try:
        has_radio = True
        bleid = args.bleid

        if not args.skipserial:
            logger.info(f'Jade OTA over serial')
            with JadeAPI.create_serial(device=args.serialport) as jade:
                has_radio, bleid = ota(jade, fwcmp, fwlen, fwhash, patchlen, args.pushmnemonic)

        if not args.skipble:
            if has_radio and bleid is None and args.bleidfromserial:
                logger.info(f'Jade OTA getting bleid via serial connection')
                with JadeAPI.create_serial(device=args.serialport) as jade:
                    has_radio, bleid = get_bleid(jade)

            if has_radio:
                logger.info(f'Jade OTA over BLE {bleid}')
                with JadeAPI.create_ble(serial_number=bleid) as jade:
                    ota(jade, fwcmp, fwlen, fwhash, patchlen, args.pushmnemonic)
            else:
                msg = 'Skipping BLE tests - not enabled on the hardware'
                logger.warning(msg)

    finally:
        if btagent:
            kill_agent(btagent)
