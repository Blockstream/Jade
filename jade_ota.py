import os
import sys
import time
import logging
import argparse
import subprocess

from jadepy import JadeAPI
import fwprep

TEST_MNEMONIC = 'fish inner face ginger orchard permit useful method fence \
kidney chuckle party favorite sunset draw limb science crane oval letter \
slot invite sadness banana'

DEFAULT_SERIAL_DEVICE = '/dev/ttyUSB0'
BLE_TEST_PASSKEYFILE = 'ble_test_passkey.txt'

FWSERVER_URL_ROOT = 'https://jadefw.blockstream.com/bin'

DEFAULT_FIRMWARE_FILE = 'build/jade.bin'
COMP_FW_DIR = 'build'

# Enable jade debug logging
jadehandler = logging.StreamHandler()

logger = logging.getLogger('jade')
logger.setLevel(logging.DEBUG)
logger.addHandler(jadehandler)

device_logger = logging.getLogger('jade-device')
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


# Parse the latest file and select firmware to download
def get_fw_filename(fwlatest, selectfw):
    # Select firmware from list of available
    fwnames = fwlatest.split()
    print("Available firmwares")
    for i, fwname in enumerate(fwnames):
        print(f'{i}) {fwname}')

    if selectfw is None:
        selectfw = int(input('Select firmware: '))

    assert selectfw < len(fwnames), f'Selected firmware not valid: {selectfw}'
    return fwnames[selectfw]


# Parse a fw filename and get the expected uncompressed length
def get_expected_fw_length(fwname):
    # Parse info encoded in the filename
    fwversion, fwtype, fwlen, suffix = fwname.split('_')
    assert suffix == 'fw.bin'
    logger.info(f'firmware version: {fwversion}')
    logger.info(f'firmware type: {fwtype}')
    logger.info(f'firmware length: {fwlen}')
    return int(fwlen)


# Write compressed fw file (eg. one we downloaded)
def write_cmpfwfile(fwname, fwcmpdata):
    cmpfilename = f'{COMP_FW_DIR}/{fwname}'
    logger.info(f'Writing compressed firmware file {cmpfilename}')
    with open(cmpfilename, 'wb') as fwfile:
        fw = fwfile.write(fwcmpdata)
    logger.info(f'Written file {cmpfilename}')


# Download firmware file from Firmware Server
def download_file(hw_target, write_compressed, index_file, auto_select_fw):
    import requests

    # GET the index file from the firmware server which lists the
    # available firmwares
    url = f'{FWSERVER_URL_ROOT}/{hw_target}/{index_file}'
    logger.info(f'Downloading firmware index file {url}')
    rslt = requests.get(url)
    assert rslt.status_code == 200, f'Cannot download index file {url}: {rslt.status_code}'

    # Get the filename of the firmware to download
    fwname = get_fw_filename(rslt.text, auto_select_fw)
    fwlen = get_expected_fw_length(fwname)

    # GET the selected firmware from the server
    url = f'{FWSERVER_URL_ROOT}/{hw_target}/{fwname}'
    logger.info(f'Downloading firmware {url}')
    rslt = requests.get(f'{FWSERVER_URL_ROOT}/{hw_target}/{fwname}')
    assert rslt.status_code == 200, f'Cannot download firmware file {url}: {rslt.status_code}'

    fwcmp = rslt.content
    logger.info(f'Downloaded {len(fwcmp)} byte firmware')

    # If passed --write-compressed we write a copy of the compressed file
    if write_compressed:
        write_cmpfwfile(fwname, fwcmp)

    # Return
    return fwcmp, fwlen


# Download firmware file from Firmware Server using GDK
def download_file_gdk(hw_target, write_compressed, index_file, auto_select_fw):
    import greenaddress as gdk
    import base64
    import json

    gdk.init({})
    session = gdk.Session({'name': 'mainnet'})

    # GET the index file from the firmware server which lists the
    # available firmwares
    url = f'{FWSERVER_URL_ROOT}/{hw_target}/{index_file}'
    logger.info(f'Downloading firmware index file {url} using gdk')
    params = {'method': 'GET', 'urls': [url]}
    rslt = gdk.http_request(session.session_obj, json.dumps(params))
    rslt = json.loads(rslt)
    assert 'body' in rslt, f'Cannot download index file {url}: {rslt.get("error")}'

    # Get the filename of the firmware to download
    fwname = get_fw_filename(rslt['body'], auto_select_fw)
    fwlen = get_expected_fw_length(fwname)

    # GET the selected firmware from the server in base64 encoding
    url = f'{FWSERVER_URL_ROOT}/{hw_target}/{fwname}'
    logger.info(f'Downloading firmware {url} using gdk')
    params = {'method': 'GET', 'urls': [url], 'accept': 'base64'}
    rslt = gdk.http_request(session.session_obj, json.dumps(params))
    rslt = json.loads(rslt)
    assert 'body' in rslt, f'Cannot download firmware file {url}: {rslt.get("error")}'

    fw_b64 = rslt['body']
    fwcmp = base64.b64decode(fw_b64)
    logger.info('Downloaded {len(fwcmp)} byte firmware')

    # If passed --write-compressed we write a copy of the compressed file
    if write_compressed:
        write_cmpfwfile(fwname, fwcmp)

    # Return
    return fwcmp, fwlen


# Use a local firmware file - uses the uncompressed firmware file and can
# either deduce the compressed firmware filename to use, or can create it.
def get_local_fwfile(fwfilename, write_compressed):
    # Load the uncompressed firmware file
    assert os.path.exists(fwfilename) and os.path.isfile(
            fwfilename), f'Uncompressed firmware file not found: {fwfilename}'

    logger.info(f'Reading file: {fwfilename}')
    with open(fwfilename, 'rb') as fwfile:
        firmware = fwfile.read()
    fwlen = len(firmware)

    # Use fwprep to deduce the filename used for the compressed firmware
    cmpfilename = fwprep.get_compressed_filepath(firmware, COMP_FW_DIR)
    expected_suffix = f'_{fwlen}_fw.bin'
    assert cmpfilename.endswith(expected_suffix)

    # If passed --write-compressed we create the compressed file now
    if write_compressed:
        logger.info('Writing compressed firmware file')
        fwprep.create_compressed_firmware_image(firmware, COMP_FW_DIR)

    assert os.path.exists(cmpfilename) and os.path.isfile(cmpfilename), \
        f'Compressed firmware file not found: {cmpfilename}'

    logger.info(f'Reading file: {cmpfilename}')
    with open(cmpfilename, 'rb') as cmpfile:
        fwcmp = cmpfile.read()

    return fwcmp, fwlen


# Takes the compressed firmware data, and the expected length of the
# uncompressed firmware image.
def ota(jade, fwcompressed, fwlength, pushmnemonic, authnetwork):
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
        ret = jade.auth_user(authnetwork)
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

    result = jade.ota_update(fwcompressed, fwlength, chunksize, _log_progress)
    assert result is True

    logger.info(f'Total ota time in secs: {time.time() - start_time}')

    # Pause to allow for post-ota reboot
    time.sleep(5)

    # Return whether we have ble and the id of the jade
    return has_radio, id


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    sergrp = parser.add_mutually_exclusive_group()
    sergrp.add_argument('--skipserial',
                        action='store_true',
                        dest='skipserial',
                        help='Skip testing over serial connection',
                        default=False)
    sergrp.add_argument('--serialport',
                        action='store',
                        dest='serialport',
                        help='Serial port or device',
                        default=DEFAULT_SERIAL_DEVICE)

    blegrp = parser.add_mutually_exclusive_group()
    blegrp.add_argument('--skipble',
                        action='store_true',
                        dest='skipble',
                        help='Skip testing over BLE connection',
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

    authgrp = parser.add_mutually_exclusive_group()
    authgrp.add_argument('--push-mnemonic',
                         action='store_true',
                         dest='pushmnemonic',
                         help='Sets a test mnemonic - only works with debug build of Jade',
                         default=False)
    authgrp.add_argument('--auth-network',
                         action='store',
                         dest='authnetwork',
                         help='Sets a network to use if unlocking Jade with PIN',
                         choices=['mainnet', 'liquid', 'testnet', 'localtest', 'localtest-liquid'],
                         default='mainnet')

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
    srcgrp.add_argument('--fwfile',
                        action='store',
                        dest='fwfilename',
                        help='Uncompressed local file to OTA',
                        default=DEFAULT_FIRMWARE_FILE)

    # These only apply to firmware downloading
    parser.add_argument('--hw-target',
                        action='store',
                        dest='hwtarget',
                        help='Hardware target for downloading firmware.  Defaults to jade',
                        choices=['jade', 'jadedev', 'jade1.1', 'jade1.1dev'],
                        default=None)
    parser.add_argument('--auto-select-fw',
                        action='store',
                        type=int,
                        dest='autoselectfw',
                        help='Index of firmware to download (skips interactive prompt)',
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
        logger.error('Can only skip one of Serial or BLE test, not both!')
        sys.exit(1)

    if args.bleid and not args.skipserial:
        logger.error('Can only supply ble-id when skipping serial tests')
        sys.exit(1)

    if args.autoselectfw and not downloading:
        logger.error('Can only provide auto-select index when downloading fw from server')
        sys.exit(1)

    if args.release and not downloading:
        logger.error('Can only specify release when downloading fw from server')
        sys.exit(1)

    if args.hwtarget and not downloading:
        logger.error('Can only supply hardware target when downloading fw from server')
        sys.exit(1)

    if downloading and not args.hwtarget:
        args.hwtarget = 'jade'  # default to prod jade

    if downloading:
        # default to stable versions
        indexfile = {'previous': 'PREVIOUS',
                     'beta': 'BETA'}.get(args.release, 'LATEST')

    # Get the file to OTA
    if args.downloadfw:
        fwcmp, fwlen = download_file(args.hwtarget, args.writecompressed,
                                     indexfile, args.autoselectfw)
    elif args.downloadgdk:
        fwcmp, fwlen = download_file_gdk(args.hwtarget, args.writecompressed,
                                         indexfile, args.autoselectfw)
    else:
        fwcmp, fwlen = get_local_fwfile(args.fwfilename, args.writecompressed)

    logger.info(f'Got fw file of length {len(fwcmp)} with expected uncompressed length {fwlen}')

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
            logger.info(f'Jade OTA over serial {args.serialport}')
            with JadeAPI.create_serial(device=args.serialport) as jade:
                has_radio, bleid = ota(jade, fwcmp, fwlen, args.pushmnemonic, args.authnetwork)

        if not args.skipble:
            if has_radio:
                logger.info(f'Jade OTA over BLE {bleid}')
                with JadeAPI.create_ble(serial_number=bleid) as jade:
                    ota(jade, fwcmp, fwlen, args.pushmnemonic, args.authnetwork)
            else:
                msg = 'Skipping BLE tests - not enabled on the hardware'
                logger.warning(msg)

    finally:
        if btagent:
            kill_agent(btagent)
