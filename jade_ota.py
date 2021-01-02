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

FWSERVER_CERTIFICATE_FILE = './jade_services_certificate.pem'

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
    logger.info('Starting bt-agent with passkey file: {}'.format(passkey_file))
    command = ["/usr/bin/bt-agent", "-c", "DisplayYesNo", "-p", passkey_file]
    btagent = subprocess.Popen(command,
                               shell=False,
                               stdout=subprocess.DEVNULL)
    logger.info('Started bt-agent with process id: {}'.format(btagent.pid))
    return btagent


def kill_agent(btagent):
    command = 'kill -HUP {}'.format(btagent.pid)
    subprocess.run(command,
                   shell=True,
                   stdout=subprocess.DEVNULL)
    logger.info('Killed bt-agent {}'.format(btagent.pid))


# Takes the compressed firmware data, and the expected length of the
# uncompressed firmware image.
def ota(jade, fwcompressed, fwlength, skip_mnemonic=False):
    info = jade.get_version_info()
    logger.info("Running OTA on: {}".format(info))
    has_radio = info['JADE_CONFIG'] == 'BLE'
    id = info['EFUSEMAC'][6:]

    chunksize = int(info['JADE_OTA_MAX_CHUNK'])
    assert chunksize > 0

    # Can set the mnemonic to ensure OTA is allowed
    if not skip_mnemonic:
        ret = jade.set_mnemonic(TEST_MNEMONIC)
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
        template = "{0:.2f} b/s - progress {1:.2f}% - {2:.2f} seconds left"
        logger.info(template.format(last_rate, progress, secs_remaining))
        logger.info("Written {0}b in {1:.2f}s".format(written, total_secs))

        last_time = current_time
        last_written = written

    result = jade.ota_update(fwcompressed, fwlength, chunksize, _log_progress)
    assert result is True

    logger.info("Total ota time in secs: {}".format(time.time() - start_time))

    # Pause to allow for post-ota reboot
    time.sleep(4)

    # Return whether we have ble and the id of the jade
    return has_radio, id


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    sergrp = parser.add_mutually_exclusive_group()
    sergrp.add_argument("--skipserial",
                        action="store_true",
                        dest="skipserial",
                        help="Skip testing over serial connection",
                        default=False)
    sergrp.add_argument("--serialport",
                        action="store",
                        dest="serialport",
                        help="Serial port or device",
                        default=DEFAULT_SERIAL_DEVICE)

    blegrp = parser.add_mutually_exclusive_group()
    blegrp.add_argument("--skipble",
                        action="store_true",
                        dest="skipble",
                        help="Skip testing over BLE connection",
                        default=False)
    blegrp.add_argument("--bleid",
                        action="store",
                        dest="bleid",
                        help="BLE device serial number or id",
                        default=None)

    agtgrp = parser.add_mutually_exclusive_group()
    agtgrp.add_argument("--noagent",
                        action="store_true",
                        dest="noagent",
                        help="Do not run the BLE passkey agent",
                        default=False)
    agtgrp.add_argument("--agentkeyfile",
                        action="store",
                        dest="agentkeyfile",
                        help="Use the specified BLE passkey agent key file",
                        default=BLE_TEST_PASSKEYFILE)

    parser.add_argument("--fwfile",
                        action="store",
                        dest="fwfilename",
                        help="Uncompressed firmware file to OTA",
                        default=DEFAULT_FIRMWARE_FILE)
    agtgrp.add_argument("--compress",
                        action="store_true",
                        dest="compress",
                        help="Create compressed firmware file if not present",
                        default=False)
    agtgrp.add_argument("--download-firmware",
                        action="store_true",
                        dest="download_firmware",
                        help="Down the firmware from the firmware server",
                        default=False)
    parser.add_argument("--skipmnemonic",
                        action="store_true",
                        dest="skipmnemonic",
                        help="Skip setting test mnemonic",
                        default=False)
    parser.add_argument("--log",
                        action="store",
                        dest="loglevel",
                        help="Jade logging level",
                        choices=["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"],
                        default="INFO")

    args = parser.parse_args()
    jadehandler.setLevel(getattr(logging, args.loglevel))
    logger.debug('args: {}'.format(args))
    manage_agents = args.agentkeyfile and not args.skipble and not args.noagent

    if args.skipserial and args.skipble:
        logger.error("Can only skip one of Serial or BLE test, not both!")
        os.exit(1)

    if args.bleid and not args.skipserial:
        logger.error("Can only supply ble-id when skipping serial tests")
        os.exit(1)

    if args.download_firmware:
        import greenaddress as gdk
        import base64
        import json

        # We need to pass the relevant root certificate
        with open(FWSERVER_CERTIFICATE_FILE, "r") as cf:
            root_cert = cf.read()

        gdk.init({})
        session = gdk.Session({'name': 'mainnet'})

        # GET the LATEST file from the firmware server which lists the
        # available firmwares
        params = {'method': 'GET',
                  'root_certificates': [root_cert],
                  'urls': ['https://jadefw.blockstream.com/bin/LATEST']}
        latest = gdk.http_request(session.session_obj, json.dumps(params))
        latest = json.loads(latest)
        fwnames = latest['body'].split()

        # User selects firmware from list of available
        if len(fwnames) > 1:
            print("Available firmwares")
            for i, fwname in enumerate(fwnames):
                print("{}) {}".format(i, fwname))
            fwname = fwnames[int(input("Select firmware: "))]
        else:
            fwname = firmwares[0]

        # Info encoded in the filename
        fwversion, fwtype, fwlen, suffix = fwname.split('_')
        assert suffix == 'fw.bin'
        logger.info("firmware version: {}".format(fwversion))
        logger.info("firmware type: {}".format(fwtype))
        logger.info("firmware length: {}".format(fwlen))
        fwlen = int(fwlen)

        # GET the selected firmware from the server in base64 encoding
        firmware_url = 'https://jadefw.blockstream.com/bin/{}'.format(fwname)
        params['urls'] = [firmware_url]
        params['accept'] = 'base64'
        logger.info("Downloading firmware {} using gdk".format(firmware_url))

        fw_json = gdk.http_request(session.session_obj, json.dumps(params))
        fw_json = json.loads(fw_json)
        logger.debug("fw_json: {}".format(fw_json))
        fw_b64 = fw_json['body']
        fwcmp = base64.b64decode(fw_b64)
        logger.info("Downloaded {} byte firmware".format(len(fwcmp)))
    else:
        # Load the uncompressed firmware file
        assert os.path.exists(args.fwfilename) and os.path.isfile(
            args.fwfilename), "Uncompressed firmware file '{}' not found."

        logger.info("Reading file: {}".format(args.fwfilename))
        with open(args.fwfilename, 'rb') as fwfile:
            firmware = fwfile.read()
        fwlen = len(firmware)

        # Use fwprep to deduce the filename used for the compressed firmware
        cmpfilename = fwprep.get_compressed_filepath(firmware, COMP_FW_DIR)
        expected_suffix = '_' + str(fwlen) + '_fw.bin'
        assert cmpfilename.endswith(expected_suffix)

        # If compressed file doesn't exist, and we are passed the --compresss
        # option, we can create the compressed file on-the-fly.
        if args.compress and not os.path.exists(cmpfilename):
            logger.info("Creating compressed firmware file")
            fwprep.create_compressed_firmware_image(firmware, COMP_FW_DIR)

        assert os.path.exists(cmpfilename) and os.path.isfile(cmpfilename), \
            "Compressed firmware file '{}' not found.".format(cmpfilename)

        logger.info("Reading file: {}".format(cmpfilename))
        with open(cmpfilename, 'rb') as cmpfile:
            fwcmp = cmpfile.read()

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
            logger.info('Jade OTA over serial {}'.format(args.serialport))
            with JadeAPI.create_serial(device=args.serialport) as jade:
                has_radio, bleid = ota(jade, fwcmp, fwlen, args.skipmnemonic)

        if not args.skipble:
            if has_radio:
                logger.info('Jade OTA over BLE {}'.format(bleid))
                with JadeAPI.create_ble(serial_number=bleid) as jade:
                    ota(jade, fwcmp, fwlen, args.skipmnemonic)
            else:
                msg = "Skipping BLE tests - not enabled on the hardware"
                logger.warning(msg)

    finally:
        if btagent:
            kill_agent(btagent)
