#!/usr/bin/env python

import sys
import logging
import argparse
from hashlib import sha256
from jadepy import JadeAPI

# Enable jade logging
jadehandler = logging.StreamHandler()

logger = logging.getLogger('jadepy.jade')
logger.setLevel(logging.INFO)
logger.addHandler(jadehandler)

device_logger = logging.getLogger('jadepy.jade-device')
device_logger.setLevel(logging.INFO)
device_logger.addHandler(jadehandler)


def update_pinserver(jade, args):

    # do any reset first/separately
    if args.reset_details or args.reset_certificate:
        jade.reset_pinserver(args.reset_details, args.reset_certificate)

    pubkey = None
    if args.pubkeyfile:
        with open(args.pubkeyfile, 'rb') as f:
            pubkey = f.read()
        print('Sending pubkey: ', pubkey.hex())

    certificate = None
    if args.certfile is not None:
        if args.certfile:
            with open(args.certfile, 'r') as f:
                certificate = f.read()
            hash = sha256(certificate.encode()).hexdigest()
            print('Sending certificate with hash:', hash)
        else:
            certificate = ''
            print('Sending no-certificate-required')

    # Do it!
    jade.set_pinserver(args.urlA, args.urlB, pubkey, certificate)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    conns = parser.add_mutually_exclusive_group()
    conns.add_argument('--serialport',
                       action='store',
                       dest='serialport',
                       help='Serial port or device - only pass if default not correct',
                       default=None)
    conns.add_argument('--bleid',
                       action='store',
                       dest='bleid',
                       help='BLE device serial number or id - only pass if connecting via BLE',
                       default=None)

    parser.add_argument('--reset-details',
                        action='store_true',
                        dest='reset_details',
                        help='Reset pinserver details to default',
                        default=False)
    parser.add_argument('--reset-certificate',
                        action='store_true',
                        dest='reset_certificate',
                        help='Reset pinserver certificate to default',
                        default=False)

    parser.add_argument('--set-url',
                        action='store',
                        dest='urlA',
                        help='URL for pinserver',
                        default=None)
    parser.add_argument('--set-url2',
                        action='store',
                        dest='urlB',
                        help='Second URL for pinserver',
                        default=None)

    parser.add_argument('--set-pubkey',
                        action='store',
                        dest='pubkeyfile',
                        help='Binary file containing the pinserver public key',
                        default=None)

    parser.add_argument('--set-certificate',
                        action='store',
                        dest='certfile',
                        help='Text .pem file for any pinserver TLS/URL root certificate'
                             ' - use empty if no certificate required',
                        default=None)

    parser.add_argument('--log',
                        action='store',
                        dest='loglevel',
                        help='Jade logging level',
                        choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'],
                        default='INFO')

    args = parser.parse_args()
    jadehandler.setLevel(getattr(logging, args.loglevel))
    logger.debug(f'args: {args}')

    # Cannot update 'second' url unless setting first url
    if args.urlA is None and args.urlB is not None:
        print("Cannot set second URL unless also setting first URL")
        sys.exit(1)

    print('Connecting...')
    if args.bleid:
        create_jade_fn = JadeAPI.create_ble
        kwargs = {'serial_number': args.bleid}
    else:
        create_jade_fn = JadeAPI.create_serial
        kwargs = {'device': args.serialport, 'timeout': 120}

    with create_jade_fn(**kwargs) as jade:
        print('Connected: {}'.format(jade.get_version_info()))
        update_pinserver(jade, args)
