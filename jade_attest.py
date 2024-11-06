#!/usr/bin/env python

import os
import sys
import logging
import argparse
from jadepy import JadeAPI

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

# Enable jade logging
jadehandler = logging.StreamHandler()

logger = logging.getLogger('jadepy.jade')
logger.setLevel(logging.INFO)
logger.addHandler(jadehandler)

device_logger = logging.getLogger('jadepy.jade-device')
device_logger.setLevel(logging.INFO)
device_logger.addHandler(jadehandler)

ESP32S3_CHIP_BOARDS = ['JADE_V2', 'TTGO_TDISPLAYS3', 'TTGO_TDISPLAYS3PROCAMERA', 'M5CORES3']

RSA_KEY_LEN = 4096
RSA_EXPONENT = 65537


def get_pem(key):
    # openssl and mbedtls both add a trailing '\n' which this lib does
    # not appear to do, so add it here for consistency
    return key.export_key() + b'\n'


def parse_pem(filename):
    # Load key from PEM file
    logger.info('Importing key from PEM file')
    with open(filename, 'rb') as f:
        return RSA.import_key(f.read())


def verify(challenge, attest_rslt, ext_pubkey, private_key=None):
    # Verify both the attestation signature over the (hashed) challenge with the returned
    # pubkey, and the external signature over the (hashed) returned pubkey serialisation
    # with the provided external pubkey.
    # Also, if the RSA private key is known, check the attestation signature returned
    # matches a locally made signature.
    logger.info('Verifying challenge signature')
    public_key = RSA.import_key(attest_rslt['pubkey_pem'])
    challenge_hash = SHA256.new(challenge)
    pkcs1_15.new(public_key).verify(challenge_hash, attest_rslt['signature'])

    logger.info('Verifying returned pubkey against external signature')
    pubkey_hash = SHA256.new(attest_rslt['pubkey_pem'].encode('ascii'))
    pkcs1_15.new(ext_pubkey).verify(pubkey_hash, attest_rslt['ext_signature'])

    if private_key:
        logger.info('Checking RSA signature matches local signing')
        signature = pkcs1_15.new(private_key).sign(challenge_hash)
        assert attest_rslt['signature'] == signature


def attestation_initialise(jade, args):
    # Initialise attestation parameters
    ext_privkey = parse_pem(args.external_key_pem)
    if not ext_privkey.has_private():
        logger.error('External private key required')
        sys.exit(3)

    if args.initialise is True:
        # Generate new RSA private key
        logger.info(f'Generating new RSA {RSA_KEY_LEN} private key')
        private_key = RSA.generate(RSA_KEY_LEN, e=RSA_EXPONENT)
    else:
        # Load private key from PEM file
        private_key = parse_pem(args.initialise)

        if not private_key.has_private():
            logger.error('Signer private key required')
            sys.exit(4)
        if private_key.size_in_bits() != RSA_KEY_LEN:
            logger.error(f'Unexpected signer key size {private_key.size_in_bits()} ' +
                         '(expecting {RSA_KEY_LEN})')
            sys.exit(5)

    public_key_pem = get_pem(private_key.publickey())
    pubkey_pem_hash = SHA256.new(public_key_pem)
    ext_signature = pkcs1_15.new(ext_privkey).sign(pubkey_pem_hash)

    # Push entropy to jade
    assert jade.add_entropy(os.urandom(128))

    # Initialise attestation params (low-level api only)
    params = {'privkey_pem': get_pem(private_key).decode('ascii'),
              'ext_pubkey_pem': get_pem(ext_privkey.publickey()).decode('ascii'),
              'ext_signature': ext_signature}
    rslt = jade._jadeRpc('register_attestation', params)

    # Initialisation also signs ext_signature as if it were an attestation
    # challenge, so we can verify all working as expected.
    assert rslt['ext_signature'] == ext_signature
    assert rslt['pubkey_pem'] == public_key_pem.decode('ascii')
    verify(ext_signature, rslt, ext_privkey.publickey(), private_key)


def attestation_verify(jade, args):
    # Verify attestation
    ext_pubkey = parse_pem(args.external_key_pem)

    # Call Jade to sign an attestation challenge and verify result
    logger.info('Signing random challenge')
    challenge = os.urandom(32)
    rslt = jade.sign_attestation(challenge)

    logger.info('Verifying...')
    verify(challenge, rslt, ext_pubkey)

    print('Attestation signing verified')


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

    init = parser.add_mutually_exclusive_group()
    init.add_argument('--init-new',
                      action='store_true',
                      dest='initialise',
                      help='Initialise attestation params with a new RSA private key generated ' +
                           'locally and passed to Jade',
                      default=None)
    init.add_argument('--init-import',
                      action='store',
                      metavar="private_key_pem",
                      dest='initialise',
                      help='Initialise attestation params with an RSA private key imported from ' +
                           'given PEM file and passed to Jade',
                      default=None)

    parser.add_argument('--verify',
                        action='store_true',
                        dest='verify',
                        help='Verify attestation using a randomly generated challenge',
                        default=None)

    parser.add_argument('external_key_pem',
                        action='store',
                        help='Text file containing the verification authority PEM file.  Must ' +
                             'be private key when initialising, can be pubkey if only verifying.',
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

    # Must do something
    if not args.initialise and not args.verify:
        print('Must pass either initialise and/or verify action')
        sys.exit(1)

    logger.info('Connecting...')
    if args.bleid:
        create_jade_fn = JadeAPI.create_ble
        kwargs = {'serial_number': args.bleid}
    else:
        create_jade_fn = JadeAPI.create_serial
        kwargs = {'device': args.serialport, 'timeout': 120 if args.verify else 10}

    with create_jade_fn(**kwargs) as jade:
        verinfo = jade.get_version_info()
        print('Connected: {}'.format(verinfo))

        if verinfo['BOARD_TYPE'] not in ESP32S3_CHIP_BOARDS:
            print('Attestation only available on esp32s3 chipset')
            sys.exit(2)
        if verinfo['JADE_FEATURES'] != 'SB':
            print('Attestation only available on secure-boot devices')
            sys.exit(3)

        if args.initialise:
            attestation_initialise(jade, args)

        if args.verify:
            attestation_verify(jade, args)
