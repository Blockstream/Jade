#!/usr/bin/env python

import os
import sys
import argparse
import hashlib
import logging
from jadepy import JadeAPI

TEST_MNEMONIC = 'fish inner face ginger orchard permit useful method fence \
kidney chuckle party favorite sunset draw limb science crane oval letter \
slot invite sadness banana'

# Enable jade logging
jadehandler = logging.StreamHandler()
logger = logging.getLogger('jadepy.jade')
logger.setLevel(logging.DEBUG)
logger.addHandler(jadehandler)
device_logger = logging.getLogger('jadepy.jade-device')
device_logger.setLevel(logging.DEBUG)
device_logger.addHandler(jadehandler)


def get_digest_args(inputs):
    digests = []
    for hexdata in inputs:
        try:
            # Expect the arguments to be digest hex
            digest = bytes.fromhex(hexdata)

            if digest and len(digest) == 32:
                digests.append(digest)
            else:
                print('Invalid hex digest:', hexdata)
        except ValueError:
            pass

    return digests


def get_digest_files(inputs):
    digests = []
    for filename in inputs:
        try:
            # Expect file contents to be the digest bytes
            with open(filename, 'rb') as f:
                digest = f.read()

            if digest and len(digest) == 32:
                digests.append(digest)
            else:
                print('Invalid digest:', d)
        except FileNotFoundError as e:
            print(e)

    return digests


def get_digest_from_data(inputs):
    digests = []
    for filename in inputs:
        try:
            # Hash file contents to create digest
            with open(filename, 'rb') as f:
                data = f.read()

            digest = hashlib.sha256(data).digest()
            assert digest and len(digest) == 32
            digests.append(digest)

        except FileNotFoundError as e:
            print(e)

    return digests


def get_jade_rsa_data(args, digests):
    # Connect to Jade over serial
    with JadeAPI.create_serial(device=args.serialport) as jade:
        # Get the version info and push entropy
        verinfo = jade.get_version_info()
        assert jade.add_entropy(os.urandom(64))

        # Maybe push mnemonic (dev only)
        if args.pushmnemonic:
            jade.set_mnemonic(TEST_MNEMONIC, temporary_wallet=True)
        else:
            # The network to use is deduced from the version-info
            network = 'testnet' if verinfo.get('JADE_NETWORKS') == 'TEST' else 'mainnet'
            jade.auth_user(network)

        # Get pubkey if requested
        get_pubkey = args.printpubkey or args.pubkeyfile
        pubkey_pem = jade.get_bip85_pubkey('RSA', args.keylen, args.index) if get_pubkey else None

        # Sign digests
        sigs = jade.sign_bip85_digests('RSA', args.keylen, args.index, digests) if digests else None

        return pubkey_pem, sigs


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--serialport',
                        action='store',
                        dest='serialport',
                        help='Serial port or device',
                        default=None)

    parser.add_argument('--keylen',
                        action='store',
                        dest='keylen',
                        type=int,
                        choices=[1024, 2048, 3072, 4096],
                        help='Key length, in bits',
                        default=3072)

    parser.add_argument('--index',
                        action='store',
                        dest='index',
                        type=int,
                        help='BIP85 key index',
                        default=1784767589)

    pubkeygrp = parser.add_mutually_exclusive_group()
    pubkeygrp.add_argument('--printpubkey',
                           action='store_true',
                           dest='printpubkey',
                           help='Download and print BIP85 pubkey pem',
                           default=False)

    pubkeygrp.add_argument('--savepubkey',
                           action='store',
                           dest='pubkeyfile',
                           help='Download and save BIP85 pubkey pem',
                           default=False)

    ingrp = parser.add_mutually_exclusive_group()
    ingrp.add_argument('--digest-files',
                       action='store_true',
                       dest='digestfiles',
                       help='Expect sha256 hash digests in the given input files',
                       default=False)

    ingrp.add_argument('--digest-args',
                       action='store_true',
                       dest='digestargs',
                       help='Expect sha256 hash digests on the command line',
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
                        default='ERROR')

    parser.add_argument('inputs',
                        action='store',
                        nargs='*',
                        help='Digest hex or filenames (digests or undigested data)',
                        default=None)

    args = parser.parse_args()
    jadehandler.setLevel(getattr(logging, args.loglevel))
    logger.debug(f'args: {args}')

    if args.digestargs:
        digests = get_digest_args(args.inputs)
    elif args.digestfiles:
        digests = get_digest_files(args.inputs)
    else:
        digests = get_digest_from_data(args.inputs)

    if len(digests) != len(args.inputs):
        sys.exit(1)

    pubkey_pem, sigs = get_jade_rsa_data(args, digests)

    if pubkey_pem:
        if args.pubkeyfile:
            with open(args.pubkeyfile, 'w') as f:
                f.write(pubkey_pem)
        else:
            assert args.printpubkey
            print(pubkey_pem)

    # Files in, files out
    # Command-line hex in, just print sig hex out
    if sigs:
        assert len(sigs) == len(args.inputs)
        for inputdata, sig in zip(args.inputs, sigs):
            assert len(sig) == args.keylen / 8
            if args.digestargs:
                print(sig.hex())
            else:
                filename = inputdata + '.sig'
                with open(filename, 'wb') as f:
                    f.write(sig)
