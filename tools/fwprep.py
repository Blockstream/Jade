#!/usr/bin/env python

import sys
import logging
import os

import fwtools

# Enable logging
logger = logging.getLogger('jade')
logger.setLevel(logging.INFO)


# Function to load a firmware file, compress it, and write compressed image
def create_compressed_firmware_image(fwfilename, outputdir):

    # Load uncompressed firmware and deduce the appropriate compressed firmware filename
    firmware = fwtools.read(fwfilename)
    outfile = fwtools.get_firmware_compressed_filepath(firmware, outputdir)

    # Compress and write
    compressed = fwtools.compress(firmware)
    fwtools.write(compressed, outfile)

    # Uncompress and check size and contents
    logger.info('Verifying...')
    compressed = fwtools.read(outfile)
    checkfw = fwtools.decompress(compressed)
    assert len(firmware) == len(checkfw)
    assert firmware == checkfw
    logger.info('OK')


# Can be run as a utility
if __name__ == '__main__':
    jadehandler = logging.StreamHandler()
    logger.addHandler(jadehandler)

    assert len(sys.argv) == 3, f'Usage: {sys.argv[0]} uncompressed-fw output_dir'

    # Uncompressed firmware (ie. input) file
    fwfilename, outputdir = sys.argv[1], sys.argv[2]

    assert os.path.exists(fwfilename) and os.path.isfile(
        fwfilename), f'Firmware file {fwfilename} not found.'
    assert os.path.exists(outputdir) and os.path.isdir(
        outputdir), f'Output directory {outputdir} not found.'

    # Compress firmware and write file
    create_compressed_firmware_image(fwfilename, outputdir)
