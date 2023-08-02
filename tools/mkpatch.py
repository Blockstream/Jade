#!/usr/bin/env python

import sys
import logging
import subprocess
import os

import fwtools

# Enable logging
logger = logging.getLogger('jadepy.jade')
logger.setLevel(logging.INFO)


# Return filepath of binary diff command
def _bsdiff_cmd():
    scriptdir = os.path.dirname(os.path.realpath(__file__))
    bsdiffcmd = fwtools.prefix_dir(scriptdir, 'bsdiff')
    return bsdiffcmd


# Get filepath for a temporary file (in the output dir)
def _tmpfilepath(outputdir, filename):
    return fwtools.prefix_dir(outputdir, filename + '.tmp')


# Remove file if present - eg. a temporary file
def _remove(filepath):
    try:
        os.remove(filepath)
    except OSError:
        pass


# Helper to read, decompress (zlib), and write a file
def write_decompressed(compressedpath, uncompressedpath):
    compressed = fwtools.read(compressedpath)
    uncompressed = fwtools.decompress(compressed)
    return fwtools.write(uncompressed, uncompressedpath)


def create_patch(frominfo, frompath, toinfo, topath, outputdir):

    tmppathpatch = _tmpfilepath(outputdir, 'patch')
    try:
        # Create the binary diff between uncompressed fw files using bsdiff
        # (expected to be in same directory as this script)
        bsdiff = _bsdiff_cmd()
        rslt = subprocess.run([bsdiff, frompath, topath, tmppathpatch])
        assert rslt.returncode == 0

        # Read the uncompressed patch data, and write zlib compressed
        # with the standard expected filename
        patch = fwtools.read(tmppathpatch)
        patchpath = fwtools.get_patch_compressed_filepath(patch, frominfo, toinfo, outputdir)
        compressed = fwtools.compress(patch)
        fwtools.write(compressed, patchpath)
    finally:
        _remove(tmppathpatch)


def create_patches(fwpathA, fwpathB, outputdir):

    logger.info(f'Patching between {fwpathA} and {fwpathB}')
    typeA, infoA, infoA_ = fwtools.parse_compressed_filename(fwpathA)
    typeB, infoB, infoB_ = fwtools.parse_compressed_filename(fwpathB)
    assert typeA == fwtools.FWFILE_TYPE_FULL and typeB == fwtools.FWFILE_TYPE_FULL
    assert infoA_ is None and infoB_ is None

    # Create (temporary) uncompressed fw files
    tmppathA, tmppathB = _tmpfilepath(outputdir, 'fwA'), _tmpfilepath(outputdir, 'fwB')

    try:
        # Decompress the source firmware images
        write_decompressed(fwpathA, tmppathA)
        write_decompressed(fwpathB, tmppathB)

        # Create patches in both directions
        create_patch(infoA, tmppathA, infoB, tmppathB, outputdir)
        create_patch(infoB, tmppathB, infoA, tmppathA, outputdir)
    finally:
        # Delete the uncompressed firmware images
        _remove(tmppathA)
        _remove(tmppathB)

    logger.info('Done!')


# Can be run as a utility
if __name__ == '__main__':
    jadehandler = logging.StreamHandler()
    logger.addHandler(jadehandler)

    assert len(sys.argv) == 4, f'Usage: {sys.argv[0]} fwA fwB output_dir'

    # Compressed firmware (ie. input) files to patch between
    fwA, fwB, outputdir = sys.argv[1], sys.argv[2], sys.argv[3]

    for fw in [fwA, fwB]:
        assert os.path.exists(fw) and os.path.isfile(fw), f'Firmware file {fw} not found.'
    assert os.path.exists(outputdir) and os.path.isdir(
        outputdir), f'Output directory {outputdir} not found.'

    # Check bsdiff exe has been compiled/is present
    bsdiff = _bsdiff_cmd()
    assert os.path.exists(bsdiff) and os.path.isfile(bsdiff), f'{bsdiff} not found.' + \
        os.linesep + 'Maybe it needs compiling - eg. from top level dir: ' + \
        os.linesep + 'gcc -O2 -DBSDIFF_EXECUTABLE -o tools/bsdiff components/esp32_bsdiff/bsdiff.c'

    # Create patches between firmware files
    create_patches(fwA, fwB, outputdir)
