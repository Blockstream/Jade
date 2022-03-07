import zlib
import logging
import re
import os

from collections import namedtuple
FwInfo = namedtuple('FwInfo', 'version config fwsize')

FWFILE_TYPE_FULL = 'fw.bin'
FWFILE_TYPE_PATCH = 'patch.bin'

logger = logging.getLogger('jade')


# Prefix a directory to an existing filename/path
def prefix_dir(dir, filename):
    anyslash = '' if dir.endswith('/') else '/'
    return dir + anyslash + filename


# Generate compressed image filename based on version, ble-config and size of
# the uncompressed firmware (as deduced from the passed firmware image)
# See also 'parse_compressed_filename()' below
def get_firmware_compressed_filepath(firmware, outputdir):
    # Get the version string - first printable string in the
    # firmware binary file of length 6 or more.
    # FIXME: improve regex when we know what the version labels will look like
    match = re.search(u'[^\x00-\x1F\x7F-\xFF]{6,}'.encode('utf8'), firmware)
    assert match and match.group() and match.group().decode('utf8')
    ver = match.group().decode('utf8')

    # Look for the 'NORADIO' value in the binary
    match = re.search('NORADIO'.encode(), firmware)
    config = 'noradio' if match else 'ble'

    # Maybe double-check these, search in the ninja/config files?

    # Full file path is:
    # <dir>/<ver>_<config>_<uncompressed-size>_fw.bin
    filename = ver + '_' + config + '_' + str(len(firmware)) + '_' + FWFILE_TYPE_FULL

    filepath = prefix_dir(outputdir, filename)
    logger.info(f'Deduced compressed firmware filepath: {filepath}')
    return filepath


# Generate path filename based on versions and ble-configs of from/to fws, the uncompressed
# size of the final destination firmware, and the uncompressed size of this patch
# See also 'parse_compressed_filename()' below
def get_patch_compressed_filepath(patch, frominfo, toinfo, outputdir):
    # Full file path is:
    # <dir>/<tover>_<toconfig>_from_<fromver>_<fromcfg>_sizes_<uncompressed-fwsize>_<uncompressed-patchsize>_patch.bin
    filename = toinfo.version + '_' + toinfo.config + '_from_' + \
               frominfo.version + '_' + frominfo.config + '_sizes_' + \
               str(toinfo.fwsize) + '_' + str(len(patch)) + '_' + FWFILE_TYPE_PATCH

    filepath = prefix_dir(outputdir, filename)
    logger.info(f'Deduced compressed patch filepath: {filepath}')

    return filepath


def parse_compressed_filename(filepath):
    filename = os.path.basename(filepath)
    parts = filename.split('_')

    if len(parts) == 4 and parts[-1] == FWFILE_TYPE_FULL:
        # File name is:
        # <ver>_<config>_<uncompressed-size>_fw.bin[.uncompressed]
        logger.info(f'Filename suggests full firmware: {filename}')
        fwinfo = FwInfo(parts[0], parts[1], int(parts[2]))
        return (FWFILE_TYPE_FULL, fwinfo, None)

    elif len(parts) == 9 and parts[-1] == FWFILE_TYPE_PATCH:
        # File name is:
        # <tover>_<otconfig>_from_<fromver>_<fromcfg>_sizes_<uncompressed-fwsize>_<uncompressed-patchsize>_patch.bin
        logger.info(f'Filename suggests firmware patch: {filename}')
        toinfo = FwInfo(parts[0], parts[1], int(parts[6]))
        frominfo = FwInfo(parts[3], parts[4], int(parts[7]))  # store patch len in frominfo size
        return (FWFILE_TYPE_PATCH, toinfo, frominfo)

    else:
        raise Exception(f'Unknown filename format: {filename}')


# Compress using zlib
# Returns compressed data
def compress(uncompressed):
    logger.info(f'Compressing {len(uncompressed)} bytes')
    compressed = zlib.compress(uncompressed, 9)
    logger.info(f'Compressed to {len(compressed)} bytes')
    return compressed


# Decompress using zlib
# Returns decompressed data
def decompress(compressed):
    logger.info(f'Decompressing {len(compressed)} bytes')
    uncompressed = zlib.decompress(compressed)
    logger.info(f'Decompressed to {len(uncompressed)} bytes')
    return uncompressed


# Read data bytes from file
# Returns data read
def read(filepath):
    logger.info(f'Reading file {filepath}')
    with open(filepath, 'rb') as f:
        data = f.read()
    logger.info(f'Read {len(data)} bytes')
    return data


# Write data bytes to file
# Returns data written
def write(data, filepath):
    # Write the bytes
    with open(filepath, 'wb') as f:
        data = f.write(data)
    logger.info(f'Written file {filepath}')
    return data
