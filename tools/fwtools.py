import zlib
import logging
import re

FWFILE_TYPE_FULL = 'fw.bin'

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
