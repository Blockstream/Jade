import sys
import zlib
import logging
import re
import os

# NOTE: Python2 compatible so can run in gitlab-ci

DEFAULT_FIRMWARE_FILE = "build/jade.bin"
DEFAULT_OUTPUT_DIR = "build"

# Enable logging
logger = logging.getLogger('jade')
logger.setLevel(logging.DEBUG)


# Generate compressed image filename based on version, ble-config and size of
# the uncompressed firmware (as deduced from the passed firmware image)
def get_compressed_filepath(firmware, outputdir):
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

    # Full file path is <dir>/<ver>_<config>_<uncompressed-size>_fw.bin
    filename = ver + '_' + config + '_' + str(len(firmware)) + "_fw.bin"
    slash = '' if outputdir.endswith('/') else '/'
    filepath = outputdir + slash + filename
    logger.info("Deduced compressed filepath: {}".format(filepath))

    return filepath


# Compress firmware and write to file
# Returns compressed data
def compress_and_write(uncompressed, filename):

    logger.info("Compressing {} bytes".format(len(uncompressed)))

    compressed = zlib.compress(uncompressed, 9)
    logger.info("Compressed to {} bytes".format(len(compressed)))

    with open(filename, 'wb') as fwfile:
        fw = fwfile.write(compressed)

    logger.info("Written file {}".format(filename))

    return compressed


# Read a compressed firmware file and decompress
# Returns decompressed data
def read_and_decompress(filename):

    logger.info("Reading file {}".format(filename))

    with open(filename, 'rb') as fwfile:
        compressed = fwfile.read()

    logger.info("Read {} bytes".format(len(compressed)))
    decompressed = zlib.decompress(compressed)

    logger.info("Decompressed to {} bytes".format(len(decompressed)))

    return decompressed


# Function to load a firmware file, compress it, and write compressed image
def create_compressed_firmware_image(firmware, outputdir):

    # Get compressed firmware filename
    outfile = get_compressed_filepath(firmware, outputdir)

    # Compress and write
    compressed = compress_and_write(firmware, outfile)

    # Uncompress and check size and contents
    logger.info("Verifying...")
    checkfw = read_and_decompress(outfile)
    assert len(firmware) == len(checkfw)
    assert firmware == checkfw
    logger.info("OK")

    # Return compressed data
    return compressed


# Can be run as a utility
if __name__ == "__main__":
    jadehandler = logging.StreamHandler()
    logger.addHandler(jadehandler)

    # Uncompressed firmware (ie. input) file
    fwfilename = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FIRMWARE_FILE
    outputdir = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUTPUT_DIR

    assert os.path.exists(fwfilename) and os.path.isfile(
        fwfilename), "Firmware file '{}' not found.".format(fwfilename)
    assert os.path.exists(outputdir) and os.path.isdir(
        outputdir), "Output directory '{}' not found.".format(outputdir)

    # Load uncompressed firmware
    logger.info("Reading file: {}".format(fwfilename))
    with open(fwfilename, 'rb') as fwfile:
        firmware = fwfile.read()

    logger.info("Read {} bytes".format(len(firmware)))

    # Compress firmware and write file
    create_compressed_firmware_image(firmware, outputdir)
