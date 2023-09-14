import zlib
import struct
from PIL import Image

import sys

if len(sys.argv) < 2:
    print("Usage: python compressed_bgr565_byteswapped_to_bmp.py <input_compressed_file1> [<input_compressed_file2> ...]")
    sys.exit(1)

def extract_to_bmp(filename):
    with open(filename, "rb") as file:
        compressed_data = file.read()

    decompressed_data = zlib.decompress(compressed_data)

    width = decompressed_data[0]


    swapped_pixel_data = bytearray()
    for i in range(0, len(decompressed_data[1:]), 2):
        swapped_pixel_data.append(decompressed_data[1:][i + 1])
        swapped_pixel_data.append(decompressed_data[1:][i])

    decompressed_data = bytes([width]) + swapped_pixel_data

    num_pixels = (len(decompressed_data) - 1) // 2
    height = num_pixels // width

    image = Image.new("RGB", (width, height))

    pixels = image.load()
    for i in range(num_pixels):
        offset = i * 2 + 1
        bgr_value = struct.unpack("<H", decompressed_data[offset:offset+2])[0]

        r = (bgr_value >> 11) << 3
        g = ((bgr_value >> 5) & 0x003F) << 2
        b = (bgr_value & 0x001F) << 3

        x = i % width
        y = i // width
        pixels[x, y] = (r, g, b)

    bmp_file = filename.replace('.bin.gz', '.bmp')
    image.save(bmp_file, "BMP")

for input_file in sys.argv[1:]:
    extract_to_bmp(input_file)
