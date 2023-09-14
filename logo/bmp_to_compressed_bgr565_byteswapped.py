import zlib
import struct
from PIL import Image

import sys

if len(sys.argv) < 2:
    print("Usage: python bmp_to_compressed_bgr565_byteswapped.py <input_bmp > [<input_bmp > ...]")
    sys.exit(1)

def compress_to_bgr565(bmp_file):
    image = Image.open(bmp_file)
    width, height = image.size
    bgr565_data = bytearray()
    for y in range(height):
        for x in range(width):
            r, g, b = image.getpixel((x, y))
            bgr565_value = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            bgr565_data.extend(struct.pack("<H", bgr565_value))

    swapped_data = bytearray()
    for i in range(0, len(bgr565_data), 2):
        swapped_data.append(bgr565_data[i + 1])
        swapped_data.append(bgr565_data[i])

    compressed_data = bytes([width]) + swapped_data
    compressed_data = zlib.compress(compressed_data, level=9)
    compressed_file = bmp_file.replace('.bmp', '.bin.gz')
    with open(compressed_file, "wb") as file:
        file.write(compressed_data)

for input_file in sys.argv[1:]:
    compress_to_bgr565(input_file)
