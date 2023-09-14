# Files in this directory are compressed using python

```
python -c "import zlib; import sys; open(sys.argv[2], 'wb').write(zlib.compress(open(sys.argv[1], 'rb').read(), 9))" uncompressed_file.bin compressed_file.bin.gz
```

# The input file used is the output of GIMP RGB C-Source image dump (file.c) which contains a stucture Picture.
# Picture contains the following uint32_t width, height, bytes_per_pixel (always set to 2) and then the binary data in a pointer to a uint16_t

# We extracted the binary data into uncompressed_file prepended with a single byte with the width (since it can at most be 240) and then we compressed it with the python above
