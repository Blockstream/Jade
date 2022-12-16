It should take this miner running on a Jade / ESP32 about 14.7 hours to run through the nonce.

We applied a few optimizations.

We took a sha256 twice and optimized it for 80 bytes input size (block header size), with the first 64
bytes not changing for 2+-hours or until a new block is found.
