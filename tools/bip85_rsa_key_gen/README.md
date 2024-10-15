This tool allows to create rsa private keys from xpriv or from bip39 mnemonics with or without passphrase.
Unfortunately the bip85 standard doesn't tell much about the exact valid private keys for rsa and each rsa implementation (mbedtls/openssl/pycryptodome etc) all have slightly different implementations.

This in practice means that mbedtls will give you different valid keys from pycryptodome even though they have access to exactly the same entropy.


Jade as such only offers a specific implementation in time - mbedtls at time of release, with automated checks to automatically catch any change in the future.
In case any change happens we plan to keep the old behaviour unless it is considered unsafe. Likewise if a proper standard emerges we plan to adapt to it with a slightly different parameter.

It is to be noted that rsa keys generated with pycryptodome are *not* compatible with ours.

# FIXME: add support for https://developer.espressif.com/blog/secure-signing-using-external-hsm/
