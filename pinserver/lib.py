import os

from wallycore import AES_BLOCK_LEN, AES_FLAG_DECRYPT, AES_FLAG_ENCRYPT, \
    aes_cbc, ec_private_key_verify, ec_public_key_from_private_key, ecdh, \
    hmac_sha256


def encrypt(aes_key, plaintext):
    iv = os.urandom(AES_BLOCK_LEN)
    size = (int(len(plaintext) / AES_BLOCK_LEN) + 1) * AES_BLOCK_LEN
    encrypted = bytearray(size)
    written = aes_cbc(aes_key, iv, plaintext, AES_FLAG_ENCRYPT, encrypted)
    return iv + encrypted[:written]


def decrypt(aes_key, encrypted):
    plaintext = bytearray(len(encrypted) - AES_BLOCK_LEN)
    iv = encrypted[:AES_BLOCK_LEN]
    written = aes_cbc(aes_key,
                      iv,
                      encrypted[AES_BLOCK_LEN:],
                      AES_FLAG_DECRYPT,
                      plaintext)
    return plaintext[:written]


class E_ECDH(object):

    @classmethod
    def _generate_private_key(cls):
        counter = 4
        while counter:
            private_key = os.urandom(32)
            try:
                ec_private_key_verify(private_key)
                return private_key
            except Exception:
                counter -= 1
        raise Exception

    @classmethod
    def generate_ec_key_pair(cls):
        private_key = cls._generate_private_key()
        public_key = ec_public_key_from_private_key(private_key)
        return private_key, public_key

    def __init__(self):
        self.private_key, self.public_key = self.generate_ec_key_pair()

    def generate_shared_secrets(self, public_key):
        master_shared_key = ecdh(public_key, self.private_key)

        def _derived(val):
            return hmac_sha256(master_shared_key, bytearray([val]))

        self.request_encryption_key = _derived(0)
        self.request_hmac_key = _derived(1)
        self.response_encryption_key = _derived(2)
        self.response_hmac_key = _derived(3)
