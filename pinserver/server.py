import time
from hmac import compare_digest
import os
from .lib import decrypt, encrypt, E_ECDH
from wallycore import ec_private_key_verify, ec_sig_from_bytes, sha256, \
    hmac_sha256, EC_FLAG_ECDSA


class PINServerECDH(E_ECDH):
    STATIC_SERVER_PRIVATE_KEY_FILE = 'server_private_key.key'
    STATIC_SERVER_PUBLIC_KEY_FILE = 'server_public_key.pub'
    STATIC_SERVER_PRIVATE_KEY = None
    STATIC_SERVER_AES_PIN_DATA = None

    @classmethod
    def generate_server_key_pair(cls):
        if os.path.exists(cls.STATIC_SERVER_PRIVATE_KEY_FILE):
            print(f'Key already exists in file {cls.STATIC_SERVER_PRIVATE_KEY_FILE}')
            return

        private_key, public_key = cls.generate_ec_key_pair()

        with open(cls.STATIC_SERVER_PRIVATE_KEY_FILE, 'wb') as f:
            f.write(private_key)

        with open(cls.STATIC_SERVER_PUBLIC_KEY_FILE, 'wb') as f:
            f.write(public_key)

        print(f'New private key written to file {cls.STATIC_SERVER_PRIVATE_KEY_FILE}')
        print(f'New public key written to file {cls.STATIC_SERVER_PUBLIC_KEY_FILE}')

    @classmethod
    def _load_private_key(cls):
        if not cls.STATIC_SERVER_PRIVATE_KEY:
            with open(cls.STATIC_SERVER_PRIVATE_KEY_FILE, 'rb') as f:
                cls.STATIC_SERVER_PRIVATE_KEY = f.read()
                ec_private_key_verify(cls.STATIC_SERVER_PRIVATE_KEY)

    @classmethod
    def _sign_with_static_key(cls, msg):
        cls._load_private_key()

        hashed = sha256(msg)
        return ec_sig_from_bytes(cls.STATIC_SERVER_PRIVATE_KEY,
                                 hashed,
                                 EC_FLAG_ECDSA)

    @classmethod
    def _get_aes_pin_data_key(cls):
        cls._load_private_key()
        if not cls.STATIC_SERVER_AES_PIN_DATA:
            cls.STATIC_SERVER_AES_PIN_DATA = hmac_sha256(cls.STATIC_SERVER_PRIVATE_KEY, b'pin_data')
        return cls.STATIC_SERVER_AES_PIN_DATA

    # Instance methods
    def __init__(self):
        super().__init__()
        self.time_started = int(time.time())

    def get_signed_public_key(self):
        return self.public_key, self._sign_with_static_key(self.public_key)

    # Decrypt the received payload (ie. aes-key)
    def decrypt_request_payload(self, cke, encrypted, hmac):
        # Verify hmac received
        hmac_calculated = hmac_sha256(self.request_hmac_key, cke + encrypted)
        assert compare_digest(hmac, hmac_calculated)

        # Return decrypted data
        return decrypt(self.request_encryption_key, encrypted)

    def encrypt_response_payload(self, payload):
        encrypted = encrypt(self.response_encryption_key, payload)
        hmac = hmac_sha256(self.response_hmac_key, encrypted)
        return encrypted, hmac

    # Function to deal with wrapper ecdh encryption.
    # Calls passed function with unwrapped payload, and wraps response before
    # returning.  Separates payload handler func from wrapper encryption.
    def call_with_payload(self, cke, encrypted, hmac, func):
        self.generate_shared_secrets(cke)
        payload = self.decrypt_request_payload(cke, encrypted, hmac)

        # Call the passed function with the decrypted payload
        response = func(cke, payload, self._get_aes_pin_data_key())

        encrypted, hmac = self.encrypt_response_payload(response)
        return encrypted, hmac
