import os
import time
import struct
import redis
from .lib import decrypt, encrypt
from pathlib import Path
from hmac import compare_digest
from wallycore import ec_sig_to_public_key, sha256, hmac_sha256, \
    hex_from_bytes, AES_KEY_LEN_256, EC_SIGNATURE_RECOVERABLE_LEN, SHA256_LEN, \
    hex_to_bytes
from dotenv import load_dotenv

b2h = hex_from_bytes
h2b = hex_to_bytes

VERSION = 0

load_dotenv()

redis_host = os.environ.get('REDIS_HOST')
redis_port = int(os.environ.get('REDIS_PORT', 6379))
redis_health_check_interval = int(os.environ.get('REDIS_HEALTH_CHECK_INTERVAL', 25))
redis_password = os.environ.get('REDIS_PASSWORD', None)
red_conn = redis.Redis(host=redis_host, port=redis_port, db=0, password=redis_password,
                       health_check_interval=redis_health_check_interval,
                       retry_on_timeout=True)


class FileStorage(object):

    @staticmethod
    def _get_filename(key):
        filename = '{}.pin'.format(b2h(key))
        if os.path.exists('pins'):
            return Path('pins') / filename
        return filename

    @classmethod
    def get(cls, key):
        with open(cls._get_filename(key), 'rb') as f:
            return f.read()

    @classmethod
    def set(cls, key, data):
        with open(cls._get_filename(key), 'wb') as f:
            f.write(data)

    @classmethod
    def exists(cls, key):
        return os.path.exists(cls._get_filename(key))

    @classmethod
    def remove(cls, key):
        return os.remove(cls._get_filename(key))


class RedisStorage(object):

    @staticmethod
    def redis_retry(func):
        redis_sleep = int(os.environ.get('REDIS_SLEEP', 5))
        while True:
            try:
                return func()
            except redis.ConnectionError:
                print(f'Server {redis_host} unavailable, retrying in {redis_sleep}...')
                time.sleep(redis_sleep)

    @classmethod
    def get(cls, key):
        data = cls.redis_retry(lambda: red_conn.get(key))
        if not data:
            raise Exception("No valid pin found")
        return data

    @classmethod
    def set(cls, key, data):
        return cls.redis_retry(lambda: red_conn.set(key, data))

    @classmethod
    def exists(cls, key):
        return cls.redis_retry(lambda: red_conn.exists(key))

    @classmethod
    def remove(cls, key):
        return cls.redis_retry(lambda: red_conn.delete(key))


def get_storage():
    if not redis_host:
        print("Using filesystem based storage")
        return FileStorage

    print(f'''Connecting to {redis_host}:{redis_port},
health check every {redis_health_check_interval}''')

    RedisStorage.redis_retry(lambda: red_conn.ping())
    return RedisStorage


class PINDb(object):

    storage = get_storage()

    @classmethod
    def _extract_fields(cls, cke, data):
        assert len(data) == (2*SHA256_LEN) + EC_SIGNATURE_RECOVERABLE_LEN

        # secret + entropy + sig
        pin_secret = data[:SHA256_LEN]
        entropy = data[SHA256_LEN: SHA256_LEN + SHA256_LEN]
        sig = data[SHA256_LEN + SHA256_LEN:]

        # We know mesage the signature is for, so can recover the public key
        signed_msg = sha256(cke + pin_secret + entropy)
        client_public_key = ec_sig_to_public_key(signed_msg, sig)

        return pin_secret, entropy, client_public_key

    @classmethod
    def _save_pin_fields(cls, pin_pubkey_hash, hash_pin_secret, aes_key,
                         pin_pubkey, aes_pin_data_key, count=0):

        # the data is encrypted and then hmac'ed for authentication
        # the encrypted data can't be read by us without the user
        # sending us the pin_pubkey (we only store the hash thereof)

        storage_aes_key = hmac_sha256(aes_pin_data_key, pin_pubkey)
        count_bytes = struct.pack('B', count)
        plaintext = hash_pin_secret + aes_key + count_bytes
        encrypted = encrypt(storage_aes_key, plaintext)
        pin_auth_key = hmac_sha256(aes_pin_data_key, pin_pubkey_hash)
        version_bytes = struct.pack('B', VERSION)
        hmac_payload = hmac_sha256(pin_auth_key, version_bytes + encrypted)

        cls.storage.set(pin_pubkey_hash, version_bytes + hmac_payload + encrypted)

        return aes_key

    @classmethod
    def _load_pin_fields(cls, pin_pubkey_hash, pin_pubkey, aes_pin_data_key):

        data = cls.storage.get(pin_pubkey_hash)
        assert len(data) == 129
        version, hmac_received, encrypted = data[:1], data[1:33], data[33:]

        # verify integrity of encrypted data first
        pin_auth_key = hmac_sha256(aes_pin_data_key, pin_pubkey_hash)
        version_bytes = struct.pack('B', VERSION)
        assert version_bytes == version
        hmac_payload = hmac_sha256(pin_auth_key, version_bytes + encrypted)

        assert hmac_payload == hmac_received

        storage_aes_key = hmac_sha256(aes_pin_data_key, pin_pubkey)
        plaintext = decrypt(storage_aes_key, encrypted)

        assert len(plaintext) == 32 + 32 + 1

        hash_pin_secret, aes_key = plaintext[:32], plaintext[32:64]
        count = struct.unpack('B', plaintext[64: 64 + struct.calcsize('B')])[0]

        return hash_pin_secret, aes_key, count

    @classmethod
    def make_client_aes_key(self, pin_secret, saved_key):
        # The client key returned is a combination of the aes-key persisted
        # and the raw pin_secret (that we do not persist anywhere).
        aes_key = hmac_sha256(saved_key, pin_secret)
        assert len(aes_key) == AES_KEY_LEN_256
        return aes_key

    # Get existing aes_key given pin fields
    @classmethod
    def get_aes_key_impl(cls, pin_pubkey, pin_secret, aes_pin_data_key):
        # Load the data from the pubkey
        pin_pubkey_hash = bytes(sha256(pin_pubkey))
        saved_hps, saved_key, counter = cls._load_pin_fields(pin_pubkey_hash,
                                                             pin_pubkey,
                                                             aes_pin_data_key)

        # Check that the pin provided matches that saved
        hash_pin_secret = sha256(pin_secret)
        if compare_digest(saved_hps, hash_pin_secret):
            # pin-secret matches - correct pin
            if counter != 0:
                # Zero the 'bad guess counter'
                cls._save_pin_fields(pin_pubkey_hash, saved_hps, saved_key,
                                     pin_pubkey, aes_pin_data_key)

            # return the saved key
            return saved_key

        # user provided wrong pin
        if counter >= 2:
            # pin failed 3 times, overwrite and then remove secret
            cls._save_pin_fields(pin_pubkey_hash,
                                 saved_hps,
                                 bytearray(AES_KEY_LEN_256),
                                 pin_pubkey,
                                 aes_pin_data_key)
            cls.storage.remove(pin_pubkey_hash)
            raise Exception("Too many attempts")
        else:
            # increment counter
            cls._save_pin_fields(pin_pubkey_hash, saved_hps, saved_key, pin_pubkey,
                                 aes_pin_data_key, counter + 1)
            raise Exception("Invalid PIN")

    # Get existing aes_key given pin fields, or junk if pin or pubkey bad
    @classmethod
    def get_aes_key(cls, cke, payload, aes_pin_data_key):
        pin_secret, _, pin_pubkey = cls._extract_fields(cke, payload)

        # Translate internal exception and bad-pin into junk key
        try:
            saved_key = cls.get_aes_key_impl(pin_pubkey,
                                             pin_secret,
                                             aes_pin_data_key)
        except Exception as e:
            # return junk key
            saved_key = os.urandom(AES_KEY_LEN_256)

        # Combine saved key with (not persisted) pin-secret
        return cls.make_client_aes_key(pin_secret, saved_key)

    # Set pin fields, return new aes_key
    @classmethod
    def set_pin(cls, cke, payload, aes_pin_data_key):
        pin_secret, entropy, pin_pubkey = cls._extract_fields(cke, payload)

        # Make a new aes-key to persist from our and client entropy
        our_random = os.urandom(32)
        new_key = hmac_sha256(our_random, entropy)

        # Persist the pin fields
        pin_pubkey_hash = bytes(sha256(pin_pubkey))
        hash_pin_secret = sha256(pin_secret)
        saved_key = cls._save_pin_fields(pin_pubkey_hash, hash_pin_secret, new_key,
                                         pin_pubkey, aes_pin_data_key)

        # Combine saved key with (not persisted) pin-secret
        return cls.make_client_aes_key(pin_secret, saved_key)
