import unittest

import os
from hmac import compare_digest

from ..pindb import PINDb
from ..lib import encrypt, decrypt, E_ECDH

from wallycore import sha256, ec_sig_from_bytes, hex_from_bytes, \
    AES_KEY_LEN_256, EC_FLAG_ECDSA, EC_FLAG_RECOVERABLE

b2h = hex_from_bytes


# Tests the pindb and payload handling without any reference to the ecdh
# protocol/encryption wrapper.
class PINDbTest(unittest.TestCase):

    @staticmethod
    def new_pin_secret():
        return os.urandom(32)

    @staticmethod
    def new_entropy():
        return os.urandom(32)

    @staticmethod
    def make_payload(signing_key, cke, secret_in, entropy_in):
        # Build the expected payload
        sig = ec_sig_from_bytes(signing_key,
                                sha256(cke + secret_in + entropy_in),
                                EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE)
        return secret_in + entropy_in + sig

    @classmethod
    def new_keys(cls):
        # USE ECDH class just because it's convenient way to make key pairs
        sig_priv, sig_pub = E_ECDH.generate_ec_key_pair()
        _, cke = E_ECDH.generate_ec_key_pair()

        # add the pin_pubkey_hash to the set
        pin_pubkey_hash = bytes(sha256(sig_pub))
        cls.pinfiles.add(pin_pubkey_hash)

        return sig_priv, sig_pub, cke, pin_pubkey_hash

    @classmethod
    def setUpClass(cls):
        # pinfiles that may be created, so we can ensure they are deleted
        cls.pinfiles = set()

    # tearDownClass() tidies up any remaining pinfiles
    @classmethod
    def tearDownClass(cls):
        # Delete any remaining pinfiles
        for f in cls.pinfiles:
            if PINDb.storage.exists(f):
                PINDb.storage.remove(f)

    def _test_extract_fields_impl(self):
        # Reinitialise keys and secret and entropy
        sig_priv, sig_pub, cke, _ = self.new_keys()
        secret_in, entropy_in = self.new_pin_secret(), self.new_entropy()

        # Build the expected payload
        payload = self.make_payload(sig_priv, cke, secret_in, entropy_in)

        # Check pindb function can extract the components from the payload
        secret_out, entropy_out, pubkey = PINDb._extract_fields(cke, payload)
        self.assertEqual(secret_out, secret_in)
        self.assertEqual(entropy_out, entropy_in)

        # Check the public key is correctly recovered from the signature
        self.assertEqual(pubkey, sig_pub)

    def test_extract_fields(self):
        for i in range(5):
            with self.subTest(i=i):
                self._test_extract_fields_impl()

    def test_mismatching_cke_and_sig(self):
        # Get two sets of keys and a new secret
        privX, pubX, ckeX, _ = self.new_keys()
        privY, pubY, ckeY, _ = self.new_keys()
        secret_in, entropy_in = self.new_pin_secret(), self.new_entropy()

        # Build the expected payload with the wrong cke value
        payload = self.make_payload(privX, ckeY, secret_in, entropy_in)

        # Call the pindb function to extract the components from the payload
        # but use the 'expected' cke - the sig should not match either pubkey.
        secret_out, entropy_out, pubkey = PINDb._extract_fields(ckeX, payload)
        self.assertEqual(secret_out, secret_in)
        self.assertEqual(entropy_out, entropy_in)
        self.assertNotEqual(pubkey, pubX)
        self.assertNotEqual(pubkey, pubY)

    def test_save_and_load_pin_fields(self):
        # Reinitialise keys and secret
        _, _, _, pinfile = self.new_keys()
        pin_secret, key_in = self.new_pin_secret(), self.new_entropy()
        hps_in = sha256(pin_secret)
        count_in = 5

        # Trying to read non-existent file throws (and does not create file)
        self.assertFalse(PINDb.storage.exists(pinfile))
        with self.assertRaises((FileNotFoundError, Exception)) as _:
            PINDb._load_pin_fields(pinfile, None, None)
        self.assertFalse(PINDb.storage.exists(pinfile))

        user_id = os.urandom(32)
        aes_pin = bytes(os.urandom(32))

        # Save some data - check new file created
        new_key = PINDb._save_pin_fields(pinfile, hps_in, key_in, user_id, aes_pin, count_in)
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Atm the 'new key' returned should be the one passed in
        self.assertEqual(new_key, key_in)

        # Read file back in - ensure fields the same
        hps_out, key_out, count_out = PINDb._load_pin_fields(pinfile, user_id, aes_pin)
        self.assertEqual(hps_out, hps_in)
        self.assertEqual(key_out, key_in)
        self.assertEqual(count_out, count_in)

        # Ensure we can set zero the count of an existing file
        count_in = 0
        new_key = PINDb._save_pin_fields(pinfile, hps_in, key_in, user_id, aes_pin, count_in)
        hps_out, key_out, count_out = PINDb._load_pin_fields(pinfile, user_id, aes_pin)
        self.assertEqual(hps_out, hps_in)
        self.assertEqual(key_out, key_in)
        self.assertEqual(count_out, count_in)

        # Ensure we can't decrypt the pin with the wrong aes_key, hmac won't match
        bad_aes = os.urandom(32)
        with self.assertRaises(AssertionError) as _:
            PINDb._load_pin_fields(pinfile, user_id, bad_aes)

    def _test_set_and_get_pin_impl(self):
        # Reinitialise keys and secret
        sig_priv, _, cke, pinfile = self.new_keys()
        secret = self.new_pin_secret()

        # Make the expected payload
        payload = self.make_payload(sig_priv, cke, secret, self.new_entropy())
        # Set the pin = check this creates the file
        self.assertFalse(PINDb.storage.exists(pinfile))
        pin_aes_key = bytes(os.urandom(32))
        aeskey_s = PINDb.set_pin(cke, payload, pin_aes_key)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Get the key with the pin - new payload has new entropy (same pin)
        payload = self.make_payload(sig_priv, cke, secret, self.new_entropy())
        aeskey_g = PINDb.get_aes_key(cke, payload, pin_aes_key)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

    def test_set_and_get_pin(self):
        for i in range(5):
            with self.subTest(i=i):
                self._test_set_and_get_pin_impl()

    def test_bad_guesses_clears_pin(self):
        # Reinitialise keys and secret
        sig_priv, _, cke, pinfile = self.new_keys()
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()

        # Build the expected payload
        good_payload = self.make_payload(sig_priv, cke, pin_secret, entropy)
        # Set and verify the the pin = check this creates the file
        self.assertFalse(PINDb.storage.exists(pinfile))
        pin_aes_key = bytes(os.urandom(32))
        aeskey_s = PINDb.set_pin(cke, good_payload, pin_aes_key)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        aeskey_g = PINDb.get_aes_key(cke, good_payload, pin_aes_key)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Bad guesses at PIN
        for attempt in range(3):
            # Attempt to get with bad pin (using same entropy)
            bad_secret = os.urandom(32)
            bad_payload = self.make_payload(sig_priv, cke, bad_secret, entropy)
            guesskey = PINDb.get_aes_key(cke, bad_payload, pin_aes_key)

            # Wrong pin should return junk aes-key
            self.assertEqual(len(aeskey_s), len(guesskey))
            self.assertFalse(compare_digest(aeskey_s, guesskey))

        # after three failed attempts server deletes the file
        self.assertFalse(PINDb.storage.exists(pinfile))

        # Now even the correct pin will fail...
        aeskey = PINDb.get_aes_key(cke, good_payload, pin_aes_key)
        self.assertEqual(len(aeskey), len(aeskey_s))
        self.assertFalse(compare_digest(aeskey, aeskey_s))
        self.assertFalse(PINDb.storage.exists(pinfile))

    def test_bad_server_key_or_user_pub_key_breaks(self):
        # Reinitialise keys and secret
        sig_priv, _, cke, pinfile = self.new_keys()
        pin_secret, entropy = self.new_pin_secret(), self.new_entropy()

        # Build the expected payload
        good_payload = self.make_payload(sig_priv, cke, pin_secret, entropy)

        # Set and verify the the pin = check this creates the file
        self.assertFalse(PINDb.storage.exists(pinfile))
        pin_aes_key = bytes(os.urandom(32))
        aeskey_s = PINDb.set_pin(cke, good_payload, pin_aes_key)
        self.assertEqual(len(aeskey_s), AES_KEY_LEN_256)
        aeskey_g = PINDb.get_aes_key(cke, good_payload, pin_aes_key)
        self.assertTrue(compare_digest(aeskey_g, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Bad server key
        for attempt in range(3):
            # Attempt to get with bad server key (using same entropy)
            bad_key = os.urandom(32)
            guesskey = PINDb.get_aes_key(cke, good_payload, bad_key)

            # Wrong pubkey should return junk aes-key
            self.assertEqual(len(aeskey_s), len(guesskey))
            self.assertFalse(compare_digest(aeskey_s, guesskey))

        # Bad pub key
        for attempt in range(3):
            # Attempt to get with bad pub_key (using same entropy)
            bad_key = os.urandom(32)
            bad_payload = self.make_payload(bad_key, cke, pin_secret, entropy)
            guesskey = PINDb.get_aes_key(cke, bad_payload, pin_aes_key)

            # Wrong pubkey should return junk aes-key
            self.assertEqual(len(aeskey_s), len(guesskey))
            self.assertFalse(compare_digest(aeskey_s, guesskey))

        # after six failed attempts server keeps the file
        # as it doesn't know what file to check even
        self.assertTrue(PINDb.storage.exists(pinfile))

        # Now the correct pin will should still be correct...
        aeskey = PINDb.get_aes_key(cke, good_payload, pin_aes_key)
        self.assertEqual(len(aeskey), len(aeskey_s))
        self.assertTrue(compare_digest(aeskey, aeskey_s))
        self.assertTrue(PINDb.storage.exists(pinfile))

    def test_two_users_with_same_pin(self):
        # Get two sets of keys and a new secret
        privX, pubX, ckeX, _ = self.new_keys()
        privY, pubY, ckeY, _ = self.new_keys()
        secret_in, entropy_in = self.new_pin_secret(), self.new_entropy()

        # Build the expected payloads
        # X and Y use the same values... bizarre but should be fine
        payloadX = self.make_payload(privX, ckeX, secret_in, entropy_in)
        payloadY = self.make_payload(privY, ckeY, secret_in, entropy_in)
        pin_aes_key = bytes(os.urandom(32))
        aeskeyX_s = PINDb.set_pin(ckeX, payloadX, pin_aes_key)
        aeskeyY_s = PINDb.set_pin(ckeY, payloadY, pin_aes_key)

        # Keys should be different
        self.assertEqual(len(aeskeyX_s), len(aeskeyY_s))
        self.assertFalse(compare_digest(aeskeyX_s, aeskeyY_s))

        # Each can get their own key
        aeskeyX_g = PINDb.get_aes_key(ckeX, payloadX, pin_aes_key)
        aeskeyY_g = PINDb.get_aes_key(ckeY, payloadY, pin_aes_key)
        self.assertFalse(compare_digest(aeskeyX_g, aeskeyY_g))
        self.assertTrue(compare_digest(aeskeyX_g, aeskeyX_s))
        self.assertTrue(compare_digest(aeskeyY_g, aeskeyY_s))

    def test_rejects_without_client_entropy(self):
        # Reinitialise keys and secret and entropy
        sig_priv, _, cke, pinfile = self.new_keys()
        secret, entropy = self.new_pin_secret(), bytearray()

        # Build the expected payload
        payload = self.make_payload(sig_priv, cke, secret, entropy)

        pin_aes_key = bytes(os.urandom(32))
        with self.assertRaises(AssertionError) as cm:
            PINDb.set_pin(cke, payload, pin_aes_key)

        with self.assertRaises(AssertionError) as cm:
            PINDb.get_aes_key(cke, payload, pin_aes_key)


if __name__ == '__main__':
    unittest.main()
