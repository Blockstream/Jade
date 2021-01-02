import unittest

import os

from ..client import PINClientECDH
from ..server import PINServerECDH


# Tests ECDH wrapper without any reference to the pin/aes-key paylod stuff.
# Just testing the ECDH envelope/ecryption in isolation, with misc bytearray()
# payloads (ie. any old str.encode()).  Tests client/server handshake/pairing.
class ECDHTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # The server public key the client would know
        with open(PINServerECDH.STATIC_SERVER_PUBLIC_KEY_FILE, 'rb') as f:
            cls.static_server_public_key = f.read()

    # Make a new client and initialise with server handshake
    def new_client_handshake(self, ske, sig):
        client = PINClientECDH(self.static_server_public_key)
        client.handshake(ske, sig)
        ske1, cke = client.get_key_exchange()
        self.assertEqual(ske, ske1)
        return cke, client

    def _test_client_server_impl(self, client_request, server_response):

        # A new server is created, which signs its newly-created ske with the
        # static key (so the client can validate that the ske is genuine).
        server = PINServerECDH()
        ske, sig = server.get_signed_public_key()

        # They get sent to the client (eg. over network) which then validates
        # and uses the ske along with its own newly-created cke to make the
        # ecdh shared secrets.
        cke, client = self.new_client_handshake(ske, sig)

        # The client can then encrypt a payload (and hmac) for the server
        encrypted, hmac = client.encrypt_request_payload(client_request)
        self.assertNotEqual(client_request, encrypted)

        # The client then sends its cke and this encrypted data and hmac
        # to the server.  The server can use the cke to derive the shared
        # secrets, and can then decrypt the payload.
        # Note: this validates hmac before it decrypts/returns
        server.generate_shared_secrets(cke)
        received = server.decrypt_request_payload(cke, encrypted, hmac)
        self.assertEqual(received, client_request)

        # The server can then send an encrypted response to the client
        encrypted, hmac = server.encrypt_response_payload(server_response)

        # The client can decrypt the response.
        # Note: this validates hmac before it decrypts/returns
        received = client.decrypt_response_payload(encrypted, hmac)
        self.assertEqual(received, server_response)

    def test_client_server_happypath(self):
        for (request, response) in [
                ('REQUEST'.encode(), 'RESPONSE'.encode()),
                ('12345 request string'.encode(), '67890 reply'.encode()),
                (os.urandom(32), os.urandom(64))
        ]:
            with self.subTest(request=request, response=response):
                self._test_client_server_impl(request, response)

    def test_call_with_payload(self):
        # A new server and client
        server = PINServerECDH()
        ske, sig = server.get_signed_public_key()
        cke, client = self.new_client_handshake(ske, sig)

        # Client sends message to server
        client_request = "Hello - test 123".encode()
        encrypted, hmac = client.encrypt_request_payload(client_request)
        self.assertNotEqual(client_request, encrypted)

        # Test server un-/re-wrapping function - this handles all the ecdh
        # decrypting, hmac checking and encrypting/hmac-ing of the response.
        # Hander need know nothing about the wrapping encryption.
        server_response = "Reply to 'test 123' message".encode()

        def _func(client_key, payload, aes_pin_data_key):
            self.assertEqual(client_key, cke)
            self.assertEqual(payload, client_request)
            return server_response

        encrypted, hmac = server.call_with_payload(cke, encrypted, hmac, _func)

        # Assert that is what the client expects
        received = client.decrypt_response_payload(encrypted, hmac)
        self.assertEqual(received, server_response)

    def test_multiple_calls(self):
        # A new server and client
        server = PINServerECDH()
        ske, sig = server.get_signed_public_key()
        cke, client = self.new_client_handshake(ske, sig)

        # Server can handle multiple calls from the client with same secrets
        server.generate_shared_secrets(cke)
        for i in range(5):
            client_request = 'request-{}'.format(i).encode()
            encrypted, hmac = client.encrypt_request_payload(client_request)

            received = server.decrypt_request_payload(cke, encrypted, hmac)
            self.assertEqual(received, client_request)

            server_response = 'response-{}'.format(i).encode()
            encrypted, hmac = server.encrypt_response_payload(server_response)

            received = client.decrypt_response_payload(encrypted, hmac)
            self.assertEqual(received, server_response)

    def test_multiple_clients(self):
        # A new server and several clients
        server = PINServerECDH()
        ske, sig = server.get_signed_public_key()

        # Server can persist and handle multiple calls provided each one is
        # accompanied by its relevant cke for that client and the server
        # regenerates the sharewd secrets each time.
        for i in range(5):
            client_request = 'client-{}-request'.format(i).encode()
            cke, client = self.new_client_handshake(ske, sig)
            encrypted, hmac = client.encrypt_request_payload(client_request)

            server.generate_shared_secrets(cke)
            received = server.decrypt_request_payload(cke, encrypted, hmac)
            self.assertEqual(received, client_request)

            server_response = 'server-response-to-client-{}'.format(i).encode()
            encrypted, hmac = server.encrypt_response_payload(server_response)

            received = client.decrypt_response_payload(encrypted, hmac)
            self.assertEqual(received, server_response)

    def test_bad_request_hmac_throws(self):
        # A new server and client
        server = PINServerECDH()
        ske, sig = server.get_signed_public_key()
        cke, client = self.new_client_handshake(ske, sig)

        # Encrypt message
        client_request = 'bad-hmac-request'.encode()
        encrypted, hmac = client.encrypt_request_payload(client_request)

        # Break hmac
        bad_hmac = bytearray(b+1 if b < 255 else b-1 for b in hmac)
        self.assertNotEqual(hmac, bad_hmac)

        # Ensure decrypt_request() throws
        server.generate_shared_secrets(cke)
        server.decrypt_request_payload(cke, encrypted, hmac)  # no error
        with self.assertRaises(AssertionError) as cm:
            server.decrypt_request_payload(cke, encrypted, bad_hmac)  # error

        # Ensure call_with_payload() throws before it calls the handler fn
        def _func(client_key, payload, aes_pin_data_key):
            self.fail('should-never-get-here')

        with self.assertRaises(AssertionError) as cm:
            server.call_with_payload(cke, encrypted, hmac, _func)

    def test_bad_response_hmac_throws(self):
        # A new server and client
        server = PINServerECDH()
        ske, sig = server.get_signed_public_key()
        cke, client = self.new_client_handshake(ske, sig)

        # Encrypt message
        client_request = 'bad-hmac-request'.encode()
        encrypted, hmac = client.encrypt_request_payload(client_request)

        def _func(client_key, payload, pin_data_aes_key):
            self.assertEqual(client_key, cke)
            self.assertEqual(payload, client_request)
            return 'bad-hmac-response'.encode()

        encrypted, hmac = server.call_with_payload(cke, encrypted, hmac, _func)

        # Break hmac
        bad_hmac = bytearray(b+1 if b < 255 else b-1 for b in hmac)
        self.assertNotEqual(hmac, bad_hmac)

        client.decrypt_response_payload(encrypted, hmac)  # No error
        with self.assertRaises(AssertionError) as cm:
            client.decrypt_response_payload(encrypted, bad_hmac)  # error


if __name__ == '__main__':
    unittest.main()
