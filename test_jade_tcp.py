"""Host-only transport tests: python -m unittest test_jade_tcp."""
import socket
import unittest
from unittest.mock import MagicMock, patch

from jadepy.jade import JadeInterface
from jadepy.jade_tcp import JadeTCPImpl


class JadeTCPTests(unittest.TestCase):
    def transport(self, *chunks):
        impl = JadeTCPImpl('tcp:localhost:30121', timeout=0.1)
        impl.tcp_sock = MagicMock()
        # Fail promptly if a read loops past EOF rather than hanging the test.
        impl.tcp_sock.recv.side_effect = [*chunks, AssertionError('read past EOF')]
        return impl

    def test_fragmented_read(self):
        impl = self.transport(b'a', b'bc', b'd')
        self.assertEqual(impl.read(4), b'abcd')
        self.assertFalse(impl.eof)

    def test_clean_eof(self):
        impl = self.transport(b'')
        self.assertEqual(impl.read(4), b'')
        self.assertTrue(impl.eof)

    def test_partial_eof(self):
        impl = self.transport(b'ab', b'')
        self.assertEqual(impl.read(4), b'ab')
        self.assertTrue(impl.eof)

    def test_zero_length_read_is_not_eof(self):
        impl = self.transport(b'')
        self.assertEqual(impl.read(0), b'')
        self.assertFalse(impl.eof)

    def test_socket_timeout(self):
        impl = self.transport(socket.timeout('fixture timeout'))
        with self.assertRaises(socket.timeout):
            impl.read(4)
        self.assertFalse(impl.eof)

    def test_cbor_eof(self):
        interface = JadeInterface(self.transport(b''))
        with self.assertRaises(interface.EOFError):
            interface.read_response()

    def test_cbor_eof_with_long_timeout(self):
        interface = JadeInterface(self.transport(b''))
        with self.assertRaises(interface.EOFError):
            interface.read_response(long_timeout=True)

    def test_long_timeout_still_retries_on_open_stream(self):
        interface = JadeInterface(self.transport())
        reply = {'id': '1', 'result': True}
        with patch.object(interface, 'read_cbor_message',
                          side_effect=[interface.EOFError(), reply]):
            self.assertEqual(interface.read_response(long_timeout=True), reply)

    def test_drain_stops_at_eof(self):
        impl = self.transport(b'')
        JadeInterface(impl).disconnect(drain=True)
        self.assertIsNone(impl.tcp_sock)

    def test_connect_resets_eof(self):
        impl = self.transport(b'')
        impl.read(1)
        impl.disconnect()
        with patch('jadepy.jade_tcp.socket.socket'):
            impl.connect()
        self.assertFalse(impl.eof)


if __name__ == '__main__':
    unittest.main()
