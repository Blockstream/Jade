from . import *
import socket
from unittest.mock import MagicMock, patch

from jadepy.jade import JadeInterface
from jadepy.jade_tcp import JadeTCPImpl


def _tcp_transport(*chunks):
    impl = JadeTCPImpl('tcp:localhost:30121', timeout=0.1)
    impl.tcp_sock = MagicMock()
    # Fail promptly if a read loops past EOF rather than hanging the test.
    impl.tcp_sock.recv.side_effect = [*chunks, AssertionError('read past EOF')]
    return impl


def test_fragmented_read():
    impl = _tcp_transport(b'a', b'bc', b'd')
    assert impl.read(4) == b'abcd'
    assert not impl.eof


def test_clean_eof():
    impl = _tcp_transport(b'')
    assert impl.read(4) == b''
    assert impl.eof


def test_partial_eof():
    impl = _tcp_transport(b'ab', b'')
    assert impl.read(4) == b'ab'
    assert impl.eof


def test_zero_length_read_is_not_eof():
    impl = _tcp_transport(b'')
    assert impl.read(0) == b''
    assert not impl.eof


def test_socket_timeout():
    impl = _tcp_transport(socket.timeout('fixture timeout'))
    with pytest.raises(socket.timeout):
        impl.read(4)
    assert not impl.eof


def test_cbor_eof():
    interface = JadeInterface(_tcp_transport(b''))

    for long_timeout in [False, True]:
        with pytest.raises(interface.EOFError):
            interface.read_response()


def test_long_timeout_still_retries_on_open_stream():
    interface = JadeInterface(_tcp_transport())
    reply = {'id': '1', 'result': True}
    with patch.object(interface, 'read_cbor_message',
                      side_effect=[interface.EOFError(), reply]):
        assert interface.read_response(long_timeout=True) == reply


def test_drain_stops_at_eof():
    impl = _tcp_transport(b'')
    JadeInterface(impl).disconnect(drain=True)
    assert impl.tcp_sock is None


def test_connect_resets_eof():
    impl = _tcp_transport(b'')
    impl.read(1)
    impl.disconnect()
    with patch('jadepy.jade_tcp.socket.socket'):
        impl.connect()
    assert not impl.eof
