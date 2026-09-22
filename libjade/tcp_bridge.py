"""Bridge a TCP port to a jade instance, so external clients (test suites, tools)
can drive the same instance the GUI is displaying.

Requests are serialised with the caller's mutex (normally the GUI's RPC mutex), so
that the GUI and a bridged client cannot steal each other's replies from the single
underlying connection.
"""
import logging
import socket
import threading

import cbor2 as cbor

logger = logging.getLogger(__name__)


class TcpBridge:
    """Serve a connected jade instance over TCP"""

    def __init__(self, jade, port, mutex=None, host='localhost'):
        """
        jade : JadeAPI
            A connected jade api - its underlying interface is used directly
        port : int
            TCP port to listen on (0 picks a free port)
        mutex : threading.Lock, optional
            Serialises requests with the owner's own calls. Defaults to a new lock
        host : str, optional
            Interface to listen on (defaults to localhost)
        """
        self.jade = jade
        self.port = port
        self.mutex = mutex or threading.Lock()
        self.host = host
        self._sock = None
        self._thread = None

    def start(self):
        """Listen for clients in a background thread. Raises if the port cannot be bound"""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]  # resolve a requested port of 0
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        logger.warning(f'Bridging jade to tcp clients on {self.host}:{self.port} '
                       f'(connect with device "tcp:{self.host}:{self.port}")')

    def stop(self):
        """Stop listening (does not disconnect connected clients)"""
        if self._sock:
            self._sock.close()
            self._sock = None

    def _serve(self):
        while self._sock:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                return  # stop() closed the listening socket
            logger.info(f'Bridge client connected from {addr}')
            try:
                self._serve_client(conn)
            except Exception as e:  # a client can disconnect at any point
                logger.info(f'Bridge client finished: {e}')
            finally:
                conn.close()

    def _serve_client(self, conn):
        with conn.makefile('rwb') as stream:
            while True:
                request = cbor.load(stream)  # raises at EOF (or on garbage)
                if not isinstance(request, dict) or 'method' not in request or 'id' not in request:
                    raise ValueError(f'invalid request from bridge client: {request!r}')

                # Use the interface directly (bypassing the api's own locking), holding
                # the shared mutex so the owner's calls cannot interleave with ours
                with self.mutex:
                    self.jade.jade.write_request(request)
                    reply = self.jade.jade.read_response()

                stream.write(cbor.dumps(reply))
                stream.flush()
