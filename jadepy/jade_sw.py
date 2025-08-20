from ctypes import CDLL, POINTER, c_ubyte, c_size_t, byref
import logging
from .jade_error import JadeError


logger = logging.getLogger(__name__)

try:
    _libjade = CDLL('libjade.so')
    _libjade.libjade_receive.restype = POINTER(c_ubyte)
except Exception as _:
    raise ImportError  # libjade.so not available


#
# Experimental, internal, in-process interface to Jade
# Intended for use via JadeInterface wrapper.
#
# Use via JadeInterface.create_libjade() (see JadeInterface)
#
class JadeSoftwareImpl:

    _log_levels = {
        logging.DEBUG: 1,
        logging.INFO: 2,
        logging.WARNING: 3,
        logging.ERROR: 4,
        logging.CRITICAL: 5,  # Note we have no critical logs
        logging.NOTSET: 5  # Default to critical (i.e. no logging)
    }

    def __init__(self, timeout):
        self.timeout = timeout
        self.libjade = None
        self.msg = None  # Bytes of the current message being read, if any

    def connect(self):
        assert self.libjade is None
        self.libjade = _libjade
        # Respect the python log level for Jade logging
        log_level = self._log_levels[logger.getEffectiveLevel()]
        self.libjade.libjade_set_log_level(log_level)
        # Starts the firmware in a separate thread
        self.libjade.libjade_start()
        logger.info('Connected to in-process software Jade')

    def disconnect(self):
        assert self.libjade is not None
        self.libjade.libjade_stop()
        self.libjade = None

    def write(self, bytes_):
        assert self.libjade is not None
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f'Pushing {bytes_.hex()}\n')
        # The software interface takes the whole message in one go
        num_bytes = len(bytes_)
        if not self.libjade.libjade_send(bytes_, num_bytes):
            raise JadeError(1, f'Failed to send {num_bytes} bytes', None)
        return num_bytes  # Let the caller know we wrote all bytes

    def read(self, n):
        assert self.libjade is not None
        if n == 0:
            # Sometimes read is called with 0 bytes.
            # Treat this as a no-op.
            logger.debug('Read of 0 bytes requested')
            return bytes()

        if not self.msg:
            # The software interface reads the whole message in one go.
            # Fetch it here, then return it in chunks below
            logger.debug(f'Calling libjade_receive() with timeout {self.timeout}\n')
            bytes_len = c_size_t()
            buff = self.libjade.libjade_receive(self.timeout, byref(bytes_len))
            if not buff:
                logger.debug('Timeout calling libjade_receive()\n')
                return bytes()
            self.msg = bytes([buff[i] for i in range(bytes_len.value)])
            self.libjade.libjade_release(buff)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f'Received message {self.msg.hex()}\n')

        # Return as much of the message as the caller asked for
        ret = self.msg[:n]
        self.msg = self.msg[n:]
        if False and logger.isEnabledFor(logging.DEBUG):
            # Not generally useful unless debugging serialization failures
            logger.debug(f'Returning {ret.hex()} leaving {self.msg.hex()}')
        elif not self.msg:
            logger.debug('Message consumed')
        return ret
