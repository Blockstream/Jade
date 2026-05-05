import sys
import types
import unittest

serial_module = types.ModuleType('serial')
serial_module.Serial = object

serialutil_module = types.ModuleType('serial.serialutil')
serialutil_module.SerialException = Exception
serial_module.serialutil = serialutil_module

tools_module = types.ModuleType('serial.tools')
list_ports_module = types.ModuleType('serial.tools.list_ports')
list_ports_module.comports = lambda: []
tools_module.list_ports = list_ports_module

sys.modules.setdefault('serial', serial_module)
sys.modules.setdefault('serial.serialutil', serialutil_module)
sys.modules.setdefault('serial.tools', tools_module)
sys.modules.setdefault('serial.tools.list_ports', list_ports_module)

from jadepy.jade_serial import JadeSerialImpl


class FakeSerial:
    def __init__(self, *, in_waiting, payload):
        self.in_waiting = in_waiting
        self.payload = payload
        self.read_calls = []

    def read(self, n):
        self.read_calls.append(n)
        return self.payload[:n]


class JadeSerialImplReadTest(unittest.TestCase):
    def make_impl(self, fake_serial):
        impl = JadeSerialImpl('/dev/ttyACM0', 115200, 1)
        impl.ser = fake_serial
        return impl

    def test_read_uses_buffered_bytes_instead_of_requested_chunk_size(self):
        fake_serial = FakeSerial(in_waiting=3, payload=b'abc')
        impl = self.make_impl(fake_serial)

        result = impl.read(4096)

        self.assertEqual(result, b'abc')
        self.assertEqual(fake_serial.read_calls, [3])

    def test_read_uses_single_byte_when_no_bytes_are_buffered(self):
        fake_serial = FakeSerial(in_waiting=0, payload=b'z')
        impl = self.make_impl(fake_serial)

        result = impl.read(4096)

        self.assertEqual(result, b'z')
        self.assertEqual(fake_serial.read_calls, [1])
