from . import *


class JadeConfig:
    """A jade connection and its config."""

    def __init__(self, config):
        """Initialize a Jade connection from pytest config options."""
        def opt(name):
            return config.getoption(name)
        self.device = opt('--device')
        self.timeout = opt('--timeout')
        self.ble_device_name = opt('--ble-device-name')
        self.ble_serial_number = opt('--ble-serial-number')
        self.ble_scan_timeout = opt('--ble-scan-timeout')
        self.no_legacy_flow = opt('--no-legacy-flow')
        self.passkey_file = 'ble_test_passkey.txt'

        self.btagent = None
        self.current_mnemonic = None

        self.transport = 'serial'
        if opt('--libjade'):
            self.transport = 'libjade'
        elif opt('--ble'):
            self.transport = 'ble'

        self.jade = self._create_api()
        self.jade.connect()
        self.version_info = self.jade.get_version_info()
        self.has_psram = self.version_info['JADE_FREE_SPIRAM'] > 0
        self.has_ble = self.version_info['JADE_CONFIG'] == 'BLE'
        self.set_mnemonic(mnemonics.default)

    def _create_api(self):
        """Helper to create the jade instance."""
        if self.transport == 'serial':
            return JadeAPI.create_serial(device=self.device, timeout=self.timeout)

        if self.transport == 'libjade':
            return JadeAPI.create_libjade(timeout=self.timeout)

        # BLE
        if self.ble_device_name is None and self.ble_serial_number is None:
            # No device/serial given: get from local serial port
            with JadeAPI.create_serial(device=self.device, timeout=self.timeout) as jade:
                self.ble_serial_number = jade.get_version_info()['EFUSEMAC'][6:]
        elif self.ble_serial_number is not None:
            self.ble_serial_number = str(self.ble_serial_number)

        self.ble_start_agent()
        return JadeAPI.create_ble(
            device_name=self.ble_device_name,
            serial_number=self.ble_serial_number,
            scan_timeout=self.ble_scan_timeout,
        )

    def set_mnemonic(self, mnemonic):
        """Set the current jade mnemonic (with caching)."""
        if mnemonic != self.current_mnemonic:
            # mnemonic differs from the one currently set: change and remember it
            rslt = self.jade.set_mnemonic(mnemonic)
            assert rslt is True
            self.current_mnemonic = mnemonic
            # invalidate seed
            self.current_seed = None
        time.sleep(1)

    def set_seed(self, seed):
        """Set the current Jade seed."""
        # reset the jade
        rslt = self.jade.clean_reset()
        assert rslt is True
        # set seed
        rslt = self.jade.set_seed(bytes.fromhex(seed))
        assert rslt is True
        # invalidate mnemonic
        self.current_mnemonic = None
        time.sleep(1)

    def disconnect(self):
        """Disconnect the jade instance."""
        self.jade.disconnect()
        self.jade = None
        self.ble_stop_agent()

    def ble_start_agent(self):
        command = ['/usr/bin/bt-agent', '-c', 'DisplayYesNo', '-p', self.passkey_file]
        self.btagent = subprocess.Popen(command, shell=False, stdout=subprocess.DEVNULL)
        logger.info(f'Started bt-agent pid {btagent.pid} passkey {self.passkey_file}')

    def ble_stop_agent(self):
        if self.btagent:
            command = f'kill -HUP {self.btagent.pid}'
            subprocess.run(command, shell=True, stdout=subprocess.DEVNULL)
            logger.info(f'Stopped bt-agent pid {btagent.pid}')
            self.btagent = None


#
# PyTest hooks
#
def pytest_addoption(parser):
    # pytest: add test configration options
    parser.addoption(
        '--device',
        default='/dev/ttyACM0',
        help='Serial device for Jade (for example /dev/ttyACM0).',
    )
    parser.addoption(
        '--timeout',
        type=int,
        default=240,
        help='Connection timeout in seconds.',
    )
    parser.addoption(
        '--libjade',
        action='store_true',
        help='Use in-process libjade instead of serial transport.',
    )
    parser.addoption(
        '--ble',
        action='store_true',
        help='Use Bluetooth transport instead of serial transport.',
    )
    parser.addoption(
        '--ble-serial-number',
        type=str,
        default=None,
        help='BLE serial number to disambiguate multiple devices.',
    )
    parser.addoption(
        '--ble-device-name',
        default=None,
        help='BLE device name to scan for.',
    )
    parser.addoption(
        '--ble-scan-timeout',
        type=int,
        default=60,
        help='BLE scan timeout in seconds.',
    )
    parser.addoption(
        '--no-legacy-flow',
        action='store_true',
        default=False,
        help='Do not use the legacy sign_tx flow (use the AE flow instead)',
    )


def _remove_pin_files():
    """Helper to remove pinserver .pin files from testing"""
    for f in glob.glob("./*.pin"):
        os.remove(f)


def pytest_configure(config):
    # pytest: global test initialization
    config.addinivalue_line('markers',
                            'mnemonic(value): set a custom Jade mnemonic before the test')
    config.addinivalue_line('markers',
                            'seed(value): set a custom Jade seed before the test')
    set_jade_config(JadeConfig(config))
    _remove_pin_files()


def pytest_unconfigure(config):
    # pytest: global test teardown
    if get_jade_config():
        get_jade_config().disconnect()
    _remove_pin_files()


def _get_test_mnemonic(item):
    """Helper to fetch the mnemonic used by a test_ function."""
    marker = item.get_closest_marker('mnemonic')
    return marker.args[0] if marker and marker.args else ''


def _get_test_seed(item):
    """Helper to fetch the seed used by a test_ function."""
    marker = item.get_closest_marker('seed')
    return marker.args[0] if marker and marker.args else ''


def pytest_collection_modifyitems(session, config, items):
    # pytest: Re-order tests so tests using the same mnemonic run together,
    # which allows us to avoid resetting the mnemonic for every test.
    items.sort(key=_get_test_mnemonic)


#
# Test fixtures
#
@pytest.fixture(scope="session")
def jade(request):
    """Fixture for providing a connected jadepy instance.
       Add 'jade' as an argument to any test function to use it."""
    return get_jade_config().jade


@pytest.fixture(scope="function")
def mnemonic(request):
    """Fixture for testing with a mnemonic other than the default.
       Add 'mnemonic' as an argument to any test function to use it,
       and give the mnemonic to use as a pytest mark, e.g.:
       @pytest.mark.mnemonic(mnemonics.singlesig)
    """
    s = _get_test_seed(request.node)
    if s == '':  # no seed, set mnemonic
        m = _get_test_mnemonic(request.node) or mnemonics.default
        get_jade_config().jade.set_mnemonic(m)
    else:  # if there is seed ignore mnemonic and set seed
        get_jade_config().set_seed(s)
