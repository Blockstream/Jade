from . import *

from contextlib import contextmanager
from pinserver.pindb import PINDb
from pinserver.server import PINServerECDHv2


TEST_PIN = 234567
TEST_PIN_NEW = 765432
URL_A = 'https://oracle-a.test'
URL_B = 'http://oracle-b.test'
MOVED_URL_A = 'https://moved-oracle-a.test'
MOVED_URL_B = 'http://moved-oracle-b.test'
CERTIFICATE = 'test oracle certificate'
MOVED_CERTIFICATE = 'moved test oracle certificate'
DEFAULT_URLS = [
    'https://j8d.io',
    'http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion',
]


class MemoryStorage:
    """Replacement for FileStorage storing pinserver records in memory"""

    def __init__(self):
        self.data = {}

    def get(self, key):
        if key not in self.data:
            # Raise FileNotFoundError for a missing record, as FileStorage does
            raise FileNotFoundError(2, 'No record found', key.hex())
        return self.data[key]

    def set(self, key, data):
        self.data[key] = data

    def exists(self, key):
        return key in self.data

    def remove(self, key):
        if key not in self.data:
            # Raise FileNotFoundError for a missing record, as FileStorage does
            raise FileNotFoundError(2, 'No record found', key.hex())
        del self.data[key]


def _server_public_key():
    PINServerECDHv2.load_private_key()
    return wally.ec_public_key_from_private_key(PINServerECDHv2.STATIC_SERVER_PRIVATE_KEY)


def _set_debug_pin(jade, pin, new_pin=None):
    params = {'pin': pin}
    if new_pin is not None:
        params['new_pin'] = new_pin
    return jade._jadeRpc('debug_set_pin', params)


@contextmanager
def _pin_lifecycle(jade):
    # Temporarily replace file I/O of PINDb with in-memory storage, restoring it on context exit
    with pytest.MonkeyPatch.context() as patch:
        try:
            # Clear Jade's wallet and PIN state before the test
            assert jade.clean_reset() is True

            # Keep pinserver records in a fresh in-memory database for this test
            storage = MemoryStorage()
            patch.setattr(PINDb, 'storage', storage)
            PINServerECDHv2.load_private_key()

            # Let the test use Jade and inspect its pinserver records
            yield jade, storage
        finally:
            # Try each cleanup step even if an earlier RPC fails
            try:
                _set_debug_pin(jade, 12345)
            finally:
                jade.clean_reset()


@pytest.fixture
def pin_lifecycle(jade):
    with _pin_lifecycle(jade) as lifecycle:
        yield lifecycle


class PINServerRecorder:
    """Wrapper around PINServerECDHv2 with parameter validation and call recording"""

    def __init__(self, urls, certificate):
        self.urls = urls
        self.certificate = certificate
        self.calls = []
        self.client_pubkeys = []

    def request(self, params):
        assert params['method'] == 'POST'
        assert params['accept'] == 'json'
        endpoint = params['urls'][0].rsplit('/', 1)[1]
        assert endpoint in ('set_pin', 'get_pin')
        assert params['urls'] == [f'{url}/{endpoint}' for url in self.urls]
        if self.certificate is None:
            assert 'root_certificates' not in params
        else:
            assert params['root_certificates'] == [self.certificate]

        # Handle Jade's HTTP request in-process with a fresh PINServerECDHv2 protocol handler.
        # The static server private key is shared, and _pin_lifecycle provides shared MemoryStorage
        # to persist PIN records between requests within the lifecycle context.

        # Decode the ephemeral client pubkey (33 bytes), counter (4 bytes) and encrypted payload
        data = base64.b64decode(params['data']['data'])
        cke, replay_counter, encrypted_data = data[:33], data[33:37], data[37:]
        server = PINServerECDHv2(replay_counter, cke)

        # Record the client pubkey recovered from the signature for later identity checks
        payload = server.decrypt_request_payload(cke, encrypted_data)
        _, _, client_pubkey = PINDb._extract_fields(cke, payload, replay_counter)
        self.calls.append(endpoint)
        self.client_pubkeys.append(client_pubkey)

        # Process the request through PINDb and encrypt AES key with an ECDH-derived response key
        handler = PINDb.set_pin if endpoint == 'set_pin' else PINDb.get_aes_key
        encrypted_key = server.call_with_payload(cke, encrypted_data, handler)
        return {'body': {'data': base64.b64encode(encrypted_key).decode()}}


@pytest.fixture
def pin_test_setup(pin_lifecycle):
    """Provide wallet with a default test PIN, storage and pinserver"""
    jade, storage = pin_lifecycle
    assert _set_debug_pin(jade, TEST_PIN) is True
    assert jade.set_pinserver(URL_A, URL_B, _server_public_key(), CERTIFICATE) is True
    assert jade.set_mnemonic(mnemonics.default) is True
    pinserver = PINServerRecorder([URL_A, URL_B], CERTIFICATE)
    assert jade.auth_user('testnet', http_request_fn=pinserver.request) is True
    assert pinserver.calls == ['set_pin']
    return jade, storage, pinserver


def test_pin_requires_auth_user(jade):
    request = jade.jade.build_request('pin_no_auth', 'pin', {'data': 'unused'})
    reply = jade.jade.make_rpc_call(request)
    assert reply['id'] == 'pin_no_auth'
    assert 'result' not in reply
    assert reply['error']['code'] == JadeError.PROTOCOL_ERROR
    assert reply['error']['message'] == 'Unexpected method'


@pytest.mark.mnemonic(mnemonics.reset)
def test_bad_pin(pin_test_setup):
    """Check that Jade rejects bad PINs passed to 'debug_set_pin'"""
    jade, storage, _ = pin_test_setup
    database_keys = set(storage.data)
    assert jade.logout() is True

    for bad_pins in [
        {'pin': 1000000},                    # Default pin too large
        {'pin': 123456, 'new_pin': 1000000}  # New pin too large
    ]:
        request = jade.jade.build_request('bad_debug_pin', 'debug_set_pin', bad_pins)
        reply = jade.jade.make_rpc_call(request)
        assert reply['error']['code'] == JadeError.BAD_PARAMETERS
        assert 'result' not in reply


# Covers the checks Jade makes when reading the pinserver's reply
MALFORMED_PINSERVER_REPLIES = [
    (None, 'Failed to read parameters from Oracle'),
    ({}, 'data field missing'),
    ({'data': ''}, 'data field missing'),
    ({'data': 'not base64!'}, 'data field invalid'),
    ({'data': base64.b64encode(b'short').decode()}, 'data field invalid'),
    ({'data': base64.b64encode(bytes(96)).decode()}, 'Failed to decrypt payload'),
]


@pytest.mark.mnemonic(mnemonics.reset)
def test_malformed_pinserver_reply(pin_lifecycle):
    jade, _ = pin_lifecycle
    for body, expected_message in MALFORMED_PINSERVER_REPLIES:
        assert jade.set_mnemonic(mnemonics.default) is True

        def malformed_reply(params):
            assert params['urls'] == [f'{url}/set_pin' for url in DEFAULT_URLS]
            assert 'root_certificates' not in params
            return {'body': body}

        with pytest.raises(JadeError) as excinfo:
            jade.auth_user('testnet', http_request_fn=malformed_reply)
        assert excinfo.value.code == JadeError.BAD_PARAMETERS
        assert excinfo.value.message == expected_message


@pytest.mark.mnemonic(mnemonics.reset)
def test_pinserver_settings_reset(pin_lifecycle):
    """Check that 'auth_user' uses custom URLs and certificates until they are reset"""
    jade, _ = pin_lifecycle
    pubkey = _server_public_key()
    assert jade.set_pinserver(URL_A, URL_B, pubkey, CERTIFICATE) is True
    assert jade.set_mnemonic(mnemonics.default) is True
    requests = []

    def abort(params):
        """Return an invalid reply so we can inspect the request without setting a PIN"""
        requests.append(params)
        return {'body': None}

    with pytest.raises(JadeError):
        jade.auth_user('testnet', http_request_fn=abort)
    assert requests[0]['urls'] == [f'{URL_A}/set_pin', f'{URL_B}/set_pin']
    assert requests[0]['root_certificates'] == [CERTIFICATE]
    assert jade.reset_pinserver(reset_details=True, reset_certificate=True) is True
    assert jade.logout() is True
    assert jade.set_mnemonic(mnemonics.default) is True
    requests.clear()
    with pytest.raises(JadeError):
        jade.auth_user('testnet', http_request_fn=abort)
    assert requests[0]['urls'] == [f'{url}/set_pin' for url in DEFAULT_URLS]
    assert 'root_certificates' not in requests[0]


@pytest.mark.mnemonic(mnemonics.reset)
def test_initial_wallet_setup_uses_current_debug_pin(pin_lifecycle):
    """Verify 'new_pin' doesn't override the current debug 'pin' during initial wallet setup"""
    jade, _ = pin_lifecycle
    assert _set_debug_pin(jade, TEST_PIN, TEST_PIN_NEW) is True
    assert jade.set_pinserver(URL_A, URL_B, _server_public_key(), CERTIFICATE) is True
    assert jade.set_mnemonic(mnemonics.default) is True
    pinserver = PINServerRecorder([URL_A, URL_B], CERTIFICATE)
    assert jade.auth_user('testnet', http_request_fn=pinserver.request) is True
    assert pinserver.calls == ['set_pin']

    assert _set_debug_pin(jade, TEST_PIN) is True
    assert jade.logout() is True
    pinserver = PINServerRecorder([URL_A, URL_B], CERTIFICATE)
    assert jade.auth_user('testnet', http_request_fn=pinserver.request) is True
    assert pinserver.calls == ['get_pin']


def _unlock_with_pinserver(jade, storage, urls, certificate, client_pubkey, database_keys, xpub):
    """Verify pinserver with explicitly provided settings can unlock the given wallet"""
    assert jade.logout() is True
    pinserver = PINServerRecorder(urls, certificate)
    assert jade.auth_user('testnet', http_request_fn=pinserver.request) is True
    assert pinserver.calls == ['get_pin']
    assert pinserver.client_pubkeys == [client_pubkey]
    assert set(storage.data) == database_keys
    assert jade.get_xpub('testnet', []) == xpub


@pytest.mark.mnemonic(mnemonics.reset)
def test_pin_unlock_after_pinserver_updates(pin_test_setup):
    """Check unlock after updating PIN, URL, certificate and Oracle key"""
    jade, storage, pinserver = pin_test_setup
    pubkey = _server_public_key()
    client_pubkey = pinserver.client_pubkeys[-1]
    database_keys = set(storage.data)
    assert len(database_keys) == 1
    xpub = jade.get_xpub('testnet', [])
    _unlock_with_pinserver(jade, storage, [URL_A, URL_B], CERTIFICATE, client_pubkey,
                           database_keys, xpub)

    assert _set_debug_pin(jade, TEST_PIN, TEST_PIN_NEW) is True
    assert jade.logout() is True
    pinserver = PINServerRecorder([URL_A, URL_B], CERTIFICATE)
    assert jade.auth_user('testnet', http_request_fn=pinserver.request) is True
    assert pinserver.calls == ['get_pin', 'set_pin']
    assert pinserver.client_pubkeys == [client_pubkey, client_pubkey]
    assert set(storage.data) == database_keys

    # Reject the old PIN but keep the wallet and pinserver record for the next attempt
    assert _set_debug_pin(jade, TEST_PIN) is True
    assert jade.logout() is True
    pinserver = PINServerRecorder([URL_A, URL_B], CERTIFICATE)
    assert jade.auth_user('testnet', http_request_fn=pinserver.request) is False
    assert pinserver.calls == ['get_pin']
    assert pinserver.client_pubkeys == [client_pubkey]
    assert set(storage.data) == database_keys
    assert jade.get_version_info()['JADE_STATE'] == 'LOCKED'
    with pytest.raises(JadeError) as excinfo:
        jade.get_xpub('testnet', [])
    assert excinfo.value.code == JadeError.HW_LOCKED

    assert _set_debug_pin(jade, TEST_PIN_NEW) is True
    _unlock_with_pinserver(jade, storage, [URL_A, URL_B], CERTIFICATE, client_pubkey,
                           database_keys, xpub)

    updates = [
        (lambda: jade.set_pinserver(MOVED_URL_A, MOVED_URL_B),
         [MOVED_URL_A, MOVED_URL_B], CERTIFICATE),
        (lambda: jade.set_pinserver(cert=MOVED_CERTIFICATE),
         [MOVED_URL_A, MOVED_URL_B], MOVED_CERTIFICATE),
        (lambda: jade.set_pinserver(URL_A, URL_B, cert=CERTIFICATE),
         [URL_A, URL_B], CERTIFICATE),
        (lambda: jade.set_pinserver(MOVED_URL_A, MOVED_URL_B, pubkey=pubkey),
         [MOVED_URL_A, MOVED_URL_B], CERTIFICATE),
    ]
    for update, urls, certificate in updates:
        assert update() is True
        _unlock_with_pinserver(jade, storage, urls, certificate, client_pubkey, database_keys, xpub)

    # Changing the public key of pinserver is forbidden once the wallet has a PIN
    replacement_pubkey = wally.ec_public_key_from_private_key(bytes(31) + b'\x02')
    assert replacement_pubkey != pubkey
    with pytest.raises(JadeError) as excinfo:
        jade.set_pinserver(URL_A, URL_B, replacement_pubkey, CERTIFICATE)
    assert excinfo.value.code == JadeError.BAD_PARAMETERS
    assert excinfo.value.message == 'Cannot update initialized unit'

    # A rejected key change must preserve the previous settings, identity and wallet
    _unlock_with_pinserver(jade, storage, [MOVED_URL_A, MOVED_URL_B], CERTIFICATE, client_pubkey,
                           database_keys, xpub)


@pytest.mark.mnemonic(mnemonics.reset)
def test_pin_retry_limit(pin_test_setup):
    """Check that three consecutive wrong PINs erase the wallet and pinserver record"""
    jade, storage, _ = pin_test_setup
    assert len(storage.data) == 1
    assert jade.logout() is True
    assert _set_debug_pin(jade, 999999) is True
    for attempt in range(3):
        pinserver = PINServerRecorder([URL_A, URL_B], CERTIFICATE)
        assert jade.auth_user('testnet', http_request_fn=pinserver.request) is False
        assert pinserver.calls == ['get_pin']
        state = jade.get_version_info()['JADE_STATE']
        if attempt < 2:
            assert state == 'LOCKED'
            assert len(storage.data) == 1
        else:
            assert state == 'UNINIT'
            assert not storage.data
