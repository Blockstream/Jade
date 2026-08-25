from . import *


@with_test_cases('tests/rpc/data/bip85/bip85_bip39_*.json')
def test_bip85_bip39_encrypted_entropy(jade, test_case):
    # Get the Jade test mnemonic master key locally so we can verify the
    # bip85_bip39 entropy returned from jade with libwally
    # Test cases generated with: https://github.com/ethankosakovsky/bip85
    seed = wally.bip39_mnemonic_to_seed512(mnemonics.default, None)
    local_master_key = wally.bip32_key_from_seed(seed, wally.BIP32_VER_MAIN_PRIVATE, 0)
    label = 'bip85_bip39_entropy'.encode()

    for nwords, index, expected_mnemonic in test_case:
        # get new ephemeral key
        while True:
            try:
                privkey = os.urandom(32)
                wally.ec_private_key_verify(privkey)
                break
            except Exception:
                pass

        pubkey = wally.ec_public_key_from_private_key(privkey)

        # Get encrypted bip85 bip39 data from Jade
        rslt = jade.get_bip85_bip39_entropy(nwords, index, pubkey)
        jade_entropy = wally.aes_cbc_with_ecdh_key(privkey, None, rslt['encrypted'],
                                                   rslt['pubkey'], label, wally.AES_FLAG_DECRYPT)

        # Check against libwally when calculated locally
        expected_entropy = wally.bip85_get_bip39_entropy(local_master_key, None, nwords, index)
        assert jade_entropy == expected_entropy

        # Check against explicit mnemonic words if passed
        if expected_mnemonic:
            jade_mnemonic = wally.bip39_mnemonic_from_bytes(None, jade_entropy)
            assert jade_mnemonic == expected_mnemonic


@with_test_cases('tests/rpc/data/bip85/bip85_rsa.json')
def test_bip85_rsa_encrypted_entropy(jade, test_case):
    # Test vector generated using
    # https://github.com/akarve/bipsea/blob/main/tests/test_bip85.py#L127
    # modified to use our own TEST_MNEMONIC and 1024 to 8192 keys
    label = 'bip85_rsa_entropy'.encode()

    for entropy, key_bits, index in test_case:
        # get new ephemeral key
        while True:
            try:
                privkey = os.urandom(32)
                wally.ec_private_key_verify(privkey)
                break
            except Exception:
                pass

        pubkey = wally.ec_public_key_from_private_key(privkey)

        # Get encrypted bip85 rsa entropy from Jade
        rslt = jade.get_bip85_rsa_entropy(key_bits, index, pubkey)
        jade_entropy = wally.aes_cbc_with_ecdh_key(privkey, None, rslt['encrypted'],
                                                   rslt['pubkey'], label, wally.AES_FLAG_DECRYPT)
        assert jade_entropy == entropy


@with_test_cases('tests/rpc/data/bip85/bip85_rsa_pubkey.json')
def test_bip85_rsa_pubkey(jade, test_case):
    # Index chosen so as not to take too long, even on jade v1 hw
    INDEX = 'Index: '
    KEYLEN = 'Key bits: '
    KEY_START = '-----BEGIN PUBLIC KEY-----'
    KEY_END = '-----END PUBLIC KEY-----'
    EOL = '\n'

    for testcase_file in test_case:
        # Get test case inputs and expected key from the test file
        with open(testcase_file, 'r') as f:
            filedata = f.read()

        index = filedata.index(INDEX) + len(INDEX)
        index = int(filedata[index:filedata.index(EOL, index)])

        keylen = filedata.index(KEYLEN) + len(KEYLEN)
        keylen = int(filedata[keylen:filedata.index(EOL, keylen)])

        pemstart = filedata.index(KEY_START)
        pemend = filedata.index(KEY_END) + len(KEY_END)
        expected_pubkey_pem = filedata[pemstart:pemend] + EOL

        # Get bip85 rsa pubkey from Jade and check matches
        rslt = jade.get_bip85_pubkey('RSA', keylen, index)
        assert rslt == expected_pubkey_pem


@with_test_cases('tests/rpc/data/bip85/bip85_rsa_signing.json')
def test_bip85_rsa_signing(jade, test_case):
    # Testvectors index chosen so as not to take too long, even on jade v1 hw
    for keylen, index, digests, expected in test_case:
        assert len(digests) == len(expected)
        sigs = jade.sign_bip85_digests('RSA', keylen, index, digests)
        assert sigs == expected


@pytest.mark.parametrize('key_bits, num_digests', [(2048, 9), (4096, 5)])
def test_sign_bip85_digests_too_many(jade, key_bits, num_digests):
    # 2048-bit keys support at most 8 digests, 4096-bit keys at most 4; send
    # one more than the maximum for each size
    try:
        jade.sign_bip85_digests('RSA', key_bits, 0, [bytes(32)] * num_digests)
        assert False, 'Expected error for oversized digests array'
    except JadeError as e:
        assert e.code == JadeError.BAD_PARAMETERS, e
        assert e.message == 'Unsupported number of digests', e.message
