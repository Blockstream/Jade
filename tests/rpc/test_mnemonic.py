from . import *


TEST_MNEMONIC_12 = 'retire verb human ecology best member fiction measure \
demand stereo wedding olive'

TEST_MNEMONIC_PREFIXES = 'fish inne face gin orc perm usef meth fen kidn chuc \
part fav suns draw limb scie cran ova let slot invi sadn bana'

# 'can' and 'net' are ambiguous prefixes, but are an exact match to words in
# the bip39-wordlist, so should be recognised/allowed.
TEST_MNEMONIC_PREFIXES_EXACT_MATCH = 'recy wear club hurr indu floa cust gua \
ae plan scan carr elec reco acco stoc insp net ups can opt brie guid priv'

# One word (met) prefix is not unambiguous: met => metal, method
TEST_MNEMONIC_PREFIXES_AMBIGUOUS = 'fish inne face gin orc perm usef met fen \
kidn chuc part fav suns draw limb scie cran ova let slot invi sadn bana'

# Seedsigner styles for our test mnemonic
TEST_MNEMONIC_SEEDSIGNER = '0701093106520784124813051919112106800979032412840\
67217400531103815430402126110281632094415190145'
TEST_MNEMONIC_SEEDSIGNER_COMPACT = b'W\xae\x8dF1\t\xc1F{\xfcaU\x0fL\xa2PEA\xb3\
\x10\x9c\x0e\xc0\xe6Jv\xc0L\xc0\xec/x'

# bcur bip39 style for our test mnemonic
TEST_MNEMONIC_BCUR_BIP39_LOWER = 'ur:crypto-bip39/oeadlkiyjkisinihjzieihiojpjl\
kpjoihihjpjlieihihhskthsjeihiejzjliajeiojkhskpjkhsioihieiahsjkisihiojzhsjpihie\
kthskoihieiajpihktihiyjzhsjnihihiojzjlkoihaoidihjtrkkndede'
TEST_MNEMONIC_BCUR_BIP39_UPPER = 'UR:CRYPTO-BIP39/OEADLKIYJKISINIHJZIEIHIOJPJL\
KPJOIHIHJPJLIEIHIHHSKTHSJEIHIEJZJLIAJEIOJKHSKPJKHSIOIHIEIAHSJKISIHIOJZHSJPIHIE\
KTHSKOIHIEIAJPIHKTIHIYJZHSJNIHIHIOJZJLKOIHAOIDIHJTRKKNDEDE'
# bcur-bip39 mnemonic that has too many (32) words
TEST_MNEMONIC_BCUR_BIP39_TOO_MANY = 'ur:crypto-bip39/oeadmkcxis\
jyjljpjyjlinjkihis' * 31 + 'jyjljpjyjlinjkihaoidihjtsgfpvooe'
# bcur-bip39 mnemonic that has too few (11) words
TEST_MNEMONIC_BCUR_BIP39_TOO_FEW = 'ur:crypto-account/1-5/lpadahcshecygmzcbdca\
guoeadluiohsidhsjtiejljtiohsidhsjtiejljtzsmeoelb'
# bcur-bip39 mnemonic, the last word is abandoned which is 9 chars
TEST_MNEMONIC_BCUR_BIP39_LONG_WORD = 'ur:crypto-account/1-5/lpadahcsincyrkgosr\
cegooeadlkiohsidhsjtiejljtiohsidhsjtiejljtiohsintbwscw'
TEST_MNEMONIC_BCUR_BIP39_EMPTY_WORD = 'ur:crypto-account/1-5/lpadahcshncysavwc\
sdighoeadlkiohsidhsjtiejljtiohsidhsjtiejljtiocpcxtnnd'


TEST_MNEMONIC_BCUR_BIP39_STRING = 'shield group erode awake lock sausage \
cash glare wave crew flame glove'


# Seedsigner's own test vectors
# See: https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md
SEEDSIGNER_MNEMONIC_TEST_VECTORS = [
  # 24-word
  ('attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony \
ranch winter theme error hybrid van cereal salon goddess expire',
   '0115132511540127119007710415074212891906200808700266134314202016179206140896192903001524080\
10643',
   b'\x0et\xb6A\x07\xf9L\xc0\xcc\xfa\xe6\xa1=\xcb\xec6b\x15O\xecg\xe0\xe0\t\x99\xc0x\x92Y}\x19\n'),
  ('atom solve joy ugly ankle message setup typical bean era cactus various odor refuse element \
afraid meadow quick medal plate wisdom swap noble shallow',
   '0114165509641888007311191572188701560610025619321225144305730036110114051106132920181754119\
71576',
   b"\x0eY\xdd\xe2v\x00\x93\x17\xf1'_\x13\x89\x88\x80x\xc9\x93h\xd1\xe8$\x89\xb5\xf6)S\x1f\xc5\
\xb6\xa5n"),
  ('sound federal bonus bleak light raise false engage round stock update render quote truck \
quality fringe palace foot recipe labor glow tortoise potato still',
   '1662067502030188103614170658059415071712190814561408186514010744127307271437099407981836135\
01710',
   b'\xcf\xca\x8ce\x8b\xc8\x19bT\x92R\xbcz\xc3\xba[\x0b\x01\xd2k\xca\xe8\x9f+^\xce\xbe&=\xcb*6'),
  # 12-word
  ('forum undo fragile fade shy sign arrest garment culture tube off merit',
   '073318950739065415961602009907670428187212261116',
   b'[\xbd\x9dq\xa8\xecy\x90\x83\x1a\xff5\x9dBeE'),
  ('good battle boil exact add seed angle hurry success glad carbon whisper',
   '080301540200062600251559007008931730078802752004',
   b"dbhd' 3\x85\xc23}\xd8LP\x89\xfd"),
  ('approve fruit lens brass ring actual stool coin doll boss strong rate',
   '008607501025021714880023171503630517020917211425',
   b'\n\xcb\xba\x00\x8d\x9b\xa0\x05\xf5\x99k@\xa3G\\\xd9'),
  # Potentially Problematic
  ('dignity utility vacant shiver thought canoe feel multiply item youth actor coyote',
   '049619221923158517990268067811630950204300210397',
   b'>\x1e\x0b\xc1\xe3\x1e\x0eC\x154\x8bv\xdf\xec\n\x98'),
  ('corn voice scrap arrow original diamond trial property benefit choose junk lock',
   '038719631547010112530489185713790169032209701051',
   b'0~\xaf\x05\x86Y\xcazz\rc\x15%\t\xe5A'),
  ('vocal tray giggle tool duck letter category pattern train magnet excite swamp',
   '196218530783182905421028028912901848107106301753',
   b'\xf5\\\xf5\x87\xf2T=\x01\t\r\n\xe7\x10\xbd;m'),
]


def _set_wallet(jade, mnemonic=mnemonics.default, passphrase=None):
    # Set mnemonic
    request = jade.build_request('id_mnem', 'debug_set_mnemonic',
                                 {'mnemonic': mnemonic, 'passphrase': passphrase})
    reply = jade.make_rpc_call(request)
    assert reply['id'] == request['id'], f"{reply['id']} != {request['id']}: {reply}"
    assert 'error' not in reply, f'{reply}'
    assert reply['result'] is True, f'{reply}'

    # Get and return root xpub
    request = jade.build_request('id_xpub', 'get_xpub',
                                 {'network': 'mainnet', 'path': []})
    reply = jade.make_rpc_call(request)
    assert reply['id'] == request['id']
    assert 'error' not in reply
    assert reply['result'].startswith('xpub')
    return reply['result']


@pytest.mark.mnemonic(mnemonics.reset)
def test_12word_mnemonic(jade, mnemonic):
    # Short sanity-test of 12-word mnemonic
    rslt = jade.set_mnemonic(TEST_MNEMONIC_12)
    assert rslt is True
    rslt = jade.get_xpub('mainnet', [1, 12])
    assert rslt == 'xpub6BETMaQnyXi1gqFdL5FX8A3YEtRCEvBPijmr7EL42rGeEc6pvjYv25\
ZoxpDgc3UZwmpCgfdCkNmcSQa2tjnZLPohvRFECZP9P1boFKdJ5Sx'
    rslt = jade.get_receive_address('mainnet', 1, 1, 231)
    assert rslt == '38SBTKLCNKVvQh1jPpbkAbXa3gtRJEh9Ud'


@pytest.mark.mnemonic(mnemonics.reset)
def test_mnemonic_import(jade, mnemonic):
    # Check the mnemonic unique prefixes expands to the same mnemonic/wallet
    # as when giving the full mnemonic words (test for qr-scanning prefixes)
    # as the unambiguous prefixes are expanded to the full words.  orc -> orchard
    # Also check the SeedSigner formats also (SeeqQR and CompactSeedQR)
    xpub_root0 = _set_wallet(jade.jade, mnemonic=mnemonics.default)
    xpub_root1 = _set_wallet(jade.jade, mnemonic=TEST_MNEMONIC_PREFIXES)
    xpub_root2 = _set_wallet(jade.jade, mnemonic=TEST_MNEMONIC_SEEDSIGNER)
    xpub_root3 = _set_wallet(jade.jade, mnemonic=TEST_MNEMONIC_SEEDSIGNER_COMPACT)
    assert xpub_root1 == xpub_root0
    assert xpub_root2 == xpub_root0
    assert xpub_root3 == xpub_root0

    # Check that mnemonic-prefixes are accepted even if they are prefixes to multiple
    # words, provided one of them is an exact/full match for the entire word.
    # eg. 'pen' is a prefix to 'pen', 'penalty' and 'pencil' - but is accepted as it
    # is an exact full match for 'pen', so no 'expansion' is carried out.  pen -> pen.
    xpub_root2 = _set_wallet(jade.jade, mnemonic=TEST_MNEMONIC_PREFIXES_EXACT_MATCH)
    assert xpub_root2 != xpub_root0

    # Seedsigner's own test vectors
    # See: https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md
    for mnem_string, seeqr_numeric, compact_bin in SEEDSIGNER_MNEMONIC_TEST_VECTORS:
        xpub_root0 = _set_wallet(jade.jade, mnemonic=mnem_string)
        xpub_root1 = _set_wallet(jade.jade, mnemonic=seeqr_numeric)
        xpub_root2 = _set_wallet(jade.jade, mnemonic=compact_bin)
        assert xpub_root1 == xpub_root0
        assert xpub_root2 == xpub_root0

    # bcur's bip39 own test case (12-words)
    xpub_root0 = _set_wallet(jade.jade, mnemonic=TEST_MNEMONIC_BCUR_BIP39_STRING)
    xpub_root1 = _set_wallet(jade.jade, mnemonic=TEST_MNEMONIC_BCUR_BIP39_LOWER)
    xpub_root2 = _set_wallet(jade.jade, mnemonic=TEST_MNEMONIC_BCUR_BIP39_UPPER)
    assert xpub_root1 == xpub_root0
    assert xpub_root2 == xpub_root0


@pytest.mark.mnemonic(mnemonics.reset)
def test_mnemonic_import_bad(jade, mnemonic):
    # Check importing invalid mnemonics
    bad_mnemonics = [
        # mnemonic phrase
        TEST_MNEMONIC_PREFIXES_AMBIGUOUS,        # ambiguous prefixes
        # seedsigner
        TEST_MNEMONIC_SEEDSIGNER[:-1],           # bad length (too short)
        TEST_MNEMONIC_SEEDSIGNER + '1234',       # bad length (too long)
        TEST_MNEMONIC_SEEDSIGNER[:-4] + '2048',  # out of range
        TEST_MNEMONIC_SEEDSIGNER[:-4] + '0000',  # invalid checksum word
        TEST_MNEMONIC_SEEDSIGNER_COMPACT[:-1],   # bad length (compact case)
        # bcur-bip39
        TEST_MNEMONIC_BCUR_BIP39_TOO_MANY,       # too many words
        TEST_MNEMONIC_BCUR_BIP39_TOO_FEW,        # too few words
        TEST_MNEMONIC_BCUR_BIP39_LONG_WORD,      # word too long
        TEST_MNEMONIC_BCUR_BIP39_EMPTY_WORD,     # empty word
    ]
    for i, bad_mnemonic in enumerate(bad_mnemonics):
        request = jade.jade.build_request('badmnemonic_' + str(i), 'debug_set_mnemonic',
                                          {'mnemonic': bad_mnemonic})
        reply = jade.jade.make_rpc_call(request)
        assert reply['id'] == request['id']
        assert 'result' not in reply
        assert reply['error']['code'] == JadeError.BAD_PARAMETERS
        message = reply['error']['message']
        expected = ['Failed to expand mnemonic prefixes',
                    'Failed to extract mnemonic prefixes']
        assert any(m in message for m in expected), message


@pytest.mark.mnemonic(mnemonics.reset)
def test_passphrase(jade, mnemonic):
    # Set mnemonic with/without a passphrase, and get root xpub
    xpub0 = _set_wallet(jade.jade, passphrase=None)
    xpub1 = _set_wallet(jade.jade, passphrase='Passphrase1')
    xpub2 = _set_wallet(jade.jade, passphrase='Passphrase2')

    # Check root xpubs are not the same
    # ie. that the passphrase leads to a different wallet
    assert xpub0 != xpub1 and xpub1 != xpub2 and xpub2 != xpub0

    # Check that using the same passphrase does get the same wallet
    xpub0_again = _set_wallet(jade.jade, passphrase=None)
    xpub1_again = _set_wallet(jade.jade, passphrase='Passphrase1')
    xpub2_again = _set_wallet(jade.jade, passphrase='Passphrase2')

    assert xpub0_again == xpub0 and xpub1_again == xpub1 and xpub2_again == xpub2
