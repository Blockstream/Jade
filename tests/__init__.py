import base64
import functools
import glob
import json
import logging
import os
import pytest
import subprocess
import time
from types import SimpleNamespace
import unittest

from jadepy.jade import JadeAPI, JadeError
import wallycore as wally

logger = logging.getLogger('jade.tests')

# Default test mnemonics
mnemonics = SimpleNamespace(**{
    # Default mnemonic, used primarily for multisig tests
    'default': 'fish inner face ginger orchard permit useful method fence \
kidney chuckle party favorite sunset draw limb science crane oval letter \
slot invite sadness banana',
    # Default singlesig mnemonic
    'singlesig': 'paddle puppy easily actor poet apart screen \
drastic city front predict damp',
    # Mnemonic used in identity tests
    'identity': 'alcohol woman abuse must during monitor noble \
actual mixed trade anger aisle',
    # Used to ensure the on-device cached mnemonic is changed to an
    # otherwise unused mnemonic for tests that set a custom mnemonic/seed
    'invalidatecache': 'abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon cactus'
})

# Seeds used in tests
seeds = SimpleNamespace(**{
    # Default singlesig seed
    'singlesig': 'b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c'
})


_jade_config = None  # Global jade config for the connected Jade being tested


def set_jade_config(obj):
    global _jade_config
    _jade_config = obj


def get_jade_config():
    return _jade_config


def _h2b_test_case(value):
    """Helper to convert 0x-prefixed strings to binary and b64:-prefixed to base64"""
    if isinstance(value, dict):
        return {key: _h2b_test_case(item) for key, item in value.items()}

    if isinstance(value, list):
        return [_h2b_test_case(item) for item in value]

    if isinstance(value, str) and value.startswith('0x'):
        return bytes.fromhex(value[2:])

    if isinstance(value, str) and value.startswith('b64:'):
        return base64.b64decode(value[4:])

    return value


def _read_json_file(filename):
    """Helper to read a json file and attach its filename for dict test cases."""
    with open(filename, 'r') as json_file:
        ret = json.load(json_file)
        if isinstance(ret, dict):
            ret['filename'] = filename  # Add filename for debugging
        return ret


def _get_test_cases(pattern):
    """Helper to read json test files into a list"""
    filenames = [f for f in glob.glob(pattern)]
    return ((_h2b_test_case(_read_json_file(f)), f) for f in filenames)


def with_test_cases(pattern):
    """Decorator to add parsed json test cases to a test.
       To use, add a decorator:
       @with_test_cases('path/to/test/files/pattern*.json')
       And append a 'test_case' argument to the test function."""
    pattern = pattern if pattern.endswith('.json') else f'{pattern.rstrip('/')}/*.json'
    test_cases = _get_test_cases(pattern)
    # Create pytest parameters: this results in a new test for each case,
    # logged as "test_file.py::test_name[test_case_basename]"

    def make_id(filename):
        return filename.rpartition('/')[-1].rpartition('.')[0]

    params = [pytest.param(case, id=make_id(filename)) for case, filename in test_cases]
    assert len(params)  # Must match some files
    return pytest.mark.parametrize('test_case', params)


def transport_is_not(targets):
    """Determine if the current transport is not (or not contained in) 'targets'.
       Can be used to skip tests, e.g:
       @pytest.mark.skipif(transport_is_not('libjade'), reason='libjade only')
    """
    targets = targets if isinstance(targets, (list, tuple)) else [targets]
    for t in targets:
        assert t in ('libjade', 'serial', 'ble'), f'{t}'
    return get_jade_config().transport not in targets
