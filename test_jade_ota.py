"""Host-only download tests: python -m unittest test_jade_ota."""
import contextlib
import io
import json
import logging
from pathlib import Path
import runpy
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import jade_ota


class JadeOtaTests(unittest.TestCase):
    def test_available_firmware(self):
        for gdk in (False, True):
            with self.subTest(gdk=gdk):
                payload = b'fixture compressed firmware'
                args = SimpleNamespace(downloadfw=not gdk, downloadgdk=gdk,
                                       hwtarget='jade', writecompressed=False, release='stable')
                helper = 'download_file_gdk' if gdk else 'download_file'
                with patch.object(jade_ota, helper, return_value=(100, None, 'ab' * 32, payload)):
                    self.assertEqual(jade_ota.get_firmware(args),
                                     (100, None, bytes.fromhex('ab' * 32), payload))

    def test_missing_release(self):
        for gdk in (False, True):
            for index in ({}, {'beta': {}}):
                with self.subTest(gdk=gdk, index=index):
                    response = SimpleNamespace(status_code=200, text=json.dumps(index))
                    fake_gdk = ModuleType('greenaddress')
                    fake_gdk.init = Mock()
                    fake_gdk.Session = Mock(return_value=SimpleNamespace(session_obj=object()))
                    fake_gdk.http_request = Mock(return_value=json.dumps({'body': response.text}))
                    args = SimpleNamespace(downloadfw=not gdk, downloadgdk=gdk,
                                           hwtarget='jade', writecompressed=False, release='beta')
                    with patch('requests.get', return_value=response), \
                            patch.dict(sys.modules, {'greenaddress': fake_gdk}), \
                            self.assertRaises(SystemExit) as raised:
                        jade_ota.get_firmware(args)
                    self.assertEqual(raised.exception.code, 2)

    def test_download_without_device_default_target(self):
        script = Path(jade_ota.__file__)
        index = {'stable': {}}
        response = SimpleNamespace(status_code=200, text=json.dumps(index))
        loggers = [logging.getLogger('jadepy.jade'), logging.getLogger('jadepy.jade-device')]
        handlers = [logger.handlers[:] for logger in loggers]
        levels = [logger.level for logger in loggers]
        argv = [str(script), '--download-firmware', '--skipserial', '--skipble']
        try:
            with patch.object(sys, 'argv', argv), \
                    patch('requests.get', return_value=response) as get, \
                    contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                runpy.run_path(str(script), run_name='__main__')
            self.assertEqual(raised.exception.code, 2)
            get.assert_called_once_with(jade_ota.FWSERVER_URL_ROOT + '/jade/index.json')
        finally:
            for logger, saved_handlers, level in zip(loggers, handlers, levels):
                logger.handlers[:] = saved_handlers
                logger.setLevel(level)


if __name__ == '__main__':
    unittest.main()
