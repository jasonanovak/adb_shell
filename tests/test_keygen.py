import unittest

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from adb_shell_wifi.auth.keygen import get_user_info


class TestKeygen(unittest.TestCase):
    def test_get_user_info(self):
        with patch('adb_shell_wifi.auth.keygen.os.getlogin', side_effect=OSError), patch('adb_shell_wifi.auth.keygen.socket.gethostname', return_value=''):
            user_host = get_user_info()
            self.assertEqual(user_host, ' unknown@unknown')

        with patch('adb_shell_wifi.auth.keygen.os.getlogin', return_value=''), patch('adb_shell_wifi.auth.keygen.socket.gethostname', return_value=''):
            user_host = get_user_info()
            self.assertEqual(user_host, ' unknown@unknown')
