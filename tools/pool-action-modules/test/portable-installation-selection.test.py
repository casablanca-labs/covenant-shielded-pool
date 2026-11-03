"""Selection controls only: no installation, runtime, wallets or proving."""
import importlib.util
import os
from pathlib import Path
import pwd
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("installation", ROOT / "tools/pool-action-modules/private-runner-installation.py")
installation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installation)
CONFIG = (ROOT / "tools/pool-action-modules/lib/private-runner-installation.mjs").read_bytes()


class Selection(unittest.TestCase):
    def test_native_account_ignores_environment(self):
        expected = str(Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".nvm/versions/node/v22.22.3/bin/node")
        with patch.dict(os.environ, {"HOME": "/synthetic/forged-home", "PATH": "/synthetic/forged-bin"}):
            self.assertEqual(installation.node_selection(CONFIG), (expected, "v22.22.3"))

    def test_configuration_changes_refuse(self):
        for source in (b"", CONFIG.replace(b"v22.22.3", b"v20.19.4"),
                       CONFIG.replace(b".nvm/versions/node/", b"../versions/node/"),
                       CONFIG.replace(b".nvm/versions/node/", b"/synthetic/versions/node/")):
            with self.subTest(control="configuration"), self.assertRaises(installation.InstallationRefusal):
                installation.node_selection(source)

    def test_account_database_must_return_canonical_home(self):
        for home in ("relative", "/private/tmp/../tmp"):
            class Account:
                pw_dir = home
            with patch.object(installation.pwd, "getpwuid", return_value=Account()), self.assertRaises(installation.InstallationRefusal):
                installation.node_selection(CONFIG)


if __name__ == "__main__":
    unittest.main()
