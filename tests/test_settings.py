import json
import os
import stat
import tempfile
import unittest

from config.settings import Settings, SettingsError, load_settings, mask_token, save_settings


class SettingsTests(unittest.TestCase):
    def test_missing_file_gives_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            s = load_settings(os.path.join(d, "nope.json"))
            self.assertEqual(s.panel_address, "")
            self.assertFalse(s.is_configured())
            self.assertEqual(s.cert_root, "/cert_folder/cert")

    def test_round_trip_and_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "settings.json")
            save_settings(path, Settings(panel_address="1.2.3.4:2053", api_token="abcdwxyz"))
            loaded = load_settings(path)
            self.assertEqual(loaded.api_token, "abcdwxyz")
            self.assertTrue(loaded.is_configured())
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_bad_json_reported(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "settings.json")
            with open(path, "w") as fh:
                fh.write("{bad")
            with self.assertRaises(SettingsError):
                load_settings(path)

    def test_unsupported_version_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "settings.json")
            with open(path, "w") as fh:
                json.dump({"settings_version": 99}, fh)
            with self.assertRaisesRegex(SettingsError, "Unsupported"):
                load_settings(path)

    def test_wrong_types_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "settings.json")
            with open(path, "w") as fh:
                json.dump({"verify_tls": "yes"}, fh)
            with self.assertRaisesRegex(SettingsError, "verify_tls"):
                load_settings(path)

    def test_relative_cert_root_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "settings.json")
            with open(path, "w") as fh:
                json.dump({"cert_root": "certs"}, fh)
            with self.assertRaisesRegex(SettingsError, "absolute"):
                load_settings(path)

    def test_mask_token_never_returns_full_token(self):
        self.assertEqual(mask_token(""), "not set")
        masked = mask_token("abcdefgh1234")
        self.assertNotIn("abcdefgh", masked)
        self.assertTrue(masked.endswith("1234"))
        self.assertEqual(mask_token("ab"), "****")


if __name__ == "__main__":
    unittest.main()
