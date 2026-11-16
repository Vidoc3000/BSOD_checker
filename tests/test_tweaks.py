import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from bsod_checker import tweaks


class FakeKey:
    def __init__(self, key): self.key = key
    def __enter__(self): return self
    def __exit__(self, *args): pass


class FakeRegistry:
    HKEY_CURRENT_USER = 1
    KEY_READ = 2
    KEY_SET_VALUE = 4
    REG_DWORD = 4
    def __init__(self): self.keys = {}
    def OpenKey(self, root, name, reserved, access):
        if name not in self.keys: raise FileNotFoundError(name)
        return FakeKey(name)
    def CreateKeyEx(self, root, name, reserved, access):
        self.keys.setdefault(name, {})
        return FakeKey(name)
    def QueryValueEx(self, key, value):
        try: return self.keys[key.key][value]
        except KeyError: raise FileNotFoundError(value)
    def SetValueEx(self, key, value, reserved, kind, data): self.keys[key.key][value] = (data, kind)
    def DeleteValue(self, key, value):
        try: del self.keys[key.key][value]
        except KeyError: raise FileNotFoundError(value)


class TweaksTests(unittest.TestCase):
    def test_apply_twice_preserves_original_and_restore(self):
        reg = FakeRegistry(); spec = tweaks.TWEAKS["extensions"]
        reg.keys[spec["key"]] = {spec["value"]: (1, reg.REG_DWORD)}
        with tempfile.TemporaryDirectory() as temp, patch.object(tweaks, "winreg", reg):
            path = Path(temp) / "backup.json"
            tweaks.apply("extensions", path); tweaks.apply("extensions", path)
            self.assertEqual(reg.keys[spec["key"]][spec["value"]], (0, 4))
            tweaks.restore("extensions", path)
            self.assertEqual(reg.keys[spec["key"]][spec["value"]], (1, 4))
            with self.assertRaises(ValueError): tweaks.restore("extensions", path)

    def test_restore_absent_value_deletes_it(self):
        reg = FakeRegistry(); spec = tweaks.TWEAKS["transparency"]
        with tempfile.TemporaryDirectory() as temp, patch.object(tweaks, "winreg", reg):
            path = Path(temp) / "backup.json"
            tweaks.apply("transparency", path); tweaks.restore("transparency", path)
            self.assertNotIn(spec["value"], reg.keys[spec["key"]])

    def test_corrupt_backup_prevents_changes(self):
        reg = FakeRegistry()
        with tempfile.TemporaryDirectory() as temp, patch.object(tweaks, "winreg", reg):
            path = Path(temp) / "backup.json"; path.write_text("{broken", encoding="utf-8")
            with self.assertRaises(ValueError): tweaks.apply("extensions", path)
            self.assertFalse(reg.keys)


if __name__ == "__main__": unittest.main()
