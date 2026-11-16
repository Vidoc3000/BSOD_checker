import io
import subprocess
import unittest
from pathlib import PosixPath
from unittest.mock import patch

from bsod_checker import debugger_install as installer


class Response(io.BytesIO):
    def __init__(self, data=b"signed-binary", url="https://download.microsoft.com/winsdksetup.exe"):
        super().__init__(data)
        self.url = url
    def geturl(self): return self.url


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.patches = [patch.object(installer.os, "name", "nt"), patch.object(installer, "Path", PosixPath)]
        for p in self.patches: p.start()
        self.addCleanup(self.stop_patches)

    def stop_patches(self):
        for p in reversed(self.patches): p.stop()

    def test_signed_installer_and_verify_rediscovery(self):
        ok = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(installer.urllib.request, "urlopen", return_value=Response()) as download, patch.object(installer, "_powershell", side_effect=[ok, ok]) as ps, patch.object(installer.dump_analysis, "find_cdb", return_value="CDB.exe"):
            messages = []
            self.assertEqual(installer.install(messages.append), "CDB.exe")
            self.assertEqual(download.call_args.args[0], installer.SDK_INSTALLER_URL)
            self.assertEqual(ps.call_count, 2)
            self.assertIn("Get-AuthenticodeSignature", ps.call_args_list[0].args[0])
            self.assertIn("OptionId.WindowsDesktopDebuggers", ps.call_args_list[1].args[0])
            self.assertIn("-Verb RunAs", ps.call_args_list[1].args[0])
            self.assertEqual(len(messages), 3)

    def test_bad_signature_never_runs_installer(self):
        invalid = subprocess.CompletedProcess([], 1, "", "bad signature")
        with patch.object(installer.urllib.request, "urlopen", return_value=Response()), patch.object(installer, "_powershell", return_value=invalid) as ps:
            with self.assertRaisesRegex(RuntimeError, "подпись"):
                installer.install()
            self.assertEqual(ps.call_count, 1)

    def test_download_size_and_insecure_final_url(self):
        with patch.object(installer.urllib.request, "urlopen", return_value=Response(b"12345")), patch.object(installer, "MAX_INSTALLER_BYTES", 4), patch.object(installer, "_powershell") as ps:
            with self.assertRaisesRegex(RuntimeError, "Размер"):
                installer.install()
            ps.assert_not_called()
        with patch.object(installer.urllib.request, "urlopen", return_value=Response(url="http://bad.example/file")), patch.object(installer, "_powershell") as ps:
            with self.assertRaisesRegex(RuntimeError, "небезопасный"):
                installer.install()
            ps.assert_not_called()

    def test_cancel_or_missing_cdb_is_reported(self):
        ok = subprocess.CompletedProcess([], 0, "", "")
        cancelled = subprocess.CompletedProcess([], 1, "", "cancelled")
        with patch.object(installer.urllib.request, "urlopen", return_value=Response()), patch.object(installer, "_powershell", side_effect=[ok, cancelled]):
            with self.assertRaisesRegex(RuntimeError, "не завершена"):
                installer.install()
        with patch.object(installer.urllib.request, "urlopen", return_value=Response()), patch.object(installer, "_powershell", side_effect=[ok, ok]), patch.object(installer.dump_analysis, "find_cdb", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "cdb.exe не найден"):
                installer.install()


if __name__ == "__main__": unittest.main()
