import os
from pathlib import PosixPath
import subprocess
import unittest
from unittest.mock import patch

from bsod_checker import elevation


class ElevationTests(unittest.TestCase):
    def test_restart_uses_python_and_quoted_entry_point(self):
        with patch.object(elevation.os, "name", "nt"), patch.object(elevation, "Path", PosixPath), patch.object(elevation.sys, "executable", "/python path/python.exe"), patch.object(elevation, "_shell_execute", return_value=42) as shell:
            elevation.restart_as_admin()
            exe, args, cwd = shell.call_args.args
            self.assertEqual(exe, "/python path/python.exe")
            self.assertEqual(args, subprocess.list2cmdline([str(PosixPath(elevation.__file__).resolve().parent.parent / "main.py")]))
            self.assertTrue(cwd.endswith("BSOD_checker"))

    def test_cancelled_uac_is_reported(self):
        with patch.object(elevation.os, "name", "nt"), patch.object(elevation, "Path", PosixPath), patch.object(elevation, "_shell_execute", return_value=0):
            with self.assertRaisesRegex(OSError, "отменён"):
                elevation.restart_as_admin()

    def test_non_windows_does_not_try_to_restart(self):
        with patch.object(elevation.os, "name", "posix"), patch.object(elevation, "_shell_execute") as shell:
            self.assertFalse(elevation.is_elevated())
            with self.assertRaises(OSError): elevation.restart_as_admin()
            shell.assert_not_called()


if __name__ == "__main__": unittest.main()
