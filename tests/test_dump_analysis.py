import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bsod_checker import diagnostics as d
from bsod_checker import dump_analysis as da

SAMPLE = '''Microsoft (R) Windows Debugger Version 10
BugCheck 50, {fffff, 2, 3, 4}
*******************************************************************************
*                        Bugcheck Analysis                                    *
*******************************************************************************
PAGE_FAULT_IN_NONPAGED_AREA (50)
Arguments:
Arg1: ffffffff00000001, memory referenced.
Arg2: 0000000000000002, value 2 = write operation.
Arg3: fffff80000000000, address which referenced memory.
Arg4: 0000000000000000, reserved.
BUGCHECK_CODE:  50
PROCESS_NAME:  example.exe
MODULE_NAME: sample
IMAGE_NAME:  sample.sys
FAILURE_BUCKET_ID:  AV_sample!function
Probably caused by : sample.sys ( sample!function+10 )
STACK_TEXT:
fffff800`00000001 fffff800`00000002 : 00000000`00000050 : nt!KeBugCheckEx
fffff800`00000003 fffff800`00000004 : 00000000`00000002 : sample!function

SYMBOL_NAME:  sample!function+10
'''


class DumpParsingTests(unittest.TestCase):
    def test_full_structured_analysis(self):
        result = da.parse_output(SAMPLE)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.bugcheck_code, 0x50)
        self.assertEqual(result.bugcheck_name, "PAGE_FAULT_IN_NONPAGED_AREA")
        self.assertEqual(len(result.arguments), 4)
        self.assertEqual(result.image_name, "sample.sys")
        self.assertEqual(result.module_name, "sample")
        self.assertEqual(result.process_name, "example.exe")
        self.assertEqual(result.failure_bucket, "AV_sample!function")
        self.assertIn("sample!function", result.stack)
        self.assertNotIn("SYMBOL_NAME", result.stack)
        self.assertEqual(result.raw_output, SAMPLE)

    def test_missing_fields_and_debugger_failure_are_not_success(self):
        result = da.parse_output("Unable to open dump file, Win32 error 5")
        self.assertEqual(result.status, "error")
        self.assertIsNone(result.bugcheck_code)
        partial = da.parse_output("BugCheck 1A, {0, 0, 0, 0}\nCould not load extension")
        self.assertEqual(partial.status, "partial")
        self.assertEqual(partial.bugcheck_code, 0x1A)
        self.assertEqual(da.parse_output("IMAGE_NAME:\nMODULE_NAME: foo").image_name, "")

    def test_symbol_warnings_and_partial(self):
        result = da.parse_output(SAMPLE + "\n*** ERROR: symbols could not be loaded\n")
        self.assertEqual(result.status, "partial")
        self.assertTrue(result.warnings)

    def test_offline_command_and_online_opt_in(self):
        completed = subprocess.CompletedProcess([], 0, stdout=SAMPLE, stderr="")
        with tempfile.TemporaryDirectory() as temp, patch.object(da, "data_dir", return_value=Path(temp)), patch.object(da.subprocess, "run", return_value=completed) as run:
            result = da.analyze_dump(r"C:\\dumps\\my crash.dmp", "cdb.exe")
            self.assertEqual(result.status, "ok")
            args = run.call_args.args[0]
            self.assertNotIn("https://", args[2])
            self.assertEqual(args[4], r"C:\\dumps\\my crash.dmp")
            self.assertEqual(args[-1], "!analyze -v; q")
            self.assertNotIn("_NT_SYMBOL_PATH", run.call_args.kwargs["env"])
            da.analyze_dump("file.dmp", "cdb.exe", online_symbols=True)
            self.assertIn("https://msdl.microsoft.com/download/symbols", run.call_args.args[0][2])

    def test_timeout_and_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(da, "data_dir", return_value=Path(temp)):
            with patch.object(da.subprocess, "run", side_effect=subprocess.TimeoutExpired("cdb", 1, output=b"partial")):
                result = da.analyze_dump("a.dmp", "cdb.exe", timeout=1)
                self.assertEqual(result.status, "error")
                self.assertEqual(result.raw_output, "partial")
            with patch.object(da.subprocess, "run", return_value=subprocess.CompletedProcess([], 5, SAMPLE, "error")):
                self.assertEqual(da.analyze_dump("a.dmp", "cdb.exe").status, "error")

    def test_explicit_invalid_path_does_not_fall_back(self):
        with patch.object(da.shutil, "which", return_value="other-cdb.exe"):
            self.assertIsNone(da.find_cdb("/not/a/real/cdb.exe"))
            self.assertEqual(da.find_cdb(""), "other-cdb.exe")

    def test_report_and_recommendations_use_dump_data(self):
        dump = d.Dump("sample.dmp", "2025-01-01", 100, da.parse_output(SAMPLE))
        report = d.Report("", "", 30, dumps=[dump])
        recommendations = d.recommendations(report)
        self.assertTrue(any("0x00000050" in title for title, _ in recommendations))
        self.assertTrue(any("sample.sys" in text for _, text in recommendations))
        self.assertEqual(json.loads(json.dumps(report.to_dict()))["dumps"][0]["analysis"]["bugcheck_code"], 0x50)


if __name__ == "__main__": unittest.main()
