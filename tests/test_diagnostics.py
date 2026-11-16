import json
import os
import tempfile
import unittest
from pathlib import Path, PosixPath
from unittest.mock import patch

from bsod_checker import diagnostics as d


class DiagnosticsTests(unittest.TestCase):
    def test_bugcheck_only_for_system_error_provider(self):
        e = d.Event("today", 1001, "Microsoft-Windows-WER-SystemErrorReporting", "Bugcheck was: 0x00000116 (0xffff0000)")
        self.assertEqual(d.bugcheck_code(e), 0x116)
        e.provider = "other"
        self.assertIsNone(d.bugcheck_code(e))
        e.event_id = 41
        self.assertIsNone(d.bugcheck_code(e))

    def test_recommendations_deduplicate_and_qualify_power_events(self):
        e = d.Event("", 1001, "Microsoft-Windows-WER-SystemErrorReporting", "0x0000007e")
        report = d.Report("", "", 30, [e, e, d.Event("", 41, "Microsoft-Windows-Kernel-Power", "")])
        result = d.recommendations(report)
        self.assertEqual(sum("0x0000007E" in title for title, _ in result), 1)
        self.assertTrue(any("не доказывают BSOD" in body for _, body in result))

    def test_collect_windows_and_missing_dump(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "Minidump"
            folder.mkdir()
            (folder / "test.dmp").write_bytes(b"dump")
            events = [{"time": "2025-01-01", "event_id": 1001, "provider": "Microsoft-Windows-WER-SystemErrorReporting", "message": "0x0000007e"}]
            with patch.object(d.os, "name", "nt"), patch.object(d, "Path", PosixPath), patch.dict(os.environ, {"SystemRoot": temp}), patch.object(d, "_run_powershell", return_value=json.dumps(events)), patch.object(d.dump_analysis, "find_cdb", return_value="cdb.exe"), patch.object(d.dump_analysis, "analyze_dump", return_value=d.dump_analysis.DumpAnalysis(status="ok", bugcheck_code=0x7e)):
                report = d.collect(30, 100)
            self.assertEqual(len(report.events), 1)
            self.assertEqual(report.dumps[0].size, 4)
            self.assertFalse(report.warnings)

    def test_collection_errors_are_visible(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(d.os, "name", "nt"), patch.object(d, "Path", PosixPath), patch.dict(os.environ, {"SystemRoot": temp}), patch.object(d, "_run_powershell", side_effect=OSError("access denied")):
                report = d.collect()
            self.assertIn("access denied", report.warnings[0])

    def test_automatic_analysis_limit_and_missing_debugger(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "Minidump"
            folder.mkdir()
            for name in ("first.dmp", "second.dmp", "third.dmp"):
                (folder / name).write_bytes(b"dump")
            common = [patch.object(d.os, "name", "nt"), patch.object(d, "Path", PosixPath),
                      patch.dict(os.environ, {"SystemRoot": temp}), patch.object(d, "_run_powershell", return_value="[]")]
            for p in common: p.start()
            try:
                messages = []
                with patch.object(d.dump_analysis, "find_cdb", return_value="cdb.exe"), patch.object(d.dump_analysis, "analyze_dump", return_value=d.dump_analysis.DumpAnalysis(status="ok", bugcheck_code=0x50)) as analyze:
                    report = d.collect(max_dumps=2, online_symbols=True, progress=messages.append)
                self.assertEqual(analyze.call_count, 2)
                self.assertTrue(analyze.call_args.args[2])
                self.assertEqual(len(messages), 2)
                self.assertEqual(report.dumps[2].analysis.status, "skipped")
                self.assertTrue(report.warnings)
                with patch.object(d.dump_analysis, "find_cdb", return_value=None):
                    report = d.collect()
                self.assertIn("cdb.exe", report.warnings[0])
                self.assertTrue(all(x.analysis.status == "skipped" for x in report.dumps))
            finally:
                for p in reversed(common): p.stop()

    def test_resolver_runs_only_when_debugger_missing(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "MEMORY.DMP").write_bytes(b"dump")
            with patch.object(d.os, "name", "nt"), patch.object(d, "Path", PosixPath), patch.dict(os.environ, {"SystemRoot": temp}), patch.object(d, "_run_powershell", return_value="[]"), patch.object(d.dump_analysis, "find_cdb", return_value=None), patch.object(d.dump_analysis, "analyze_dump", return_value=d.dump_analysis.DumpAnalysis(status="ok")) as analyze:
                report = d.collect(cdb_resolver=lambda: ("installed-cdb.exe", None))
                self.assertEqual(analyze.call_args.args[1], "installed-cdb.exe")
                self.assertEqual(report.dumps[0].analysis.status, "ok")
                report = d.collect(cdb_resolver=lambda: (None, "Установка отменена"))
                self.assertIn("Установка отменена", report.warnings[0])

    def test_whea_storage_and_current_resource_recommendations(self):
        report = d.Report("", "", 30, events=[
            d.Event("", 18, "Microsoft-Windows-WHEA-Logger", ""),
            d.Event("", 153, "disk", ""),
            d.Event("", 161, "volmgr", ""),
        ], resources=d.ResourceSnapshot(disk_total=1000, disk_free=50, memory_total=1000, memory_available=50))
        text = "\n".join(title + " " + body for title, body in d.recommendations(report))
        for expected in ("WHEA", "накопителя", "Создание дампа", "Мало свободного места", "Мало доступной памяти", "текущий снимок"):
            self.assertIn(expected, text)
        self.assertEqual(report.to_dict()["resources"]["disk_free"], 50)

    def test_invalid_limits(self):
        for args in [(0, 100), (366, 100), (30, 0), (30, 501)]:
            with self.assertRaises(ValueError): d.collect(*args)
        for limit in (0, 101):
            with self.assertRaises(ValueError): d.collect(max_dumps=limit)


if __name__ == "__main__": unittest.main()
