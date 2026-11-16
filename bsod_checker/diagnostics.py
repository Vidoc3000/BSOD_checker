"""Collect Windows crash evidence without modifying the system."""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from . import dump_analysis


@dataclass
class Event:
    time: str
    event_id: int
    provider: str
    message: str


@dataclass
class Dump:
    path: str
    modified: str
    size: int
    analysis: dump_analysis.DumpAnalysis = field(default_factory=dump_analysis.DumpAnalysis)


@dataclass
class Report:
    generated: str
    system: str
    days: int
    events: list[Event] = field(default_factory=list)
    dumps: list[Dump] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def _run_powershell(script: str) -> str:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    result = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45,
        creationflags=flags,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "PowerShell завершился с ошибкой.")
    return result.stdout.strip()


def collect(days: int = 30, max_events: int = 100, *, cdb_path: str = "", online_symbols: bool = False, max_dumps: int = 10, progress: Callable[[str], None] | None = None) -> Report:
    if not 1 <= days <= 365 or not 1 <= max_events <= 500:
        raise ValueError("Период должен быть от 1 до 365 дней, число событий — от 1 до 500.")
    if not 1 <= max_dumps <= 100:
        raise ValueError("Число анализируемых дампов должно быть от 1 до 100.")
    report = Report(datetime.now().isoformat(timespec="seconds"), platform.platform(), days)
    if os.name != "nt":
        report.warnings.append("Диагностика доступна только в Windows. Запустите программу на проверяемом компьютере.")
        return report
    # Force UTF-8 because Windows PowerShell otherwise uses the console code page.
    script = f'''$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding
$ErrorActionPreference = 'Stop'
try {{
$events = @(Get-WinEvent -FilterHashtable @{{LogName='System'; Id=1001,41,6008; StartTime=(Get-Date).AddDays(-{days})}} -MaxEvents {max_events} -ErrorAction Stop | Where-Object {{
  ($_.Id -eq 1001 -and $_.ProviderName -eq 'Microsoft-Windows-WER-SystemErrorReporting') -or
  ($_.Id -eq 41 -and $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power') -or
  ($_.Id -eq 6008 -and $_.ProviderName -eq 'EventLog')
}} | ForEach-Object {{ [PSCustomObject]@{{ time=$_.TimeCreated.ToString('o'); event_id=$_.Id; provider=$_.ProviderName; message=$_.Message }} }})
}} catch {{ if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {{ $events = @() }} else {{ throw }} }}
ConvertTo-Json -InputObject $events -Depth 3 -Compress'''
    try:
        raw = _run_powershell(script)
        data = json.loads(raw) if raw else []
        if isinstance(data, dict):
            data = [data]
        for item in data:
            report.events.append(Event(str(item.get("time", "")), int(item["event_id"]),
                                       str(item.get("provider", "")), str(item.get("message") or "")))
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError, TypeError, KeyError) as exc:
        report.warnings.append(f"Не удалось прочитать журнал событий: {exc}. Попробуйте запустить программу от имени администратора.")
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    try:
        paths = [root / "MEMORY.DMP"]
        dump_dir = root / "Minidump"
        if dump_dir.exists():
            paths.extend(dump_dir.glob("*.dmp"))
        for path in paths:
            try:
                stat = path.stat()
                if path.is_file():
                    report.dumps.append(Dump(str(path), datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"), stat.st_size))
            except FileNotFoundError:
                continue
            except OSError as exc:
                report.warnings.append(f"Нет доступа к дампу {path}: {exc}")
        report.dumps.sort(key=lambda d: d.modified, reverse=True)
    except OSError as exc:
        report.warnings.append(f"Не удалось проверить папку дампов: {exc}")
    if report.dumps:
        cdb = dump_analysis.find_cdb(cdb_path)
        if cdb is None:
            message = ("Отладчик cdb.exe не найден. Установите Debugging Tools for Windows или укажите путь на вкладке «Настройки».")
            report.warnings.append(message)
            for dump in report.dumps:
                dump.analysis.message = message
        else:
            for index, dump in enumerate(report.dumps):
                if index >= max_dumps:
                    dump.analysis.message = f"Пропущен: достигнут предел {max_dumps} дампов за анализ. Измените его в настройках."
                    continue
                if progress:
                    progress(f"Анализ дампа {index + 1} из {min(len(report.dumps), max_dumps)}: {Path(dump.path).name}")
                dump.analysis = dump_analysis.analyze_dump(dump.path, cdb, online_symbols)
            if len(report.dumps) > max_dumps:
                report.warnings.append(f"Проанализированы только первые {max_dumps} дампов. Остальные пропущены согласно настройкам.")
    return report


# Code names are hints, not a substitute for debugging a dump with symbols.
CODES = {
    0xA: ("IRQL_NOT_LESS_OR_EQUAL", "Проверьте недавно установленные драйверы и оперативную память."),
    0x1A: ("MEMORY_MANAGEMENT", "Проверьте оперативную память и настройки разгона; запустите диагностику памяти Windows."),
    0x1E: ("KMODE_EXCEPTION_NOT_HANDLED", "Проверьте новые драйверы и обновления Windows."),
    0x3B: ("SYSTEM_SERVICE_EXCEPTION", "Проверьте системные файлы и обновите драйверы устройств."),
    0x50: ("PAGE_FAULT_IN_NONPAGED_AREA", "Проверьте оперативную память, диск и недавно установленные драйверы."),
    0x7E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "Проверьте драйверы и совместимость недавно установленного оборудования."),
    0x7B: ("INACCESSIBLE_BOOT_DEVICE", "Проверьте подключение накопителя и последние изменения контроллера хранения."),
    0x9F: ("DRIVER_POWER_STATE_FAILURE", "Обновите драйверы чипсета и устройств, особенно после проблем со сном."),
    0x116: ("VIDEO_TDR_FAILURE", "Проверьте драйвер видеокарты, температуру и стабильность питания."),
    0x124: ("WHEA_UNCORRECTABLE_ERROR", "Проверьте охлаждение, питание и разгон; изучите события WHEA."),
    0x133: ("DPC_WATCHDOG_VIOLATION", "Проверьте драйверы накопителя, чипсета и прошивку устройств."),
    0x139: ("KERNEL_SECURITY_CHECK_FAILURE", "Проверьте драйверы, системные файлы и оперативную память."),
    0xEF: ("CRITICAL_PROCESS_DIED", "Проверьте системные файлы и состояние накопителя."),
}


def bugcheck_code(event: Event) -> int | None:
    if event.event_id != 1001 or event.provider != "Microsoft-Windows-WER-SystemErrorReporting":
        return None
    # The System BugCheck event contains the stop code followed by parameters.
    match = re.search(r"0x([0-9a-fA-F]{1,16})\b", event.message)
    return int(match.group(1), 16) if match else None


def recommendations(report: Report) -> list[tuple[str, str]]:
    result = []
    seen = set()
    codes = [dump.analysis.bugcheck_code for dump in report.dumps if dump.analysis.status in ("ok", "partial")]
    codes.extend(bugcheck_code(event) for event in report.events)
    for code in codes:
        if code is None or code in seen:
            continue
        seen.add(code)
        name, advice = CODES.get(code, ("Неизвестный код", "Найдите код остановки в документации Microsoft и изучите вывод отладчика."))
        result.append((f"0x{code:08X} · {name}", advice + " Это возможные направления проверки, а не установленная причина."))
    for dump in report.dumps:
        analysis = dump.analysis
        suspect = analysis.probable_cause or analysis.image_name or analysis.module_name
        if suspect and analysis.status in ("ok", "partial"):
            result.append((f"Дамп: {Path(dump.path).name}", f"Отладчик указал: {suspect}. Это зацепка, а не доказанная причина; проверьте стек, символы и версию драйвера перед изменениями."))
    if any(e.event_id in (41, 6008) for e in report.events):
        result.append(("Неожиданное выключение", "Kernel-Power 41 и EventLog 6008 подтверждают некорректное завершение работы, но сами по себе не доказывают BSOD и не указывают его причину. Проверьте питание и события рядом по времени."))
    if report.dumps:
        result.append(("Дампы памяти", "Откройте каждый дамп в списке анализа. Отладчик может ошибаться, особенно при неполных символах; для перепроверки используйте WinDbg."))
    result.extend([
        ("Системные файлы", "При подозрении на повреждение запустите от администратора sfc /scannow; при необходимости затем DISM /Online /Cleanup-Image /RestoreHealth."),
        ("Производительность и стабильность", "Проверьте свободное место на системном диске, температуры и автозагрузку в диспетчере задач. Обновляйте драйверы с сайта производителя; перед изменениями создайте точку восстановления."),
    ])
    return result
