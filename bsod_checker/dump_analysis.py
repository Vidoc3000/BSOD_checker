"""Run Microsoft's console debugger on crash dumps and structure its output."""
from __future__ import annotations

import locale
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .tweaks import data_dir


@dataclass
class DumpAnalysis:
    # status is one of ok, partial, error or skipped; no conclusion is fabricated.
    status: str = "skipped"
    message: str = "Дамп ещё не анализировался."
    bugcheck_code: int | None = None
    bugcheck_name: str = ""
    arguments: list[str] = field(default_factory=list)
    probable_cause: str = ""
    image_name: str = ""
    module_name: str = ""
    process_name: str = ""
    failure_bucket: str = ""
    stack: str = ""
    warnings: list[str] = field(default_factory=list)
    raw_output: str = ""


def find_cdb(configured: str = "") -> str | None:
    """An explicit path is authoritative, even if it is invalid."""
    if configured.strip():
        path = Path(os.path.expandvars(os.path.expanduser(configured.strip().strip('"'))))
        return str(path) if path.is_file() else None
    found = shutil.which("cdb.exe")
    if found:
        return found
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if not base:
            continue
        for arch in ("x64", "x86", "arm64"):
            path = Path(base) / "Windows Kits" / "10" / "Debuggers" / arch / "cdb.exe"
            if path.is_file():
                return str(path)
    return None


def _field(output: str, name: str) -> str:
    match = re.search(r"(?im)^[ \t]*" + re.escape(name) + r"[ \t]*:[ \t]*([^\r\n]*?)[ \t]*$", output)
    return match.group(1).strip() if match else ""


def parse_output(output: str) -> DumpAnalysis:
    """Extract known fields while keeping the complete debugger output for inspection."""
    result = DumpAnalysis(raw_output=output)
    code = _field(output, "BUGCHECK_CODE")
    if not re.fullmatch(r"(?:0x)?[0-9a-fA-F`]+", code):
        match = re.search(r"(?im)^\s*BugCheck\s+([0-9a-f`]+)\s*,", output)
        code = match.group(1) if match else ""
    if code:
        try:
            result.bugcheck_code = int(code.replace("`", ""), 16)
        except ValueError:
            pass
    match = re.search(r"(?m)^([A-Z][A-Z0-9_]+)\s+\(([0-9a-fA-F]+)\)\s*$", output)
    if match:
        result.bugcheck_name = match.group(1)
    result.arguments = [m.group(0).strip() for m in re.finditer(r"(?im)^Arg[1-4]:[^\r\n]*", output)]
    result.probable_cause = _field(output, "Probably caused by")
    result.image_name = _field(output, "IMAGE_NAME")
    result.module_name = _field(output, "MODULE_NAME")
    result.process_name = _field(output, "PROCESS_NAME")
    result.failure_bucket = _field(output, "FAILURE_BUCKET_ID")
    stack = re.search(r"(?ims)^\s*STACK_TEXT\s*:\s*\n(.*?)(?=\n\s*\n|\n[A-Z][A-Z0-9_]+\s*:|\Z)", output)
    if stack:
        result.stack = stack.group(1).strip()
    if re.search(r"(?i)(symbols could not be loaded|unable to load image|unable to verify timestamp|incorrect symbols|symbol file could not be found|unqualified symbol|symbols are wrong)", output):
        result.warnings.append("Отладчик сообщил о проблемах с символами или образами; вывод может быть неполным или неточным.")
    # A dump header alone does not mean !analyze -v ran successfully.
    has_analysis = bool(re.search(r"(?i)bugcheck analysis", output))
    if has_analysis and result.bugcheck_code is not None:
        result.status = "partial" if result.warnings else "ok"
        result.message = "Разбор выполнен." if not result.warnings else "Разбор выполнен с предупреждениями."
    elif result.bugcheck_code is not None:
        result.status = "partial"
        result.message = "Код остановки извлечён, но полный вывод !analyze -v не получен. Проверьте текст отладчика."
    else:
        result.status = "error"
        result.message = "Не удалось извлечь код остановки. Файл может быть повреждён или не являться дампом ядра; проверьте вывод отладчика."
    return result


def analyze_dump(path: str, cdb: str, online_symbols: bool = False, timeout: int = 180) -> DumpAnalysis:
    """Run cdb without a shell; the file name is never interpreted as a debugger command."""
    try:
        cache = data_dir() / "symbols"
        cache.mkdir(parents=True, exist_ok=True)
        symbols = f"srv*{cache}*https://msdl.microsoft.com/download/symbols" if online_symbols else str(cache)
        env = os.environ.copy()
        env.pop("_NT_SYMBOL_PATH", None)
        env.pop("_NT_ALT_SYMBOL_PATH", None)
        result = subprocess.run(
            [cdb, "-y", symbols, "-z", path, "-c", "!analyze -v; q"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding=locale.getpreferredencoding(False), errors="replace",
            timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), env=env,
        )
        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        parsed = parse_output(output)
        if result.returncode != 0:
            parsed.status = "error"
            parsed.message = f"Отладчик завершился с кодом {result.returncode}. Проверьте доступ к дампу и вывод отладчика."
        return parsed
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(locale.getpreferredencoding(False), errors="replace")
        return DumpAnalysis(status="error", message=f"Превышено время анализа ({timeout} сек.).", raw_output=output)
    except OSError as exc:
        return DumpAnalysis(status="error", message=f"Не удалось запустить отладчик: {exc}")
