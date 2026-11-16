"""Download and install Microsoft's signed Debugging Tools for Windows on demand."""
from __future__ import annotations

import os
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Callable

from . import dump_analysis

# Microsoft Windows SDK online installer, as referenced by Microsoft's own tooling.
SDK_INSTALLER_URL = "https://go.microsoft.com/fwlink/?linkid=2272610"
MAX_INSTALLER_BYTES = 50 * 1024 * 1024


def _powershell(script: str, installer: Path, timeout: int) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["BSOD_CHECKER_SDK_INSTALLER"] = str(installer)
    return subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def install(progress: Callable[[str], None] | None = None) -> str:
    """Download the official SDK bootstrapper, verify its signature and install CDB.

    Raises an actionable exception on any failure. This installs a system component,
    so the caller must obtain the user's consent before invoking it.
    """
    if os.name != "nt":
        raise RuntimeError("Установка отладчика доступна только в Windows.")
    notify = progress or (lambda _: None)
    with tempfile.TemporaryDirectory(prefix="bsod-checker-sdk-") as temp:
        installer = Path(temp) / "winsdksetup.exe"
        notify("Загрузка установщика Windows SDK с сайта Microsoft…")
        with urllib.request.urlopen(SDK_INSTALLER_URL, timeout=60) as response, installer.open("wb") as target:
            if not response.geturl().lower().startswith("https://"):
                raise RuntimeError("Установщик был перенаправлен на небезопасный адрес.")
            total = 0
            while True:
                block = response.read(1024 * 256)
                if not block:
                    break
                total += len(block)
                if total > MAX_INSTALLER_BYTES:
                    raise RuntimeError("Размер установщика превышает допустимый предел.")
                target.write(block)
            if not total:
                raise RuntimeError("Загружен пустой установщик.")
        notify("Проверка цифровой подписи Microsoft…")
        verify = r'''$ErrorActionPreference = 'Stop'
$s = Get-AuthenticodeSignature -LiteralPath $env:BSOD_CHECKER_SDK_INSTALLER
if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Microsoft Corporation(,|$)') { Write-Error 'Invalid or non-Microsoft signature'; exit 1 }
'''
        result = _powershell(verify, installer, 60)
        if result.returncode:
            raise RuntimeError("Не удалось подтвердить действительную подпись Microsoft. Установщик не запущен. " + result.stderr.strip())
        notify("Установка Debugging Tools for Windows… Подтвердите запрос UAC, если он появится.")
        run = r'''$ErrorActionPreference = 'Stop'
try {
  $p = Start-Process -FilePath $env:BSOD_CHECKER_SDK_INSTALLER -ArgumentList '/features','OptionId.WindowsDesktopDebuggers','/quiet','/norestart' -Verb RunAs -Wait -PassThru
  exit $p.ExitCode
} catch { Write-Error $_; exit 1 }
'''
        result = _powershell(run, installer, 1800)
        if result.returncode not in (0, 3010):
            raise RuntimeError(f"Установка не завершена (код {result.returncode}). {result.stderr.strip()}")
        cdb = dump_analysis.find_cdb()
        if not cdb:
            suffix = " Возможно, требуется перезагрузка." if result.returncode == 3010 else ""
            raise RuntimeError("Установщик завершился, но cdb.exe не найден." + suffix + " Проверьте установку Windows SDK или укажите путь вручную.")
        return cdb
