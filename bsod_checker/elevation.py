"""Explicit, user-confirmed restart via the Windows UAC prompt."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import subprocess
import sys


def is_elevated() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAnAdmin())
    except (AttributeError, OSError):
        return False


def _shell_execute(executable: str, arguments: str, working_directory: str) -> int:
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    function = shell.ShellExecuteW
    function.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                         ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    function.restype = ctypes.c_void_p
    return function(None, "runas", executable, arguments, working_directory, 1) or 0


def restart_as_admin() -> None:
    """Launch a new instance; caller closes the current window only on success."""
    if os.name != "nt":
        raise OSError("Запуск с повышенными правами доступен только в Windows.")
    executable = sys.executable
    if getattr(sys, "frozen", False):
        arguments = ""
        working_directory = str(Path(executable).resolve().parent)
    else:
        main_script = Path(__file__).resolve().parent.parent / "main.py"
        arguments = subprocess.list2cmdline([str(main_script)])
        working_directory = str(main_script.parent)
    result = _shell_execute(executable, arguments, working_directory)
    if result <= 32:
        # This also covers cancelling the UAC prompt. Keep the existing report open.
        raise OSError("Запуск от имени администратора отменён или завершился ошибкой. Текущий отчёт сохранён в окне.")
