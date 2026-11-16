"""Opt-in per-user registry tweaks with persistent, reversible originals."""
from __future__ import annotations

import json
import os
from pathlib import Path

try:
    import winreg
except ImportError:
    winreg = None

TWEAKS = {
    "extensions": {
        "title": "Показывать расширения файлов",
        "description": "Показывает расширения известных типов файлов в Проводнике. Может потребоваться перезапуск Проводника.",
        "key": r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "value": "HideFileExt", "data": 0,
    },
    "transparency": {
        "title": "Отключить прозрачность интерфейса",
        "description": "Отключает эффекты прозрачности для текущего пользователя. Изменение может вступить в силу после выхода из системы; прирост производительности не гарантирован.",
        "key": r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        "value": "EnableTransparency", "data": 0,
    },
}


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".bsod_checker")
    return Path(base) / "BSODChecker"


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Файл резервных значений повреждён.")
    return data


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp, path)


def apply(tweak_id: str, backup_path: Path | None = None) -> None:
    if winreg is None:
        raise OSError("Твики доступны только в Windows.")
    tweak = TWEAKS[tweak_id]
    path = backup_path or data_dir() / "tweaks-backup.json"
    backup = _load(path)
    # Save before modifying. A second application must never overwrite the original.
    if tweak_id not in backup:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, tweak["key"], 0, winreg.KEY_READ) as key:
                try:
                    value, kind = winreg.QueryValueEx(key, tweak["value"])
                    backup[tweak_id] = {"exists": True, "value": value, "type": kind}
                except FileNotFoundError:
                    backup[tweak_id] = {"exists": False}
        except FileNotFoundError:
            backup[tweak_id] = {"exists": False}
        _save(path, backup)
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, tweak["key"], 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, tweak["value"], 0, winreg.REG_DWORD, tweak["data"])


def restore(tweak_id: str, backup_path: Path | None = None) -> None:
    if winreg is None:
        raise OSError("Твики доступны только в Windows.")
    tweak = TWEAKS[tweak_id]
    path = backup_path or data_dir() / "tweaks-backup.json"
    backup = _load(path)
    if tweak_id not in backup:
        raise ValueError("Нет сохранённого исходного значения для этого твика.")
    original = backup[tweak_id]
    if original["exists"]:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, tweak["key"], 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, tweak["value"], 0, original["type"], original["value"])
    else:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, tweak["key"], 0, winreg.KEY_SET_VALUE) as key:
                try:
                    winreg.DeleteValue(key, tweak["value"])
                except FileNotFoundError:
                    pass
        except FileNotFoundError:
            pass
    del backup[tweak_id]
    _save(path, backup)
