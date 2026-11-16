"""Desktop interface for local crash diagnosis and optional symbol downloads."""
from __future__ import annotations

import json
import os
import platform
from datetime import datetime
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__, debugger_install, diagnostics, dump_analysis, elevation, tweaks

BG = "#0b1020"
PANEL = "#151e32"
PANEL_2 = "#1b2740"
TEXT = "#f1f5ff"
MUTED = "#98a9c4"
ACCENT = "#70dfd0"
PURPLE = "#a8a5ff"
BORDER = "#273752"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BSOD Checker · диагностика Windows")
        self.geometry("1240x820")
        self.minsize(900, 680)
        self.configure(bg=BG)
        self.report = None
        self.active_dump_path = None
        self.items = {}
        self.results = queue.Queue()
        self.settings_path = tweaks.data_dir() / "settings.json"
        self.days = tk.StringVar(value="30")
        self.limit = tk.StringVar(value="100")
        self.dump_limit = tk.StringVar(value="10")
        self.cdb_path = tk.StringVar(value="")
        self.online_symbols = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Готово к анализу")
        self.metrics = [tk.StringVar(value="—") for _ in range(3)]
        self._load_settings()
        self._style()
        self._build()

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 23, "bold"))
        style.configure("Section.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 16, "bold"))
        style.configure("TButton", padding=(15, 9), background=PANEL_2, foreground=TEXT, borderwidth=0, font=("Segoe UI", 10, "bold"))
        style.map("TButton", background=[("active", "#344963"), ("disabled", "#263044")], foreground=[("disabled", MUTED)])
        style.configure("Accent.TButton", background=ACCENT, foreground="#092c2b", font=("Segoe UI", 10, "bold"))
        style.map("Accent.TButton", background=[("active", "#a2f4e8"), ("disabled", "#426861")])
        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background=BG, foreground=MUTED, padding=(19, 12), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", ACCENT)])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=36, borderwidth=0, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background=PANEL_2, foreground=MUTED, padding=(8, 8), font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", "#2a555d")], foreground=[("selected", "white")])
        style.configure("TEntry", fieldbackground=PANEL, foreground=TEXT, insertcolor=TEXT, padding=8)
        style.configure("TCheckbutton", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.map("TCheckbutton", background=[("active", BG)], foreground=[("active", TEXT)])

    def _load_settings(self):
        try:
            data = json.loads(self.settings_path.read_text(encoding="utf-8"))
            days, limit = int(data.get("days", 30)), int(data.get("max_events", 100))
            dump_limit = int(data.get("max_dumps", 10))
            if 1 <= days <= 365 and 1 <= limit <= 500 and 1 <= dump_limit <= 100:
                self.days.set(str(days)); self.limit.set(str(limit)); self.dump_limit.set(str(dump_limit))
            if isinstance(data.get("cdb_path", ""), str): self.cdb_path.set(data.get("cdb_path", ""))
            if isinstance(data.get("online_symbols", False), bool): self.online_symbols.set(data.get("online_symbols", False))
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _build(self):
        header = ttk.Frame(self, padding=(32, 25, 32, 12)); header.pack(fill="x")
        brand = ttk.Frame(header); brand.pack(fill="x")
        ttk.Label(brand, text="◈", foreground=ACCENT, font=("Segoe UI", 24, "bold")).pack(side="left", padx=(0, 10))
        names = ttk.Frame(brand); names.pack(side="left")
        ttk.Label(names, text="BSOD CHECKER", foreground=TEXT, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(names, text="WINDOWS DIAGNOSTICS", foreground=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        ttk.Label(brand, text="ЛОКАЛЬНАЯ ДИАГНОСТИКА  /  v" + __version__, foreground=MUTED, font=("Segoe UI", 9, "bold")).pack(side="right")
        ttk.Frame(self, height=1, style="Card.TFrame").pack(fill="x", padx=32, pady=(4, 0))
        self.tabs = ttk.Notebook(self); self.tabs.pack(fill="both", expand=True, padx=32, pady=(12, 0))
        self.analysis = ttk.Frame(self.tabs, padding=(0, 20, 0, 8))
        self.recs = ttk.Frame(self.tabs, padding=(0, 20, 0, 8))
        self.settings = ttk.Frame(self.tabs, padding=(0, 20, 0, 8))
        self.about = ttk.Frame(self.tabs, padding=(0, 20, 0, 8))
        self.tweaks_tab = ttk.Frame(self.tabs, padding=(0, 20, 0, 8))
        for frame, name in [(self.analysis, "Обзор и анализ"), (self.recs, "Рекомендации"), (self.tweaks_tab, "Твики"), (self.settings, "Настройки"), (self.about, "О программе")]:
            self.tabs.add(frame, text=name)
        self._analysis_tab(); self._recommendations_tab(); self._settings_tab(); self._about_tab(); self._tweaks_tab()
        footer = ttk.Frame(self, padding=(32, 10, 32, 14)); footer.pack(fill="x")
        ttk.Label(footer, text="●", foreground=ACCENT, font=("Segoe UI", 9)).pack(side="left", padx=(0, 8))
        ttk.Label(footer, textvariable=self.status, style="Muted.TLabel").pack(side="left")
        ttk.Label(footer, text="BSOD CHECKER  ·  WINDOWS", foreground=MUTED, font=("Segoe UI", 8, "bold")).pack(side="right")

    def _heading(self, parent, title, subtitle):
        ttk.Label(parent, text=title, style="Title.TLabel").pack(anchor="w")
        ttk.Label(parent, text=subtitle, style="Muted.TLabel", wraplength=950, justify="left").pack(anchor="w", pady=(4, 17))

    def _analysis_tab(self):
        top = ttk.Frame(self.analysis); top.pack(fill="x")
        actions = ttk.Frame(top); actions.pack(side="right", anchor="n", pady=5)
        self.scan_button = ttk.Button(actions, text="▶   Запустить анализ", style="Accent.TButton", command=self.start_scan); self.scan_button.pack(side="right")
        ttk.Button(actions, text="Экспорт JSON", command=self.export).pack(side="right", padx=8)
        self.import_button = ttk.Button(actions, text="Открыть дамп…", command=self.import_dump); self.import_button.pack(side="right")
        self._heading(top, "Обзор системы", "События Windows и автоматический разбор дампов памяти")
        stats = ttk.Frame(self.analysis); stats.pack(fill="x", pady=(0, 14))
        for i, (title, note, color) in enumerate([("СОБЫТИЯ", "за выбранный период", ACCENT), ("ДАМПЫ", "найдено на компьютере", PURPLE), ("РАЗОБРАНО", "отладчиком Microsoft", "#f2c978")]):
            stats.columnconfigure(i, weight=1, uniform="stats")
            card = ttk.Frame(stats, style="Card.TFrame", padding=(18, 12)); card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0 if i == 2 else 6))
            ttk.Label(card, text=title, style="Card.TLabel", foreground=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w")
            ttk.Label(card, textvariable=self.metrics[i], style="Card.TLabel", foreground=color, font=("Segoe UI", 23, "bold")).pack(anchor="w")
            ttk.Label(card, text=note, style="Card.TLabel", foreground=MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        self.summary = tk.StringVar(value="Запустите анализ. Для разбора дампов потребуется cdb.exe из Debugging Tools for Windows.")
        ttk.Label(self.analysis, textvariable=self.summary, style="Muted.TLabel", wraplength=1080, justify="left").pack(anchor="w", pady=(0, 12))
        panes = ttk.Panedwindow(self.analysis, orient="horizontal"); panes.pack(fill="both", expand=True)
        left = ttk.Frame(panes, padding=(0, 0, 8, 0)); right = ttk.Frame(panes, padding=(8, 0, 0, 0))
        panes.add(left, weight=5); panes.add(right, weight=6)
        ttk.Label(left, text="ИСТОЧНИКИ ДАННЫХ", foreground=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 8))
        table = ttk.Frame(left); table.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(table, columns=("time", "type", "detail"), show="headings", selectmode="browse", height=10)
        for col, label, width in [("time", "ВРЕМЯ", 145), ("type", "ТИП", 100), ("detail", "РЕЗУЛЬТАТ", 200)]:
            self.tree.heading(col, text=label); self.tree.column(col, width=width, minwidth=70, stretch=True)
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set); scroll.pack(side="right", fill="y"); self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._select_item)
        ttk.Label(right, text="ПОДРОБНОСТИ ВЫБРАННОЙ ЗАПИСИ", foreground=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 8))
        self.details = self._text(right, height=12)
        self._set_text(self.details, "Выберите событие или дамп слева.\n\nЗдесь появится структурированный отчёт и полный вывод отладчика.")

    def _text(self, parent, height=12):
        frame = ttk.Frame(parent, style="Card.TFrame"); frame.pack(fill="both", expand=True)
        widget = tk.Text(frame, height=height, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief="flat", wrap="word", padx=18, pady=15, font=("Segoe UI", 10), spacing3=5, selectbackground="#365a72")
        scroll = ttk.Scrollbar(frame, command=widget.yview); widget.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y"); widget.pack(fill="both", expand=True)
        return widget

    @staticmethod
    def _set_text(widget, value):
        widget.configure(state="normal"); widget.delete("1.0", "end"); widget.insert("1.0", value); widget.configure(state="disabled")

    def _recommendations_tab(self):
        self._heading(self.recs, "Рекомендации", "Направления проверки на основе данных, а не окончательный диагноз")
        self.rec_text = self._text(self.recs)
        self._set_text(self.rec_text, "После анализа здесь появятся рекомендации по диагностике и стабильности системы.")

    def _settings_tab(self):
        self._heading(self.settings, "Настройки анализа", "Изменения применяются при следующем запуске анализа")
        grid = ttk.Frame(self.settings); grid.pack(fill="x")
        for i, (label, variable, hint) in enumerate([
            ("Период событий, дней", self.days, "1–365"), ("Максимум событий", self.limit, "1–500 до фильтрации источников"), ("Максимум дампов", self.dump_limit, "1–100, сначала новые")]):
            column = ttk.Frame(grid); column.grid(row=0, column=i, sticky="nw", padx=(0, 30))
            ttk.Label(column, text=label, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 6))
            ttk.Entry(column, textvariable=variable, width=15).pack(anchor="w")
            ttk.Label(column, text=hint, style="Muted.TLabel").pack(anchor="w", pady=(5, 0))
        ttk.Label(self.settings, text="Путь к cdb.exe", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(22, 6))
        pathrow = ttk.Frame(self.settings); pathrow.pack(fill="x")
        ttk.Button(pathrow, text="Обзор…", command=self._browse_cdb).pack(side="right", padx=(8, 0))
        ttk.Entry(pathrow, textvariable=self.cdb_path).pack(side="left", fill="x", expand=True)
        ttk.Label(self.settings, text="Оставьте пустым для автоматического поиска. Если CDB не найден, программа предложит скачать и установить Debugging Tools for Windows.", style="Muted.TLabel", wraplength=950).pack(anchor="w", pady=(5, 12))
        ttk.Checkbutton(self.settings, text="Разрешить загрузку символов с сервера Microsoft", variable=self.online_symbols).pack(anchor="w", pady=(4, 5))
        ttk.Label(self.settings, text="Символы: по умолчанию только локальный кэш; при включении отладчик обращается к Microsoft. Установщик CDB скачивается отдельно после подтверждения.", style="Muted.TLabel", wraplength=950, justify="left").pack(anchor="w")
        ttk.Button(self.settings, text="Сохранить настройки", style="Accent.TButton", command=self.save_settings).pack(anchor="w", pady=22)

    def _browse_cdb(self):
        path = filedialog.askopenfilename(parent=self, title="Выберите cdb.exe", filetypes=[("Отладчик", "cdb.exe"), ("Приложения", "*.exe")])
        if path: self.cdb_path.set(path)

    def _about_tab(self):
        self._heading(self.about, "О программе", "Инструмент для первичной диагностики сбоев Windows")
        text = (f"BSOD Checker  ·  версия {__version__}\n\n"
                "Программа собирает события системного журнала и автоматически анализирует найденные дампы с помощью cdb.exe из Microsoft Debugging Tools for Windows. "
                "Если отладчик отсутствует, программа предложит скачать официальный установщик Microsoft и установить Debugging Tools for Windows.\n\n"
                "Результаты отладчика и рекомендации — зацепки, а не доказательство неисправности конкретного драйвера. "
                "Неполные символы или повреждённый дамп могут привести к неполному результату. Kernel-Power 41 и EventLog 6008 не обязательно означают BSOD.\n\n"
                "По умолчанию используются локальные символы; загрузка с сервера Microsoft включается отдельно в настройках. "
                "Дампы и отчёты могут содержать конфиденциальные данные. Для доступа к журналу или дампам может потребоваться запуск от администратора.")
        ttk.Label(self.about, text=text, style="Muted.TLabel", wraplength=900, justify="left").pack(anchor="w", pady=5)

    def _tweaks_tab(self):
        self._heading(self.tweaks_tab, "Тонкая настройка", "Необязательные изменения только для текущего пользователя")
        for tweak_id, tweak in tweaks.TWEAKS.items():
            card = ttk.Frame(self.tweaks_tab, style="Card.TFrame", padding=20); card.pack(fill="x", pady=(0, 12))
            actions = ttk.Frame(card, style="Card.TFrame"); actions.pack(side="right", padx=(15, 0))
            ttk.Button(actions, text="Применить", command=lambda i=tweak_id: self.change_tweak(i, False)).pack(side="left", padx=4)
            ttk.Button(actions, text="Восстановить", command=lambda i=tweak_id: self.change_tweak(i, True)).pack(side="left")
            ttk.Label(card, text=tweak["title"], style="Card.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w")
            ttk.Label(card, text=tweak["description"], style="Card.TLabel", foreground=MUTED, wraplength=550, justify="left").pack(anchor="w", pady=(7, 0))
        ttk.Label(self.tweaks_tab, text="Исходное значение сохраняется перед применением. Восстановление может перезаписать последующие ручные изменения.", style="Muted.TLabel", wraplength=900).pack(anchor="w", pady=8)

    def _numbers(self):
        try:
            days, limit, dump_limit = int(self.days.get()), int(self.limit.get()), int(self.dump_limit.get())
            if not 1 <= days <= 365 or not 1 <= limit <= 500 or not 1 <= dump_limit <= 100: raise ValueError
            return days, limit, dump_limit
        except ValueError:
            messagebox.showerror("Неверные настройки", "Укажите период 1–365 дней, максимум 1–500 событий и 1–100 дампов.", parent=self)
            return None

    def save_settings(self):
        values = self._numbers()
        if not values: return
        try:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            self.settings_path.write_text(json.dumps({"days": values[0], "max_events": values[1], "max_dumps": values[2], "cdb_path": self.cdb_path.get().strip(), "online_symbols": self.online_symbols.get()}, ensure_ascii=False, indent=2), encoding="utf-8")
            self.status.set("Настройки сохранены")
        except OSError as exc:
            messagebox.showerror("Ошибка сохранения", str(exc), parent=self)

    def start_scan(self):
        values = self._numbers()
        if not values: return
        cdb_path, online = self.cdb_path.get().strip(), self.online_symbols.get()
        self.active_dump_path = None
        self._set_busy(True); self.status.set("Чтение событий и поиск дампов…")
        def work():
            try:
                report = diagnostics.collect(values[0], values[1], cdb_path=cdb_path, online_symbols=online, max_dumps=values[2], progress=lambda msg: self.results.put(("progress", msg)), cdb_resolver=self._resolve_cdb)
                self.results.put(("done", (report, None)))
            except Exception as exc:
                self.results.put(("done", (None, str(exc))))
        threading.Thread(target=work, daemon=True).start()
        self.after(100, self._poll)

    def _set_busy(self, busy):
        state = "disabled" if busy else "normal"
        self.scan_button.configure(state=state)
        self.import_button.configure(state=state)

    def _resolve_cdb(self):
        # The worker must never call Tk directly. The UI answers via the event.
        response = {"event": threading.Event(), "allowed": False}
        self.results.put(("install_request", response))
        response["event"].wait()
        if not response["allowed"]:
            return None, "Установка отменена пользователем."
        try:
            path = debugger_install.install(progress=lambda msg: self.results.put(("progress", msg)))
            self.results.put(("debugger_installed", path))
            return path, None
        except Exception as exc:
            return None, f"Не удалось установить отладчик: {exc}"

    def import_dump(self):
        if os.name != "nt":
            messagebox.showerror("Открыть дамп", "Анализ дампов доступен только в Windows.", parent=self); return
        values = self._numbers()
        if not values: return
        path = filedialog.askopenfilename(parent=self, title="Выберите дамп памяти", filetypes=[("Дампы памяти", "*.dmp"), ("Все файлы", "*.*")])
        if not path: return
        try:
            stat = Path(path).stat()
            if not Path(path).is_file(): raise OSError("Выбранный путь не является файлом.")
        except OSError as exc:
            messagebox.showerror("Не удалось открыть дамп", str(exc), parent=self); return
        dump = diagnostics.Dump(path, datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"), stat.st_size)
        report = self.report or diagnostics.Report(datetime.now().isoformat(timespec="seconds"), platform.platform(), values[0])
        cdb_path, online = self.cdb_path.get().strip(), self.online_symbols.get()
        self.active_dump_path = path
        self._set_busy(True); self.status.set("Подготовка к анализу выбранного дампа…")
        def work():
            try:
                cdb = dump_analysis.find_cdb(cdb_path)
                error = None
                if not cdb: cdb, error = self._resolve_cdb()
                if cdb:
                    self.results.put(("progress", "Анализ выбранного дампа…"))
                    dump.analysis = dump_analysis.analyze_dump(path, cdb, online)
                else:
                    dump.analysis.message = error or "Отладчик cdb.exe не найден."
                # Build a new list; the report currently displayed by Tk is not mutated in the worker.
                from dataclasses import replace
                dumps = [item for item in report.dumps if os.path.normcase(item.path) != os.path.normcase(path)] + [dump]
                dumps.sort(key=lambda item: item.modified, reverse=True)
                warnings = list(report.warnings)
                if not cdb:
                    warnings.append(f"Не удалось разобрать выбранный дамп: {dump.analysis.message}")
                self.results.put(("done", (replace(report, dumps=dumps, warnings=warnings), None)))
            except Exception as exc:
                self.results.put(("done", (None, str(exc))))
        threading.Thread(target=work, daemon=True).start()
        self.after(100, self._poll)

    def _poll(self):
        try:
            while True:
                kind, value = self.results.get_nowait()
                if kind == "progress":
                    self.status.set(value); continue
                if kind == "install_request":
                    value["allowed"] = messagebox.askyesno("Отладчик не найден", "Для разбора дампа необходим CDB. Скачать официальный установщик Windows SDK и установить компонент Debugging Tools for Windows?\n\nПонадобятся интернет, права администратора и подтверждение UAC. Скачанный установщик будет проверен по цифровой подписи Microsoft.", parent=self)
                    value["event"].set()
                    continue
                if kind == "debugger_installed":
                    self.cdb_path.set(value)
                    self.save_settings()
                    self.status.set("Отладчик установлен; продолжается анализ…")
                    continue
                report, error = value
                self._set_busy(False)
                if error:
                    self.status.set("Ошибка анализа"); messagebox.showerror("Ошибка анализа", error, parent=self); return
                self._show_report(report); return
        except queue.Empty:
            self.after(100, self._poll)

    def _show_report(self, report):
        self.report = report
        self.tree.delete(*self.tree.get_children()); self.items.clear()
        if report.resources:
            r = report.resources
            gib = lambda value: f"{value / 1024**3:.1f} ГиБ" if value is not None else "нет данных"
            text = (f"ТЕКУЩИЙ СНИМОК СИСТЕМЫ\n\nСистемный том: {r.disk_path}\n"
                    f"Свободно на томе: {gib(r.disk_free)} из {gib(r.disk_total)}\n"
                    f"Доступно ОЗУ: {gib(r.memory_available)} из {gib(r.memory_total)}\n\n"
                    "Эти значения получены во время анализа, а не в момент сбоя.")
            if r.warnings: text += "\n\n" + "\n".join(r.warnings)
            item = self.tree.insert("", "end", values=(report.generated.replace("T", " "), "Система", "Память и место"))
            self.items[item] = text
        for dump in report.dumps:
            analysis = dump.analysis
            label = f"0x{analysis.bugcheck_code:08X}" if analysis.bugcheck_code is not None else {"skipped": "Не разобран", "error": "Ошибка", "partial": "Неполный разбор", "ok": "Разобран"}.get(analysis.status, analysis.status)
            item = self.tree.insert("", "end", values=(dump.modified.replace("T", " "), "Дамп", label))
            self.items[item] = self._dump_details(dump)
        for event in report.events:
            code = diagnostics.bugcheck_code(event)
            label = f"0x{code:08X}" if code is not None else ("Выключение" if event.event_id in (41, 6008) else event.provider)
            item = self.tree.insert("", "end", values=(event.time[:19].replace("T", " "), f"ID {event.event_id}", label))
            self.items[item] = f"СОБЫТИЕ WINDOWS\n\nИсточник: {event.provider}\nID: {event.event_id}\nВремя: {event.time}\n\nСООБЩЕНИЕ\n{event.message or 'Текст события недоступен.'}"
        self.metrics[0].set(str(len(report.events))); self.metrics[1].set(str(len(report.dumps)))
        self.metrics[2].set(str(sum(d.analysis.status in ("ok", "partial") for d in report.dumps)))
        errors = sum(d.analysis.status == "error" for d in report.dumps)
        warning_text = "  ·  ".join(report.warnings)
        if errors: warning_text += ("  ·  " if warning_text else "") + f"Ошибок разбора: {errors}. Выберите дамп для подробностей."
        self.summary.set(warning_text or f"Анализ завершён. События за {report.days} дн.; выберите запись для подробностей.")
        self._set_text(self.details, "Выберите запись слева." if self.items else "Данные не найдены. Отсутствие событий или дампов не исключает BSOD.\n\n" + "\n".join(report.warnings))
        self._set_text(self.rec_text, "\n\n".join(f"{title}\n{body}" for title, body in diagnostics.recommendations(report)))
        self.status.set("Анализ завершён с предупреждениями" if report.warnings or errors or any(d.analysis.status == "partial" for d in report.dumps) else "Анализ завершён")
        denied = [d for d in report.dumps if d.analysis.error_code == "access_denied"
                  and (self.active_dump_path is None or os.path.normcase(d.path) == os.path.normcase(self.active_dump_path))]
        if denied and not elevation.is_elevated():
            if messagebox.askyesno("Нет доступа к дампу", "Windows отказала в доступе к файлу дампа. Перезапустить BSOD Checker от имени администратора?\n\nПотребуется подтверждение UAC. Несохранённый отчёт и настройки будут потеряны; после перезапуска запустите анализ снова.", parent=self):
                try:
                    elevation.restart_as_admin()
                except OSError as exc:
                    messagebox.showerror("Не удалось перезапустить", str(exc), parent=self)
                else:
                    self.destroy()

    @staticmethod
    def _dump_details(dump):
        a = dump.analysis
        code = f"0x{a.bugcheck_code:08X}" if a.bugcheck_code is not None else "не определён"
        parts = [f"ДАМП ПАМЯТИ\n\nФайл: {dump.path}\nИзменён: {dump.modified}\nРазмер: {dump.size:,} байт\n\nСТАТУС\n{a.message}",
                 f"КОД ОСТАНОВКИ\n{code}" + (f" · {a.bugcheck_name}" if a.bugcheck_name else "")]
        if a.arguments: parts.append("ПАРАМЕТРЫ\n" + "\n".join(a.arguments))
        fields = [("Возможная причина", a.probable_cause), ("Образ", a.image_name), ("Модуль", a.module_name), ("Процесс", a.process_name), ("Идентификатор сбоя", a.failure_bucket), ("Хэш сбоя", a.failure_hash), ("Символ", a.symbol_name), ("Версия ОС", a.os_version), ("Команда стека", a.stack_command)]
        if any(value for _, value in fields):
            parts.append("СВЕДЕНИЯ ОТЛАДЧИКА\n" + "\n".join(f"{name}: {value}" for name, value in fields if value) + "\n\nУказанный модуль — зацепка, не доказанная причина.")
        if a.warnings: parts.append("ПРЕДУПРЕЖДЕНИЯ\n" + "\n".join(a.warnings))
        if a.analysis_values: parts.append("ПОКАЗАТЕЛИ АНАЛИЗА\n" + "\n".join(f"{key}: {value}" for key, value in a.analysis_values.items()))
        if a.stack: parts.append("СТЕК ВЫЗОВОВ\n" + a.stack)
        if a.raw_output: parts.append("ПОЛНЫЙ ВЫВОД ОТЛАДЧИКА\n" + a.raw_output)
        return "\n\n".join(parts)

    def _select_item(self, event=None):
        selection = self.tree.selection()
        if selection: self._set_text(self.details, self.items.get(selection[0], ""))

    def export(self):
        if self.report is None:
            messagebox.showinfo("Экспорт", "Сначала выполните анализ.", parent=self); return
        if not messagebox.askyesno("Конфиденциальность", "Отчёт содержит сообщения событий, пути и полный вывод отладчика, которые могут включать личные данные. Сохранить его?", parent=self): return
        path = filedialog.asksaveasfilename(parent=self, title="Сохранить отчёт", defaultextension=".json", filetypes=[("JSON", "*.json")], initialfile="bsod-report.json")
        if path:
            try:
                Path(path).write_text(json.dumps(self.report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
                self.status.set("Отчёт сохранён")
            except OSError as exc: messagebox.showerror("Ошибка экспорта", str(exc), parent=self)

    def change_tweak(self, tweak_id, restore):
        name = tweaks.TWEAKS[tweak_id]["title"]
        action = "Восстановить исходное значение" if restore else "Применить настройку"
        if not messagebox.askyesno(action, f"{action}: «{name}»?\n\nИзменяется реестр текущего пользователя. Может потребоваться перезапуск Проводника или выход из системы.", parent=self): return
        try:
            (tweaks.restore if restore else tweaks.apply)(tweak_id)
            self.status.set(f"{action}: выполнено")
            messagebox.showinfo("Готово", "Изменение сохранено. При необходимости перезапустите Проводник или выйдите из системы.", parent=self)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            messagebox.showerror("Не удалось изменить настройку", str(exc), parent=self)


def main():
    App().mainloop()
