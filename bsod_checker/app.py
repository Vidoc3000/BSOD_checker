"""Tkinter desktop interface. No network access or third-party dependencies."""
from __future__ import annotations

import json
import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__, diagnostics, tweaks

BG = "#0e1421"
PANEL = "#172132"
TEXT = "#edf2fa"
MUTED = "#9aabc1"
ACCENT = "#5ec9bc"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BSOD Checker")
        self.geometry("1100x760")
        self.minsize(820, 620)
        self.configure(bg=BG)
        self.report = None
        self.items = {}
        self.results = queue.Queue()
        self.settings_path = tweaks.data_dir() / "settings.json"
        self.days = tk.StringVar(value="30")
        self.limit = tk.StringVar(value="100")
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
        style.configure("Section.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 15, "bold"))
        style.configure("TButton", padding=(14, 9), background="#26384e", foreground=TEXT, borderwidth=0, font=("Segoe UI", 10))
        style.map("TButton", background=[("active", "#38516c"), ("disabled", "#202c3b")], foreground=[("disabled", MUTED)])
        style.configure("Accent.TButton", background=ACCENT, foreground="#071d20", font=("Segoe UI", 10, "bold"))
        style.map("Accent.TButton", background=[("active", "#87ded3"), ("disabled", "#426861")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG, foreground=MUTED, padding=(17, 12), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", ACCENT)])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=32, borderwidth=0)
        style.configure("Treeview.Heading", background="#223149", foreground=MUTED, font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", "#285452")], foreground=[("selected", "white")])
        style.configure("TEntry", fieldbackground=PANEL, foreground=TEXT, insertcolor=TEXT, padding=6)

    def _load_settings(self):
        try:
            data = json.loads(self.settings_path.read_text(encoding="utf-8"))
            days, limit = int(data.get("days", 30)), int(data.get("max_events", 100))
            if 1 <= days <= 365 and 1 <= limit <= 500:
                self.days.set(str(days)); self.limit.set(str(limit))
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _build(self):
        header = ttk.Frame(self, padding=(28, 22, 28, 12))
        header.pack(fill="x")
        ttk.Label(header, text="◈  BSOD CHECKER", foreground=ACCENT, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(header, text="Диагностика сбоев Windows", style="Title.TLabel").pack(anchor="w", pady=(7, 2))
        ttk.Label(header, text="Локальный анализ событий и дампов · без отправки данных", style="Muted.TLabel").pack(anchor="w")
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=28, pady=(10, 0))
        self.analysis = ttk.Frame(self.tabs, padding=(0, 20, 0, 10))
        self.recs = ttk.Frame(self.tabs, padding=(0, 20, 0, 10))
        self.settings = ttk.Frame(self.tabs, padding=(0, 20, 0, 10))
        self.about = ttk.Frame(self.tabs, padding=(0, 20, 0, 10))
        self.tweaks_tab = ttk.Frame(self.tabs, padding=(0, 20, 0, 10))
        for frame, name in [(self.analysis, "Анализ"), (self.recs, "Рекомендации"), (self.settings, "Настройки"), (self.about, "О программе"), (self.tweaks_tab, "Твики")]:
            self.tabs.add(frame, text=name)
        self._analysis_tab(); self._recommendations_tab(); self._settings_tab(); self._about_tab(); self._tweaks_tab()
        self.status = tk.StringVar(value="Готово к анализу")
        footer = ttk.Frame(self, padding=(28, 10))
        footer.pack(fill="x")
        ttk.Label(footer, textvariable=self.status, style="Muted.TLabel").pack(side="left")
        ttk.Label(footer, text="ПРИВАТНО  /  ЛОКАЛЬНО", foreground=ACCENT, font=("Segoe UI", 8, "bold")).pack(side="right")

    def _analysis_tab(self):
        row = ttk.Frame(self.analysis); row.pack(fill="x")
        ttk.Label(row, text="Обзор системы", style="Section.TLabel").pack(side="left")
        self.scan_button = ttk.Button(row, text="▶  Начать анализ", style="Accent.TButton", command=self.start_scan)
        self.scan_button.pack(side="right")
        ttk.Button(row, text="Экспорт JSON", command=self.export).pack(side="right", padx=8)
        self.summary = tk.StringVar(value="Запустите анализ, чтобы проверить события и наличие дампов памяти.")
        ttk.Label(self.analysis, textvariable=self.summary, style="Muted.TLabel", wraplength=960).pack(anchor="w", pady=(12, 16))
        ttk.Label(self.analysis, text="ОБНАРУЖЕННЫЕ СОБЫТИЯ И ДАМПЫ", foreground=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 7))
        table = ttk.Frame(self.analysis); table.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(table, columns=("time", "type", "detail"), show="headings", selectmode="browse", height=8)
        for col, label, width in [("time", "ВРЕМЯ", 190), ("type", "ИСТОЧНИК", 170), ("detail", "СВЕДЕНИЯ", 440)]:
            self.tree.heading(col, text=label); self.tree.column(col, width=width, minwidth=90, stretch=True)
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set); scroll.pack(side="right", fill="y"); self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._select_item)
        ttk.Label(self.analysis, text="ПОДРОБНОСТИ", foreground=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(14, 7))
        self.details = self._text(self.analysis, height=6)
        self._set_text(self.details, "Выберите событие или дамп в списке, чтобы увидеть подробности.")

    def _text(self, parent, height=12):
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.pack(fill="both", expand=True)
        widget = tk.Text(frame, height=height, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief="flat", wrap="word", padx=14, pady=12, font=("Segoe UI", 10), spacing3=5)
        scroll = ttk.Scrollbar(frame, command=widget.yview); widget.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y"); widget.pack(fill="both", expand=True)
        return widget

    @staticmethod
    def _set_text(widget, value):
        widget.configure(state="normal"); widget.delete("1.0", "end"); widget.insert("1.0", value); widget.configure(state="disabled")

    def _recommendations_tab(self):
        ttk.Label(self.recs, text="Рекомендации", style="Section.TLabel").pack(anchor="w")
        ttk.Label(self.recs, text="Направления проверки на основе собранных данных, а не окончательный диагноз.", style="Muted.TLabel", wraplength=900).pack(anchor="w", pady=(6, 18))
        self.rec_text = self._text(self.recs)
        self._set_text(self.rec_text, "После анализа здесь появятся рекомендации по диагностике и стабильности системы.")

    def _settings_tab(self):
        ttk.Label(self.settings, text="Параметры анализа", style="Section.TLabel").pack(anchor="w")
        ttk.Label(self.settings, text="Настройки хранятся локально для текущего пользователя.", style="Muted.TLabel").pack(anchor="w", pady=(6, 24))
        for label, variable, hint in [("Период поиска событий, дней", self.days, "От 1 до 365 дней"), ("Максимум событий для проверки", self.limit, "От 1 до 500; ограничение применяется до фильтрации источников")]:
            ttk.Label(self.settings, text=label).pack(anchor="w", pady=(12, 5))
            ttk.Entry(self.settings, textvariable=variable, width=18).pack(anchor="w")
            ttk.Label(self.settings, text=hint, style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        ttk.Button(self.settings, text="Сохранить настройки", style="Accent.TButton", command=self.save_settings).pack(anchor="w", pady=28)

    def _about_tab(self):
        ttk.Label(self.about, text="О программе", style="Section.TLabel").pack(anchor="w")
        text = (f"BSOD Checker  ·  версия {__version__}\n\n"
                "Помогает собрать первые признаки системных сбоев: события BugCheck, Kernel-Power 41 и EventLog 6008, а также список файлов дампов. "
                "События о внезапном выключении не обязательно означают синий экран.\n\n"
                "Содержимое дампов не разбирается, виновный драйвер автоматически не определяется. Для углублённой диагностики используйте WinDbg и !analyze -v. "
                "Дамп может отсутствовать, если его создание отключено или сбой не позволил его записать.\n\n"
                "Приложение работает локально и не отправляет данные в сеть. Чтение некоторых журналов и дампов может требовать запуска от имени администратора. "
                "Данные отчёта могут содержать имена пользователей и пути к файлам — проверьте их перед передачей другим людям.")
        ttk.Label(self.about, text=text, style="Muted.TLabel", wraplength=850, justify="left").pack(anchor="w", pady=20)

    def _tweaks_tab(self):
        ttk.Label(self.tweaks_tab, text="Тонкая настройка", style="Section.TLabel").pack(anchor="w")
        ttk.Label(self.tweaks_tab, text="Необязательные изменения только для текущего пользователя. Перед применением сохраняется исходное значение реестра.", style="Muted.TLabel", wraplength=900).pack(anchor="w", pady=(6, 18))
        for tweak_id, tweak in tweaks.TWEAKS.items():
            card = ttk.Frame(self.tweaks_tab, style="Card.TFrame", padding=18); card.pack(fill="x", pady=(0, 10))
            actions = ttk.Frame(card, style="Card.TFrame"); actions.pack(side="right", padx=(15, 0))
            ttk.Button(actions, text="Применить", command=lambda i=tweak_id: self.change_tweak(i, False)).pack(side="left", padx=4)
            ttk.Button(actions, text="Восстановить", command=lambda i=tweak_id: self.change_tweak(i, True)).pack(side="left")
            ttk.Label(card, text=tweak["title"], style="Card.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w")
            ttk.Label(card, text=tweak["description"], style="Card.TLabel", foreground=MUTED, wraplength=560, justify="left").pack(anchor="w", pady=(5, 0))
        ttk.Label(self.tweaks_tab, text="Восстановление вернёт состояние до первого применения этого твика и может перезаписать последующие ручные изменения.", style="Muted.TLabel", wraplength=900).pack(anchor="w", pady=10)

    def _numbers(self):
        try:
            days, limit = int(self.days.get()), int(self.limit.get())
            if not 1 <= days <= 365 or not 1 <= limit <= 500: raise ValueError
            return days, limit
        except ValueError:
            messagebox.showerror("Неверные настройки", "Укажите период 1–365 дней и максимум 1–500 событий.", parent=self)
            return None

    def save_settings(self):
        values = self._numbers()
        if not values: return
        try:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            self.settings_path.write_text(json.dumps({"days": values[0], "max_events": values[1]}, indent=2), encoding="utf-8")
            self.status.set("Настройки сохранены")
        except OSError as exc:
            messagebox.showerror("Ошибка сохранения", str(exc), parent=self)

    def start_scan(self):
        values = self._numbers()
        if not values: return
        self.scan_button.configure(state="disabled"); self.status.set("Идёт анализ. Это может занять до минуты…")
        def work():
            try: self.results.put((diagnostics.collect(*values), None))
            except Exception as exc: self.results.put((None, str(exc)))
        threading.Thread(target=work, daemon=True).start()
        self.after(100, self._poll)

    def _poll(self):
        try: report, error = self.results.get_nowait()
        except queue.Empty:
            self.after(100, self._poll); return
        self.scan_button.configure(state="normal")
        if error:
            self.status.set("Ошибка анализа"); messagebox.showerror("Ошибка анализа", error, parent=self); return
        self.report = report
        self.tree.delete(*self.tree.get_children()); self.items.clear()
        for event in report.events:
            code = diagnostics.bugcheck_code(event)
            label = f"Код 0x{code:08X}" if code is not None else ("Неожиданное выключение" if event.event_id in (41, 6008) else "Код не извлечён")
            item = self.tree.insert("", "end", values=(event.time[:19].replace("T", " "), f"Событие {event.event_id}", label))
            self.items[item] = f"{event.provider} · ID {event.event_id}\n{event.time}\n\n{event.message or 'Текст события недоступен.'}"
        for dump in report.dumps:
            item = self.tree.insert("", "end", values=(dump.modified.replace("T", " "), "Дамп памяти", dump.path))
            self.items[item] = f"{dump.path}\nИзменён: {dump.modified}\nРазмер: {dump.size:,} байт\n\nСодержимое дампа не анализировалось."
        warning = "  ⚠ " + " | ".join(report.warnings) if report.warnings else ""
        self.summary.set(f"Событий: {len(report.events)}  ·  Дампов: {len(report.dumps)}  ·  Период событий: {report.days} дн." + warning)
        self._set_text(self.details, "Выберите событие или дамп в списке." if self.items else "Данные не найдены. Отсутствие событий или дампов не исключает BSOD.\n" + "\n".join(report.warnings))
        recs = diagnostics.recommendations(report)
        self._set_text(self.rec_text, "\n\n".join(f"{title}\n{body}" for title, body in recs))
        self.status.set("Анализ завершён" if not report.warnings else "Анализ завершён с предупреждениями")

    def _select_item(self, event=None):
        selection = self.tree.selection()
        if selection: self._set_text(self.details, self.items.get(selection[0], ""))

    def export(self):
        if self.report is None:
            messagebox.showinfo("Экспорт", "Сначала выполните анализ.", parent=self); return
        if not messagebox.askyesno("Конфиденциальность", "Отчёт содержит полные сообщения событий и пути к файлам. Сохранить его?", parent=self): return
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
