#!/usr/bin/env python3
"""
launcher.py — главная точка входа для BTC Key Hunter.
Проверяет Bitcoin Core, предлагает скачать если нужно, запускает GUI.
"""

import sys
import tkinter as tk
from tkinter import messagebox, ttk
from pathlib import Path
import time
import threading

try:
    from bitcoin_manager import BitcoinManager
    from btc_key_hunter_gui_v2 import App
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

class LauncherWindow:
    def __init__(self, root):
        self.root = root
        self.mgr = BitcoinManager()
        self.root.title("BTC Key Hunter - Launcher")
        self.root.geometry("500x300")
        self.root.configure(bg="#0a0a0a")

        self.create_widgets()
        self.check_bitcoin()

    def create_widgets(self):
        """Создает элементы интерфейса."""
        main_frame = tk.Frame(self.root, bg="#0a0a0a")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        tk.Label(
            main_frame,
            text="BTC KEY HUNTER",
            bg="#0a0a0a",
            fg="#00c853",
            font=("Consolas", 18, "bold")
        ).pack(pady=(0, 10))

        tk.Label(
            main_frame,
            text="Проверка Bitcoin Core...",
            bg="#0a0a0a",
            fg="#e8e8e8",
            font=("Consolas", 11)
        ).pack(pady=10)

        self.progress = ttk.Progressbar(
            main_frame,
            length=400,
            mode="indeterminate"
        )
        self.progress.pack(pady=10)
        self.progress.start()

        self.status_label = tk.Label(
            main_frame,
            text="",
            bg="#0a0a0a",
            fg="#8a8a8a",
            font=("Consolas", 9),
            wraplength=400,
            justify="left"
        )
        self.status_label.pack(pady=10)

        self.button_frame = tk.Frame(main_frame, bg="#0a0a0a")
        self.button_frame.pack(pady=20)

        self.launch_btn = tk.Button(
            self.button_frame,
            text="ЗАПУСТИТЬ",
            command=self.launch_app,
            bg="#0b3d1f",
            fg="white",
            font=("Consolas", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            state="disabled"
        )
        self.launch_btn.pack(side="left", padx=5)

        self.settings_btn = tk.Button(
            self.button_frame,
            text="ПАРАМЕТРЫ",
            command=self.show_settings,
            bg="#141414",
            fg="#e8e8e8",
            font=("Consolas", 10),
            relief="flat",
            padx=15,
            pady=8
        )
        self.settings_btn.pack(side="left", padx=5)

    def check_bitcoin(self):
        """Проверяет Bitcoin Core в отдельном потоке."""
        def check():
            time.sleep(1)

            status = self.mgr.get_blockchain_status()

            if status['installed']:
                self.update_status("✓ Bitcoin Core найден")

                if status['running']:
                    self.update_status("✓ Bitcoin Core запущен")
                else:
                    self.update_status("Bitcoin Core не запущен. Запускаю...")
                    if self.mgr.start_bitcoin():
                        self.update_status("✓ Bitcoin Core запущен")
                    else:
                        self.update_status("⚠ Не удалось запустить Bitcoin Core")

                if status['has_blockchain']:
                    self.update_status(f"✓ Блокчен найден ({status['blockchain_size_gb']} GB)")
                else:
                    self.update_status("⚠ Блокчен не найден. Синхронизация начнется автоматически")

                self.progress.stop()
                self.launch_btn.config(state="normal")
            else:
                self.update_status("✗ Bitcoin Core не установлен")

                existing = self.mgr.has_blockchain_copy_elsewhere()
                if existing:
                    self.update_status(f"Найдена копия блокчена: {existing}")

                # Предлагаем скачать
                self.progress.stop()
                if messagebox.askyesno(
                    "Bitcoin Core не найден",
                    "Bitcoin Core не установлен.\n\n"
                    "Хочешь скачать его?\n"
                    "(Требуется ~500GB для блокчена)"
                ):
                    self.download_bitcoin()
                else:
                    self.update_status("Bitcoin Core обязателен для работы")

        thread = threading.Thread(target=check, daemon=True)
        thread.start()

    def update_status(self, msg):
        """Обновляет статус."""
        self.status_label.config(text=msg)
        self.root.update_idletasks()

    def download_bitcoin(self):
        """Открывает страницу загрузки Bitcoin Core."""
        import webbrowser
        webbrowser.open("https://bitcoin.org/en/download")
        self.update_status("Откроется страница загрузки в браузере.\n"
                          "Установи Bitcoin Core и попробуй снова.")

    def show_settings(self):
        """Показывает окно параметров."""
        settings_win = tk.Toplevel(self.root)
        settings_win.title("Параметры")
        settings_win.geometry("400x300")
        settings_win.configure(bg="#0a0a0a")

        frame = tk.Frame(settings_win, bg="#0a0a0a")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        tk.Label(frame, text="Bitcoin Core", bg="#0a0a0a", fg="#00c853",
                font=("Consolas", 11, "bold")).pack(anchor="w")

        status = self.mgr.get_blockchain_status()
        info_text = f"""
Bitcoin Core: {'✓ Установлен' if status['installed'] else '✗ Не установлен'}
Статус: {'Работает' if status['running'] else 'Остановлен'}
Блокчен: {status['blockchain_size_gb']} GB
Папка: {status['data_dir']}
"""
        tk.Label(frame, text=info_text, bg="#0a0a0a", fg="#e8e8e8",
                font=("Consolas", 9), justify="left", anchor="w").pack(fill="x", pady=10)

        # Кнопки управления
        btn_frame = tk.Frame(frame, bg="#0a0a0a")
        btn_frame.pack(fill="x", pady=10)

        if status['installed']:
            if status['running']:
                tk.Button(btn_frame, text="Остановить Bitcoin",
                         command=self.mgr.stop_bitcoin,
                         bg="#4a1313", fg="white", relief="flat", padx=10).pack(side="left", padx=5)
            else:
                tk.Button(btn_frame, text="Запустить Bitcoin",
                         command=self.mgr.start_bitcoin,
                         bg="#0b3d1f", fg="white", relief="flat", padx=10).pack(side="left", padx=5)

        tk.Button(btn_frame, text="Скачать Bitcoin Core",
                 command=self.download_bitcoin,
                 bg="#141414", fg="#e8e8e8", relief="flat", padx=10).pack(side="left", padx=5)

    def launch_app(self):
        """Запускает основное приложение."""
        self.progress.stop()
        self.root.destroy()

        root = tk.Tk()
        app = App(root)
        root.mainloop()

def main():
    root = tk.Tk()
    launcher = LauncherWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
