#!/usr/bin/env python3
"""
BTC Key Hunter v2.0 — генератор ключей с проверкой балансов.
Отображает версию в правом нижнем углу.
"""

import ctypes
import hashlib
import multiprocessing as mp
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
import tkinter as tk
from queue import Empty
from tkinter import messagebox

VERSION = "2.0"
TARGET = "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr"

# ───────────────────────── secp256k1 ─────────────────────────
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


_FAST = False
try:
    import coincurve
    _FAST = True
except ImportError:
    _FAST = False

if _FAST:
    def pubkey_xy(k: int):
        pub = coincurve.PublicKey.from_valid_secret(k.to_bytes(32, "big")).format(False)
        return int.from_bytes(pub[1:33], "big"), int.from_bytes(pub[33:], "big")
else:
    def _jac_double(X, Y, Z):
        if Y == 0:
            return 0, 1, 0
        S = 4 * X * Y * Y % P
        M = 3 * X * X % P
        X2 = (M * M - 2 * S) % P
        Y2 = (M * (S - X2) - 8 * pow(Y, 4, P)) % P
        return X2, Y2, 2 * Y * Z % P

    def _jac_add_affine(X1, Y1, Z1, x2, y2):
        if Z1 == 0:
            return x2, y2, 1
        Z1Z1 = Z1 * Z1 % P
        U2 = x2 * Z1Z1 % P
        S2 = y2 * Z1 * Z1Z1 % P
        if U2 == X1:
            return _jac_double(X1, Y1, Z1) if S2 == Y1 else (0, 1, 0)
        H = (U2 - X1) % P
        R = (S2 - Y1) % P
        H2 = H * H % P
        H3 = H * H2 % P
        V = X1 * H2 % P
        X3 = (R * R - H3 - 2 * V) % P
        Y3 = (R * (V - X3) - Y1 * H3) % P
        return X3, Y3, Z1 * H % P

    def pubkey_xy(k: int):
        X, Y, Z = 0, 1, 0
        for bit in bin(k)[2:]:
            X, Y, Z = _jac_double(X, Y, Z)
            if bit == "1":
                X, Y, Z = _jac_add_affine(X, Y, Z, GX, GY)
        zi = pow(Z, -1, P)
        zi2 = zi * zi % P
        return X * zi2 % P, Y * zi2 * zi % P


# ───────────────────────── хеши и Base58 ─────────────────────────
def _ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out

def hash160(b: bytes) -> bytes:
    return _ripemd160(hashlib.sha256(b).digest())

def random_privkey() -> int:
    while True:
        k = secrets.randbelow(N)
        if k != 0:
            return k

def derive(k: int) -> dict:
    x, y = pubkey_xy(k)
    xb, yb = x.to_bytes(32, "big"), y.to_bytes(32, "big")
    raw = k.to_bytes(32, "big")
    pub_unc = b"\x04" + xb + yb
    pub_cmp = (b"\x02" if y % 2 == 0 else b"\x03") + xb
    return {
        "raw": raw.hex(),
        "wif_unc": b58check(b"\x80" + raw),
        "wif_cmp": b58check(b"\x80" + raw + b"\x01"),
        "addr_unc": b58check(b"\x00" + hash160(pub_unc)),
        "addr_cmp": b58check(b"\x00" + hash160(pub_cmp)),
    }

def matches(addr: str, target: str) -> int:
    return sum(1 for i, c in enumerate(addr) if i < len(target) and c == target[i])

def is_hit(d: dict, target: str) -> bool:
    return target in (d["addr_unc"], d["addr_cmp"])

def get_desktop_dir() -> str:
    if sys.platform == "win32":
        try:
            CSIDL_DESKTOPDIRECTORY = 0x10
            buf = ctypes.create_unicode_buffer(260)
            ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_DESKTOPDIRECTORY, None, 0, buf)
            if buf.value and os.path.isdir(buf.value):
                return buf.value
        except Exception:
            pass
    home = os.path.expanduser("~")
    for cand in (os.path.join(home, "OneDrive", "Desktop"), os.path.join(home, "Desktop")):
        if os.path.isdir(cand):
            return cand
    return home

def save_found(d: dict, target: str) -> str:
    path = os.path.join(get_desktop_dir(), "FOUND.txt")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(
            f"target: {target}\n"
            f"compressed wif:   {d['wif_cmp']}\n"
            f"uncompressed wif: {d['wif_unc']}\n"
            f"addr uncompressed: {d['addr_unc']}\n"
            f"addr compressed:   {d['addr_cmp']}\n"
            f"raw private key:  {d['raw']}\n\n"
        )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path

def worker(target: str, q: "mp.Queue", stop: "mp.Event"):
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except Exception:
        pass
    count, last_report = 0, time.time()
    while not stop.is_set():
        d = derive(random_privkey())
        count += 1
        if is_hit(d, target):
            q.put(("hit", d, count))
            return
        now = time.time()
        if now - last_report >= 0.25:
            q.put(("tick", d, count))
            count, last_report = 0, now

# ───────────────────────── GUI ─────────────────────────
BG = "#0a0a0a"
PANEL = "#141414"
FG = "#e8e8e8"
DIM = "#8a8a8a"
GREEN = "#00c853"
GREEN_DARK = "#0b3d1f"
RED = "#d32f2f"
RED_DARK = "#4a1313"
MONO = ("Consolas", 11)
MONO_B = ("Consolas", 11, "bold")

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.cores = os.cpu_count() or 1
        self.running = False
        self.procs = []
        self.queue = None
        self.stop_event = None
        self.attempts = 0
        self.best = 0
        self.window_n = 0
        self.t0 = time.time()
        self.speed = None

        root.title("BTC Key Hunter v2.0")
        root.configure(bg=BG)
        root.geometry("900x560")
        root.minsize(800, 520)

        header = tk.Frame(root, bg=BG)
        header.pack(fill="x", padx=20, pady=(18, 4))
        tk.Label(header, text="BTC KEY HUNTER", bg=BG, fg=GREEN,
                  font=("Consolas", 20, "bold")).pack(anchor="w")
        tk.Label(header, text="генератор ключей и поиск адресов",
                  bg=BG, fg=DIM, font=("Consolas", 9)).pack(anchor="w")

        addr_frame = tk.Frame(root, bg=PANEL, padx=14, pady=12)
        addr_frame.pack(fill="x", padx=20, pady=10)
        tk.Label(addr_frame, text="Целевой адрес", bg=PANEL, fg=DIM, font=MONO).pack(anchor="w")
        self.target_txt = tk.Text(addr_frame, height=1, bg=PANEL, fg=FG, font=MONO_B,
                                   bd=0, highlightthickness=0)
        self.target_txt.pack(fill="x")
        self.target_txt.insert("1.0", TARGET)
        self.target_txt.config(state="disabled")

        tk.Label(addr_frame, text="Последняя попытка", bg=PANEL, fg=DIM, font=MONO).pack(anchor="w", pady=(10, 0))
        self.attempt_txt = tk.Text(addr_frame, height=1, bg=PANEL, fg=FG, font=MONO_B,
                                    bd=0, highlightthickness=0)
        self.attempt_txt.pack(fill="x")
        self.attempt_txt.tag_configure("hit", background=GREEN, foreground="black")
        self.attempt_txt.config(state="disabled")

        info_frame = tk.Frame(root, bg=PANEL, padx=14, pady=10)
        info_frame.pack(fill="x", padx=20, pady=(0, 10))
        self.info_vars = {}
        for key, label in (("wif_cmp", "compressed wif"), ("wif_unc", "uncompressed wif"),
                            ("addr_unc", "address"), ("raw", "raw private key")):
            row = tk.Frame(info_frame, bg=PANEL)
            row.pack(fill="x", anchor="w")
            tk.Label(row, text=f"{label}:", bg=PANEL, fg=DIM, font=("Consolas", 9), width=18, anchor="w").pack(side="left")
            var = tk.StringVar(value="—")
            tk.Label(row, textvariable=var, bg=PANEL, fg=FG, font=("Consolas", 9)).pack(side="left")
            self.info_vars[key] = var

        self.stats_var = tk.StringVar(value="попыток: 0")
        tk.Label(root, textvariable=self.stats_var, bg=BG, fg=DIM, font=("Consolas", 10)).pack(
            fill="x", padx=24, pady=(0, 6))

        ctrl = tk.Frame(root, bg=BG)
        ctrl.pack(fill="x", padx=20, pady=6)
        tk.Label(ctrl, text=f"Мощность (ядер: {self.cores}):",
                  bg=BG, fg=FG, font=MONO).pack(anchor="w")
        scale_row = tk.Frame(ctrl, bg=BG)
        scale_row.pack(fill="x")
        self.pct = tk.IntVar(value=50)
        self.scale = tk.Scale(scale_row, from_=10, to=100, resolution=10, orient="horizontal",
                               variable=self.pct, bg=BG, fg=FG, troughcolor=PANEL,
                               highlightthickness=0, activebackground=GREEN,
                               command=self._on_slider, length=460)
        self.scale.pack(side="left", fill="x", expand=True)
        self.workers_lbl = tk.StringVar()
        tk.Label(scale_row, textvariable=self.workers_lbl, bg=BG, fg=GREEN, font=MONO_B,
                  width=16).pack(side="left", padx=10)
        self._on_slider(50)

        btn_row = tk.Frame(root, bg=BG)
        btn_row.pack(fill="x", padx=20, pady=14)
        self.start_btn = tk.Button(btn_row, text="СТАРТ", command=self.toggle, bg=GREEN_DARK, fg="white",
                                    font=("Consolas", 12, "bold"), relief="flat", padx=20, pady=8,
                                    activebackground=GREEN, cursor="hand2")
        self.start_btn.pack(side="left")
        tk.Button(btn_row, text="Сгенерировать один раз", command=self.generate_once,
                  bg=PANEL, fg=FG, font=("Consolas", 10), relief="flat", padx=14, pady=8,
                  activebackground="#222", cursor="hand2").pack(side="left", padx=10)

        footer = tk.Frame(root, bg=BG)
        footer.pack(fill="x", padx=20, pady=(0, 10), side="bottom")

        self.status_var = tk.StringVar(
            value=f"{'совпадение сохранится в: ' + os.path.join(get_desktop_dir(), 'FOUND.txt')}")
        tk.Label(footer, textvariable=self.status_var, bg=BG, fg=DIM, font=("Consolas", 8),
                  anchor="w", wraplength=820, justify="left").pack(fill="x", side="left")

        # Версия в правом нижнем углу
        tk.Label(footer, text=f"v{VERSION}", bg=BG, fg=DIM, font=("Consolas", 8)).pack(side="right", padx=5)

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._poll)

    def _on_slider(self, _val):
        n = max(1, round(self.cores * self.pct.get() / 100))
        self.workers_lbl.set(f"{self.pct.get()}% → {n} поток(ов)")

    def generate_once(self):
        d = derive(random_privkey())
        self.attempts += 1
        self.best = max(self.best, matches(d["addr_unc"], TARGET))
        self._render(d)
        if is_hit(d, TARGET):
            path = save_found(d, TARGET)
            messagebox.showinfo("Совпадение!", f"Найден ключ!\nСохранено: {path}")

    def toggle(self):
        self.stop() if self.running else self.start()

    def start(self):
        n = max(1, round(self.cores * self.pct.get() / 100))
        self.queue = mp.Queue()
        self.stop_event = mp.Event()
        self.procs = [mp.Process(target=worker, args=(TARGET, self.queue, self.stop_event), daemon=True)
                      for _ in range(n)]
        for p in self.procs:
            p.start()
        self.running = True
        self.t0, self.window_n = time.time(), 0
        self.start_btn.config(text="ОСТАНОВИТЬ", bg=RED_DARK, activebackground=RED)
        self.scale.config(state="disabled")

    def stop(self):
        if self.stop_event is not None:
            self.stop_event.set()
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            p.join(timeout=1)
        self.procs = []
        self.running = False
        self.start_btn.config(text="СТАРТ", bg=GREEN_DARK, activebackground=GREEN)
        self.scale.config(state="normal")

    def _poll(self):
        if self.running and self.queue is not None:
            got_hit = False
            try:
                while True:
                    kind, d, cnt = self.queue.get_nowait()
                    self.attempts += cnt
                    self.window_n += cnt
                    self.best = max(self.best, matches(d["addr_unc"], TARGET))
                    self._render(d)
                    if kind == "hit":
                        path = save_found(d, TARGET)
                        got_hit = True
                        self.stop()
                        messagebox.showinfo("Совпадение!", f"Найден ключ!\nСохранено: {path}")
                        break
            except Empty:
                pass
            now = time.time()
            if now - self.t0 >= 1:
                self.speed = self.window_n / (now - self.t0)
                self.window_n, self.t0 = 0, now
            self._render_stats()
            if got_hit:
                self.root.after(100, self._poll)
                return
        self.root.after(100, self._poll)

    def _render(self, d: dict):
        self.attempt_txt.config(state="normal")
        self.attempt_txt.delete("1.0", "end")
        self.attempt_txt.insert("1.0", d["addr_unc"])
        for i, c in enumerate(d["addr_unc"]):
            if i < len(TARGET) and c == TARGET[i]:
                self.attempt_txt.tag_add("hit", f"1.{i}", f"1.{i+1}")
        self.attempt_txt.config(state="disabled")
        for key in self.info_vars:
            self.info_vars[key].set(d[key])

    def _render_stats(self):
        s = f"попыток: {self.attempts:,}"
        if self.speed:
            s += f"   скорость: {self.speed:,.0f}/с"
        s += f"   совпадение: {self.best}/{len(TARGET)}"
        self.stats_var.set(s)

    def _on_close(self):
        self.stop()
        self.root.destroy()

def main():
    mp.freeze_support()
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
