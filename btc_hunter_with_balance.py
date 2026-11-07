#!/usr/bin/env python3
"""
BTC Key Hunter v3.5 — Rich TUI dashboard + Bitcoin Core RPC batch scanner.
"""
from __future__ import annotations

import hashlib
import secrets
import time
import sys
import os
import json
import socket
import base64
import threading
import queue
import ctypes
import winsound
import struct
import math
from pathlib import Path
from datetime import datetime
from collections import deque

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.style import Style
from rich.align import Align
from rich.segment import Segment

VERSION      = "3.5"
RPC_HOST     = "127.0.0.1"
RPC_PORT     = 8332
RPC_USER     = "bitcoin"
RPC_PASSWORD = "btc_hunter_2024"
BATCH_SIZE   = 2000
LOG_FILE     = Path.home() / "Desktop" / "btc_hunter.log"
BALANCE_FILE = Path.home() / "Desktop" / "ADDRESSES_WITH_BALANCE.txt"
FOUND_FILE   = Path.home() / "Desktop" / "FOUND.txt"

# Выше какого числа целей не считаем "лучшее совпадение" по символам —
# это O(targets) на каждый адрес и с большим списком начнёт тормозить батч.
MAX_TARGETS_FOR_MATCH_STAT = 200

# Выше какого числа строк в targets.txt переходим с обычного set() (точный,
# но ~100 байт/адрес в памяти) на Bloom-фильтр (~5-6 байт/адрес, вероятностный).
BLOOM_THRESHOLD = 50_000
BLOOM_FP_RATE   = 1e-9   # при миллиардах проверок за долгий прогон не захламляет находки

def _app_dir() -> Path:
    """Папка рядом с .exe (frozen) или со скриптом (запуск из исходников)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent

TARGETS_FILE = _app_dir() / "targets.txt"
BLOOM_FILE   = _app_dir() / "targets.bloom"

_DEFAULT_TARGETS_FILE = """\
# Один биткоин-адрес на строку.
# Строки с # и пустые строки игнорируются.
# Программа ОДНОВРЕМЕННО и параллельно:
#   1) ищет точное совпадение с любым адресом из этого списка
#   2) ищет вообще любой адрес с ненулевым балансом (не зависит от списка)
# Оба события просто фиксируются (файл + звук + счётчик) и НЕ
# останавливают сканирование — со списком в десятки миллионов адресов
# одно совпадение не повод прекращать поиск.
# Если строк больше 50 000 — автоматически используется Bloom-фильтр
# (кэшируется в targets.bloom рядом с этим файлом, строится один раз).
12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr
"""

class BloomFilter:
    """
    Компактный вероятностный набор: ~5-6 байт/элемент вместо ~100 у set()
    из строк. Ложные срабатывания настраиваются через fp_rate — при
    BLOOM_FP_RATE=1e-9 ожидаемое число случайных ложных "находок" за весь
    прогон (даже на миллиардах проверенных адресов) кратно меньше единицы.
    """
    __slots__ = ("m", "k", "bits")
    MAGIC = b"BTCHBLM1"

    def __init__(self, m: int, k: int, bits: bytearray | None = None):
        self.m = m
        self.k = k
        self.bits = bits if bits is not None else bytearray((m + 7) // 8)

    @classmethod
    def sized_for(cls, n: int, fp_rate: float = BLOOM_FP_RATE) -> "BloomFilter":
        n = max(n, 1)
        m = max(8, math.ceil(-(n * math.log(fp_rate)) / (math.log(2) ** 2)))
        k = max(1, round((m / n) * math.log(2)))
        return cls(m, k)

    def _indices(self, item: bytes):
        h1, h2 = struct.unpack("<QQ", hashlib.blake2b(item, digest_size=16).digest())
        m = self.m
        for i in range(self.k):
            yield (h1 + i * h2) % m

    def add(self, item: bytes):
        bits = self.bits
        for idx in self._indices(item):
            bits[idx >> 3] |= 1 << (idx & 7)

    def __contains__(self, item: bytes) -> bool:
        bits = self.bits
        for idx in self._indices(item):
            if not (bits[idx >> 3] & (1 << (idx & 7))):
                return False
        return True

    @property
    def size_mb(self) -> float:
        return len(self.bits) / 1024 ** 2

    def save(self, path: Path, n_items: int):
        with open(path, "wb") as f:
            f.write(self.MAGIC)
            f.write(struct.pack("<QQQ", self.m, self.k, n_items))
            f.write(bytes(self.bits))

    @classmethod
    def load(cls, path: Path) -> tuple["BloomFilter", int]:
        with open(path, "rb") as f:
            if f.read(len(cls.MAGIC)) != cls.MAGIC:
                raise ValueError("Повреждённый или несовместимый targets.bloom")
            m, k, n_items = struct.unpack("<QQQ", f.read(24))
            bits = bytearray(f.read())
        return cls(m, k, bits), n_items

def _iter_target_lines(path: Path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line

def _count_target_lines(path: Path) -> int:
    return sum(1 for _ in _iter_target_lines(path))

def init_targets(progress=print) -> tuple[str, "set[str] | BloomFilter", int]:
    """
    Возвращает (mode, data, count):
      mode="exact" -> data это set[str] точных адресов
      mode="bloom" -> data это BloomFilter (вероятностный, для больших списков)
    Создаёт targets.txt при первом запуске. Для файлов > BLOOM_THRESHOLD
    строк строит targets.bloom один раз и переиспользует его, пока
    targets.txt не изменится (сверка по mtime).
    """
    if not TARGETS_FILE.exists():
        TARGETS_FILE.write_text(_DEFAULT_TARGETS_FILE, encoding="utf-8")

    n = _count_target_lines(TARGETS_FILE)

    if n <= BLOOM_THRESHOLD:
        return "exact", set(_iter_target_lines(TARGETS_FILE)), n

    if BLOOM_FILE.exists() and BLOOM_FILE.stat().st_mtime >= TARGETS_FILE.stat().st_mtime:
        progress(f"Загружаю кэш Bloom-фильтра ({BLOOM_FILE.name})...")
        bf, cached_n = BloomFilter.load(BLOOM_FILE)
        return "bloom", bf, cached_n

    progress(f"Строю Bloom-индекс из {n:,} адресов (разово, кэшируется в {BLOOM_FILE.name})...")
    bf = BloomFilter.sized_for(n)
    t0 = time.time()
    for addr in _iter_target_lines(TARGETS_FILE):
        bf.add(addr.encode("ascii", errors="ignore"))
    bf.save(BLOOM_FILE, n)
    progress(f"Готово за {time.time() - t0:.1f}s, занимает {bf.size_mb:.1f} МБ в памяти.")
    return "bloom", bf, n

TARGETS_MODE  = "exact"
TARGETS_DATA: "set[str] | BloomFilter" = set()
TARGETS_COUNT = 0

# ───────────────────────── secp256k1 ─────────────────────────
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def _jac_double(X, Y, Z):
    if Y == 0: return 0, 1, 0
    S  = 4 * X * Y * Y % P
    M  = 3 * X * X % P
    X2 = (M * M - 2 * S) % P
    Y2 = (M * (S - X2) - 8 * pow(Y, 4, P)) % P
    return X2, Y2, 2 * Y * Z % P

def _jac_add_affine(X1, Y1, Z1, x2, y2):
    if Z1 == 0: return x2, y2, 1
    Z1Z1 = Z1 * Z1 % P
    U2   = x2 * Z1Z1 % P
    S2   = y2 * Z1 * Z1Z1 % P
    if U2 == X1:
        return _jac_double(X1, Y1, Z1) if S2 == Y1 else (0, 1, 0)
    H  = (U2 - X1) % P
    R  = (S2 - Y1) % P
    H2 = H * H % P
    H3 = H * H2 % P
    V  = X1 * H2 % P
    X3 = (R * R - H3 - 2 * V) % P
    Y3 = (R * (V - X3) - Y1 * H3) % P
    return X3, Y3, Z1 * H % P

def pubkey_xy(k: int):
    X, Y, Z = 0, 1, 0
    for bit in bin(k)[2:]:
        X, Y, Z = _jac_double(X, Y, Z)
        if bit == "1":
            X, Y, Z = _jac_add_affine(X, Y, Z, GX, GY)
    zi  = pow(Z, -1, P)
    zi2 = zi * zi % P
    return X * zi2 % P, Y * zi2 * zi % P

def hash160(b: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
    except ValueError:
        return hashlib.sha256(hashlib.sha256(b).digest()).digest()

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n    = int.from_bytes(data, "big")
    out  = ""
    while n:
        n, r = divmod(n, 58)
        out  = B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out

def random_privkey() -> int:
    while True:
        k = secrets.randbelow(N)
        if k != 0: return k

def derive(k: int) -> dict:
    x, y    = pubkey_xy(k)
    xb, yb  = x.to_bytes(32, "big"), y.to_bytes(32, "big")
    raw     = k.to_bytes(32, "big")
    pub_unc = b"\x04" + xb + yb
    pub_cmp = (b"\x02" if y % 2 == 0 else b"\x03") + xb
    return {
        "raw":      raw.hex(),
        "wif_cmp":  b58check(b"\x80" + raw + b"\x01"),
        "wif_unc":  b58check(b"\x80" + raw),
        "addr_cmp": b58check(b"\x00" + hash160(pub_cmp)),
        "addr_unc": b58check(b"\x00" + hash160(pub_unc)),
    }

def matches(addr: str, target: str) -> int:
    return sum(1 for i, c in enumerate(addr) if i < len(target) and c == target[i])

def best_match_against_targets(addr: str, targets) -> int:
    """Лучшее посимвольное совпадение addr с любым адресом из targets (только exact-режим)."""
    best = 0
    for t in targets:
        m = matches(addr, t)
        if m > best:
            best = m
    return best

def hit_target(d: dict) -> str | None:
    """
    Возвращает совпавший целевой адрес (exact или bloom-режим из TARGETS_MODE/TARGETS_DATA).
    В bloom-режиме совпадение вероятностное (см. BLOOM_FP_RATE) — крайне редкий
    ложноположительный результат возможен, поэтому found-файл это помечает.
    """
    if TARGETS_MODE == "exact":
        if d["addr_unc"] in TARGETS_DATA:
            return d["addr_unc"]
        if d["addr_cmp"] in TARGETS_DATA:
            return d["addr_cmp"]
        return None
    else:
        if d["addr_unc"].encode("ascii") in TARGETS_DATA:
            return d["addr_unc"]
        if d["addr_cmp"].encode("ascii") in TARGETS_DATA:
            return d["addr_cmp"]
        return None

# ───────────────────── Файловые операции ─────────────────────
_log_lock = threading.Lock()

def log(msg: str):
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}\n"
    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)

def save_balance_address(balance: str, d: dict, which_addr: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _log_lock:
        with open(BALANCE_FILE, "a", encoding="utf-8") as f:
            f.write(
                f"{'='*70}\n"
                f"Время:             {ts}\n"
                f"БАЛАНС:            {balance}\n"
                f"Адрес (найден):    {which_addr}\n"
                f"Адрес (uncomp):    {d['addr_unc']}\n"
                f"Адрес (compressed):{d['addr_cmp']}\n"
                f"WIF (uncomp):      {d['wif_unc']}\n"
                f"WIF (compressed):  {d['wif_cmp']}\n"
                f"Приватный ключ:    {d['raw']}\n"
                f"{'='*70}\n\n"
            )

def save_found(d: dict, target: str) -> Path:
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    note = (
        f"ВНИМАНИЕ: Bloom-режим (вероятностный, FP≈{BLOOM_FP_RATE:g}) — "
        f"сверь адрес вручную, крошечный шанс ложного срабатывания.\n"
        if TARGETS_MODE == "bloom" else ""
    )
    with open(FOUND_FILE, "a", encoding="utf-8") as f:
        f.write(
            f"{'!'*70}\n"
            f"НАЙДЕН ЦЕЛЕВОЙ АДРЕС! {ts}\n"
            f"{note}"
            f"target:            {target}\n"
            f"addr compressed:   {d['addr_cmp']}\n"
            f"addr uncompressed: {d['addr_unc']}\n"
            f"WIF compressed:    {d['wif_cmp']}\n"
            f"WIF uncompressed:  {d['wif_unc']}\n"
            f"raw private key:   {d['raw']}\n"
            f"{'!'*70}\n\n"
        )
    return FOUND_FILE

# ───────────────────────── Bitcoin RPC ─────────────────────────
_scan_lock = threading.Lock()

def bitcoin_rpc_call(method, params=None, return_full=False, timeout=30):
    if params is None: params = []
    payload = json.dumps({"jsonrpc": "1.0", "id": "1", "method": method, "params": params})
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((RPC_HOST, RPC_PORT))
        auth_b64 = base64.b64encode(f"{RPC_USER}:{RPC_PASSWORD}".encode()).decode()
        req = (
            "POST / HTTP/1.1\r\n"
            f"Host: {RPC_HOST}:{RPC_PORT}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Authorization: Basic {auth_b64}\r\n"
            "Connection: close\r\n\r\n"
            f"{payload}"
        )
        sock.sendall(req.encode())
        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            resp += chunk
        sock.close()
        s = resp.decode("utf-8", errors="ignore")
        start = s.find("{")
        if start != -1:
            r = json.loads(s[start:])
            return r if return_full else r.get("result")
        return None
    except Exception:
        return None

def _wait_scan_idle():
    bitcoin_rpc_call("scantxoutset", ["abort"])
    for _ in range(50):
        st = bitcoin_rpc_call("scantxoutset", ["status"], return_full=True)
        if st and st.get("result") is None and st.get("error") is None:
            return
        time.sleep(0.3)

def get_balances_batch(wallets: list) -> dict:
    with _scan_lock:
        try:
            _wait_scan_idle()
            descriptors = []
            for w in wallets:
                descriptors.append(f"addr({w['addr_unc']})")
                descriptors.append(f"addr({w['addr_cmp']})")
            full = bitcoin_rpc_call(
                "scantxoutset", ["start", descriptors],
                return_full=True, timeout=120
            )
            if not full or full.get("error"):
                return {}
            result = full.get("result", {})
            if not result or "unspents" not in result:
                return {}
            addr_amounts: dict = {}
            for utxo in result.get("unspents", []):
                a = utxo.get("address", "")
                addr_amounts[a] = addr_amounts.get(a, 0.0) + float(utxo.get("amount", 0))
            out = {}
            for w in wallets:
                for addr in (w["addr_unc"], w["addr_cmp"]):
                    btc = addr_amounts.get(addr, 0.0)
                    if btc == 0:
                        out[addr] = "0.00000000"
                    elif btc < 0.00001:
                        out[addr] = f"{btc * 100_000_000:.0f}sat"
                    else:
                        out[addr] = f"{btc:.8f}"
            return out
        except Exception:
            return {}

def get_sync_progress() -> tuple[float, int, int]:
    info = bitcoin_rpc_call("getblockchaininfo")
    if info and "verificationprogress" in info:
        return (
            float(info["verificationprogress"]) * 100,
            int(info.get("blocks", 0)),
            int(info.get("headers", 0)),
        )
    return (0.0, 0, 0)

def test_rpc() -> bool:
    result = bitcoin_rpc_call("getblockchaininfo")
    return bool(result and "blocks" in result)

def set_title(title: str):
    try:
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    except Exception:
        pass

class _COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

class _SMALL_RECT(ctypes.Structure):
    _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short),
                ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

class _CONSOLE_SCREEN_BUFFER_INFOEX(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("dwSize", _COORD),
        ("dwCursorPosition", _COORD),
        ("wAttributes", ctypes.c_ushort),
        ("srWindow", _SMALL_RECT),
        ("dwMaximumWindowSize", _COORD),
        ("wPopupAttributes", ctypes.c_ushort),
        ("bFullscreenSupported", ctypes.c_int),
        ("ColorTable", ctypes.c_uint * 16),
    ]

def set_console_theme():
    """
    Перекрашивает палитру консоли под тёмно-серый фон (#1E1E1E) вместо
    стандартного чёрного cmd.exe — как в SVG-скриншоте для GitHub.
    Также немного осветляет 'bright_black' (#3A3A3A), которым рисуются рамки.
    """
    try:
        STD_OUTPUT_HANDLE = -11
        h = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        info = _CONSOLE_SCREEN_BUFFER_INFOEX()
        info.cbSize = ctypes.sizeof(_CONSOLE_SCREEN_BUFFER_INFOEX)
        if not ctypes.windll.kernel32.GetConsoleScreenBufferInfoEx(h, ctypes.byref(info)):
            return
        # COLORREF = 0x00BBGGRR — для серого (R=G=B) порядок не важен
        info.ColorTable[0]  = 0x001E1E1E   # чёрный  -> тёмно-серый фон
        info.ColorTable[8]  = 0x003A3A3A   # bright_black -> светлее серый (рамки/dim-текст)
        info.srWindow.Right  += 1
        info.srWindow.Bottom += 1
        ctypes.windll.kernel32.SetConsoleScreenBufferInfoEx(h, ctypes.byref(info))
    except Exception:
        pass

def alert_found():
    try:
        for _ in range(5):
            winsound.Beep(1000, 300)
            time.sleep(0.1)
    except Exception:
        pass

# ─────────────────────────── Rich UI ─────────────────────────
LOGO = r"""
 ██████╗ ████████╗ ██████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██╔══██╗╚══██╔══╝██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██████╔╝   ██║   ██║         ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██╔══██╗   ██║   ██║         ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██████╔╝   ██║   ╚██████╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝    ╚═╝    ╚═════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"""

# Глобальное состояние для dashboard
class State:
    def __init__(self):
        self.checked        = 0
        self.speed          = 0.0
        self.best_match     = 0
        self.found_count    = 0     # адресов с ненулевым балансом (независимо от targets.txt)
        self.target_hits    = 0     # попаданий в targets.txt/Bloom (не останавливает сканирование)
        self.sync_pct       = 0.0
        self.sync_blk       = 0
        self.sync_hdr       = 0
        self.start_time     = time.time()
        self.last_addrs     = deque(maxlen=22)   # последние адреса для скролла
        self.lock           = threading.Lock()
        self.running        = True

STATE = State()

def _bar(pct: float, width: int = 20) -> str:
    filled = int(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)

def make_header() -> Panel:
    logo_text = Text(LOGO, style="bold bright_yellow")
    version   = Text(f"  v{VERSION}  •  Bitcoin Key Hunter  •  Batch {BATCH_SIZE}×2 addr/req",
                     style="dim yellow", justify="center")
    content   = Align(logo_text + Text("\n") + version, align="center")
    return Panel(content, style="bold yellow", border_style="bright_yellow", padding=(0, 1))

def make_stats() -> Panel:
    s = STATE
    with s.lock:
        elapsed  = time.time() - s.start_time
        h, rem   = divmod(int(elapsed), 3600)
        m, sec   = divmod(rem, 60)
        runtime  = f"{h:02d}:{m:02d}:{sec:02d}"
        checked  = s.checked
        speed    = s.speed
        best     = s.best_match
        found    = s.found_count
        thits    = s.target_hits
        spct     = s.sync_pct
        sblk     = s.sync_blk
        shdr     = s.sync_hdr

    if TARGETS_MODE == "exact":
        tl = max((len(t) for t in TARGETS_DATA), default=0)
    else:
        tl = 34   # типичная длина адреса — для bloom-режима best_match не считается

    # Левый столбец — основная статистика
    left = Table(box=None, show_header=False, padding=(0, 1))
    left.add_column("key",   style="bright_black", width=22)
    left.add_column("value", style="bold white")
    left.add_row("⏱  Время работы",    f"[cyan]{runtime}[/cyan]")
    left.add_row("🔍 Проверено",        f"[bold white]{checked:,}[/bold white]")
    left.add_row("⚡ Скорость",         f"[bold green]{speed:,.0f}[/bold green] [dim]адр/сек[/dim]")
    left.add_row("💰 Найдено балансов", f"[bold {'yellow' if found > 0 else 'white'}]{found}[/bold {'yellow' if found > 0 else 'white'}]")
    left.add_row("🎯 Попаданий в цели", f"[bold {'bright_yellow' if thits > 0 else 'white'}]{thits}[/bold {'bright_yellow' if thits > 0 else 'white'}]")

    # Правый столбец — прогресс
    if TARGETS_MODE == "bloom":
        mb = TARGETS_DATA.size_mb
        targets_label = f"[cyan]{TARGETS_COUNT:,}[/cyan] [dim]адресов, Bloom {mb:.0f} МБ[/dim]"
    elif TARGETS_COUNT == 1:
        targets_label = f"[dim]{next(iter(TARGETS_DATA))[:20]}…[/dim]"
    elif TARGETS_COUNT > 1:
        targets_label = f"[cyan]{TARGETS_COUNT}[/cyan] [dim]адресов (targets.txt)[/dim]"
    else:
        targets_label = "[dim]targets.txt пуст[/dim]"

    match_pct = best / tl * 100 if tl else 0
    right = Table(box=None, show_header=False, padding=(0, 1))
    right.add_column("key",   style="bright_black", width=20)
    right.add_column("value", style="bold white")
    right.add_row("🎯 ЦЕЛИ",            targets_label)
    right.add_row("📍 Лучшее совп.",    f"[magenta]{best}[/magenta][dim]/{tl}[/dim]  [dim]{_bar(match_pct, 14)}[/dim]")
    right.add_row("⛓  Нода (блоков)", f"[bright_blue]{sblk:,}[/bright_blue][dim]/{shdr:,}[/dim]")
    right.add_row("🔄 Синхронизация",  f"[bright_blue]{spct:.1f}%[/bright_blue]  [dim]{_bar(spct, 14)}[/dim]")

    cols = Columns([left, right], equal=True, expand=True)
    return Panel(cols, title="[bold cyan]◆ СТАТИСТИКА ◆[/bold cyan]",
                 style="cyan", border_style="bright_cyan", padding=(0, 1))

def make_feed() -> Panel:
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold bright_black",
        expand=True,
        padding=(0, 0),
    )
    table.add_column("БАЛАНС",  style="bold", width=14, justify="right")
    table.add_column("ТИП",     style="dim",  width=5,  justify="center")
    table.add_column("АДРЕС",   style="white", width=35)
    table.add_column("WIF KEY", style="dim white", no_wrap=True)

    with STATE.lock:
        rows = list(STATE.last_addrs)

    for bal, typ, addr, wif, is_nonzero in rows:
        if is_nonzero:
            bal_text  = Text(bal,  style="bold bright_yellow on dark_orange")
            addr_text = Text(addr, style="bold bright_yellow")
            typ_text  = Text(typ,  style="bold bright_yellow")
        else:
            bal_text  = Text(bal,  style="bright_black")
            addr_text = Text(addr, style="dim white")
            typ_text  = Text(typ,  style="bright_black")
        table.add_row(bal_text, typ_text, addr_text, Text(wif, style="dim"))

    return Panel(table, title="[bold white]◆ ПОТОК АДРЕСОВ ◆[/bold white]",
                 border_style="bright_black", padding=(0, 1))

class _Dynamic:
    """Вызывает fn() при каждом рендере — Live не кэширует результат."""
    def __init__(self, fn):
        self._fn = fn
    def __rich_console__(self, console, options):
        yield self._fn()

def make_layout() -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=10),
        Layout(name="stats",  size=9),
        Layout(name="feed"),
    )
    layout["header"].update(_Dynamic(make_header))
    layout["stats"].update(_Dynamic(make_stats))
    layout["feed"].update(_Dynamic(make_feed))
    return layout

# ─────────────────────────── main ────────────────────────────
def main():
    global TARGETS_MODE, TARGETS_DATA, TARGETS_COUNT

    set_console_theme()
    console = Console()
    os.system("cls")

    console.print("\n[bold yellow]Проверяю подключение к Bitcoin Core...[/bold yellow]")
    if not test_rpc():
        console.print("[bold red]⚠  Нет подключения к Bitcoin Core RPC![/bold red]")
        console.print(f"[dim]server=1 | rpcuser={RPC_USER} | rpcport={RPC_PORT}[/dim]")
        input("\nНажми Enter для выхода.")
        sys.exit(1)

    spct, sblk, shdr = get_sync_progress()
    with STATE.lock:
        STATE.sync_pct = spct
        STATE.sync_blk = sblk
        STATE.sync_hdr = shdr

    console.print(f"[bold green]✓ Подключено![/bold green] Синхронизация: [cyan]{spct:.1f}%[/cyan] (блок {sblk:,}/{shdr:,})")

    TARGETS_MODE, TARGETS_DATA, TARGETS_COUNT = init_targets(
        progress=lambda msg: console.print(f"[dim]{msg}[/dim]")
    )
    if TARGETS_MODE == "bloom":
        console.print(f"[cyan]✓ Bloom-индекс:[/cyan] {TARGETS_COUNT:,} адресов, {TARGETS_DATA.size_mb:.1f} МБ в памяти")
    elif TARGETS_COUNT:
        console.print(f"[cyan]✓ Загружено целей из targets.txt:[/cyan] {TARGETS_COUNT}")
    else:
        console.print("[dim]targets.txt пуст — ищем любой адрес с балансом, без конкретных целей.[/dim]")
    log(f"Старт v{VERSION}. Синхронизация: {spct:.1f}%. Батч: {BATCH_SIZE}. Целей: {TARGETS_COUNT} ({TARGETS_MODE})")
    time.sleep(0.5)

    # Если целей много (или bloom-режим) — не считаем "лучшее совпадение", только точные хиты
    track_best_match = TARGETS_MODE == "exact" and 0 < TARGETS_COUNT <= MAX_TARGETS_FOR_MATCH_STAT

    stop_event = threading.Event()
    batch_q    = queue.Queue(maxsize=3)
    t0         = time.time()

    def generator_worker():
        while not stop_event.is_set():
            batch_q.put([derive(random_privkey()) for _ in range(BATCH_SIZE)])

    threading.Thread(target=generator_worker, daemon=True).start()

    # Поток обновления синхронизации
    def sync_worker():
        while not stop_event.is_set():
            time.sleep(60)
            if stop_event.is_set(): break
            p, b, h = get_sync_progress()
            with STATE.lock:
                STATE.sync_pct = p
                STATE.sync_blk = b
                STATE.sync_hdr = h

    threading.Thread(target=sync_worker, daemon=True).start()

    layout = make_layout()

    try:
        with Live(layout, console=console, refresh_per_second=4, screen=True):
            while True:
                batch    = batch_q.get()
                balances = get_balances_batch(batch)

                new_found  = []
                feed_added = False   # добавляем только 1 строку в деку за батч

                for d in batch:
                    if track_best_match:
                        for addr in (d["addr_unc"], d["addr_cmp"]):
                            m = best_match_against_targets(addr, TARGETS_DATA)
                            if m > STATE.best_match:
                                STATE.best_match = m

                    for addr, wif, label in (
                        (d["addr_unc"], d["wif_unc"], "UNC"),
                        (d["addr_cmp"], d["wif_cmp"], "CMP"),
                    ):
                        bal        = balances.get(addr, "—")
                        is_nonzero = bal not in ("0.00000000", "—")

                        if is_nonzero:
                            # Находки всегда добавляем в деку
                            with STATE.lock:
                                STATE.last_addrs.append((bal, label, addr, wif, True))
                                STATE.found_count += 1
                            save_balance_address(bal, d, addr)
                            log(f"БАЛАНС {bal} | {addr}")
                            new_found.append((bal, addr))
                        elif not feed_added:
                            # Обычный адрес — только первый из батча
                            with STATE.lock:
                                STATE.last_addrs.append((bal, label, addr, wif, False))
                            feed_added = True

                    hit = hit_target(d)
                    if hit is not None:
                        with STATE.lock:
                            STATE.target_hits += 1
                        save_found(d, hit)
                        log(f"НАЙДЕН ЦЕЛЕВОЙ! {hit} | ключ: {d['raw']}")
                        new_found.append(("TARGET", hit))
                        # НЕ останавливаемся — список целей может быть большим (rich-list),
                        # находка одной не значит, что дальше сканировать нечего.

                for bal, addr in new_found:
                    alert_found()

                with STATE.lock:
                    STATE.checked += len(batch)
                    elapsed        = time.time() - t0
                    STATE.speed    = STATE.checked / elapsed if elapsed > 0 else 0

                set_title(f"BTC Hunter v{VERSION} | {STATE.speed:,.0f}/s | {STATE.checked:,} адресов")

    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()

    elapsed = time.time() - t0
    console.print()
    if STATE.target_hits > 0 or STATE.found_count > 0:
        console.print(Panel(
            f"[bold bright_yellow]  Найдено за сессию: {STATE.found_count} с балансом, "
            f"{STATE.target_hits} попаданий в цели  [/bold bright_yellow]\n"
            f"[dim]Баланс-файл: {BALANCE_FILE}[/dim]\n"
            f"[dim]Файл целей:  {FOUND_FILE}[/dim]",
            border_style="bright_yellow", style="bold"
        ))
    console.print(f"\n[dim]Проверено: [bold]{STATE.checked:,}[/bold] адресов за [bold]{elapsed:.0f}[/bold] сек "
                  f"([bold]{STATE.speed:,.0f}[/bold]/s)[/dim]")
    console.print(f"[dim]Лог: {LOG_FILE}[/dim]")
    console.print(f"[dim]Баланс-файл: {BALANCE_FILE}[/dim]")
    log(f"Остановлено. Проверено {STATE.checked} за {elapsed:.0f}s, {STATE.speed:.0f}/s, "
        f"балансов: {STATE.found_count}, целей: {STATE.target_hits}")

if __name__ == "__main__":
    main()
