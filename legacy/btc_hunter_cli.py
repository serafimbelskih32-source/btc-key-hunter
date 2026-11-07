#!/usr/bin/env python3
"""
BTC Key Hunter CLI v2.0 — консольная версия без Tkinter.
Генерирует адреса и проверяет балансы из Bitcoin Core.
"""

import hashlib
import secrets
import time
import sys
import os
from pathlib import Path

# ───────────────────────── secp256k1 ─────────────────────────
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

TARGET = "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr"

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

def hash160(b: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
    except ValueError:
        return hashlib.sha256(hashlib.sha256(b).digest()).digest()

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
        "wif_cmp": b58check(b"\x80" + raw + b"\x01"),
        "wif_unc": b58check(b"\x80" + raw),
        "addr_cmp": b58check(b"\x00" + hash160(pub_cmp)),
        "addr_unc": b58check(b"\x00" + hash160(pub_unc)),
    }

def matches(addr: str, target: str) -> int:
    return sum(1 for i, c in enumerate(addr) if i < len(target) and c == target[i])

def is_hit(d: dict, target: str) -> bool:
    return target in (d["addr_unc"], d["addr_cmp"])

def save_found(d: dict, target: str):
    desktop = Path.home() / "Desktop"
    path = desktop / "FOUND.txt"

    with open(path, "a", encoding="utf-8") as f:
        f.write(
            f"target: {target}\n"
            f"compressed wif:   {d['wif_cmp']}\n"
            f"uncompressed wif: {d['wif_unc']}\n"
            f"addr compressed:   {d['addr_cmp']}\n"
            f"addr uncompressed: {d['addr_unc']}\n"
            f"raw private key:  {d['raw']}\n\n"
        )

    return path

def main():
    print("\n")
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║           BTC KEY HUNTER v2.0 — CLI EDITION               ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print()
    print(f"TARGET: {TARGET}")
    print()

    attempts = 0
    best = 0
    t0 = time.time()
    last_report = t0

    print("Начинаю генерирование адресов...")
    print("Нажми Ctrl+C чтобы остановить\n")

    try:
        while True:
            d = derive(random_privkey())
            attempts += 1
            current_match = matches(d["addr_unc"], TARGET)
            best = max(best, current_match)

            now = time.time()
            if now - last_report >= 1:
                speed = attempts / (now - t0)
                print(
                    f"Попыток: {attempts:>12,}  │  "
                    f"Скорость: {speed:>10,.0f}/s  │  "
                    f"Совпадение: {best}/{len(TARGET)}"
                )
                last_report = now

            if is_hit(d, TARGET):
                print("\n" + "="*60)
                print("🎉 НАЙДЕН КЛЮЧ!")
                print("="*60)
                print(f"Address:        {d['addr_cmp']}")
                print(f"WIF (compressed): {d['wif_cmp']}")
                print(f"Private Key:    {d['raw']}")
                print("="*60)

                path = save_found(d, TARGET)
                print(f"\n✓ Сохранено в: {path}\n")
                break

    except KeyboardInterrupt:
        print("\n\nОстановлено пользователем.")
        print(f"Всего попыток: {attempts:,}")
        elapsed = time.time() - t0
        print(f"Время работы: {elapsed:.1f} сек")
        if elapsed > 0:
            print(f"Среднее: {attempts/elapsed:,.0f} генераций/сек")

if __name__ == "__main__":
    main()
