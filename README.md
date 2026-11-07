<div align="center">

<img src="assets/icon.png" width="110" alt="BTC Key Hunter icon">

# BTC Key Hunter

**Генератор и batch-сканер биткоин-адресов с живым TUI-дашбордом**

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows-0a0a0a?logo=windows)
![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python)
[![Release](https://img.shields.io/github/v/release/serafimbelskih32-source/btc-key-hunter?include_prereleases&color=orange)](../../releases/latest)

[Скачать EXE](../../releases/latest) · [Запуск из исходников](#запуск-из-исходников) · [Настройка Bitcoin Core](#настройка-bitcoin-core)

</div>

---

## Что это

Программа генерирует случайные приватные ключи secp256k1, выводит из них
Bitcoin-адреса (compressed и uncompressed) и батчами проверяет их баланс через
RPC твоей локальной ноды **Bitcoin Core** (`scantxoutset`). Всё находки
сохраняются в файл, с подтверждением звуком.

> **Важно понимать математику.** Пространство приватных ключей — 2²⁵⁶.
> Шанс когда-либо наткнуться на адрес с реальным балансом статистически
> неотличим от нуля, даже проверяя миллиарды ключей в секунду. Это проект
> для изучения криптографии биткоина, работы с Bitcoin Core RPC и построения
> быстрых TUI-интерфейсов на Python — не стратегия заработка.

## Скриншот

<div align="center">
<img src="assets/screenshot.svg" width="900" alt="Дашборд BTC Key Hunter">
</div>

## Возможности

- 🎯 **Список целевых адресов** — `targets.txt` рядом с программой, один адрес на строку (см. ниже)
- ⚡ **Batch-сканирование** — тысячи адресов за один RPC-запрос (`scantxoutset`), оба формата адреса (compressed + uncompressed) разом
- 🖥 **Живой дашборд** на [Rich](https://github.com/Textualize/rich) — скорость, счётчик, лучшее совпадение с таргетом, синхронизация ноды
- 📝 **Логирование** всех событий в `btc_hunter.log`
- 💰 **Автосохранение** находок (полный адрес + WIF + приватный ключ) в `ADDRESSES_WITH_BALANCE.txt`
- 🔔 **Звуковой сигнал** при находке ненулевого баланса
- 🏷 **Заголовок окна** с живой статистикой (скорость, счётчик)
- 📦 Собирается в один **portable .exe** без установки Python

## Скачать

Готовый `.exe` для Windows — на странице **[Releases](../../releases/latest)**.
Python не нужен, запускается сразу.

> EXE работает **только локально с твоей Bitcoin Core** — см. ниже. Если
> скинуть exe другу, у него должна быть своя синхронизированная нода с теми
> же RPC-настройками (или собственными, см. `RPC_*` в начале скрипта).

## Целевые адреса (targets.txt)

При первом запуске рядом с программой (или с `.exe`) создаётся `targets.txt`:

```
# Один биткоин-адрес на строку.
# Строки с # и пустые строки игнорируются.
12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr
```

Можно вписать сколько угодно адресов — программа параллельно ищет совпадение
с любым из них (плюс основная задача — найти *любой* адрес с ненулевым
балансом, это не зависит от списка). Пустой `targets.txt` — ищем только
ненулевой баланс, без конкретных целей. При большом списке (>200 адресов)
дашборд перестаёт считать «лучшее посимвольное совпадение» — слишком дорого
на каждый батч, но точные попадания по-прежнему ловятся мгновенно (`set`).

## Настройка Bitcoin Core

Программе нужен **Bitcoin Core** (любой режим — даже pruned) с включённым RPC:

1. Установи [Bitcoin Core](https://bitcoincore.org/en/download/) и дай ему синхронизироваться
2. Запусти `setup_bitcoin_conf.bat` — он создаст `%APPDATA%\Bitcoin\bitcoin.conf` автоматически,
   **или** пропиши туда вручную:
   ```ini
   server=1
   rpcuser=bitcoin
   rpcpassword=btc_hunter_2024
   rpcallowip=127.0.0.1
   rpcport=8332
   ```
3. Перезапусти Bitcoin Core

## Запуск

**Готовый EXE:** скачай из [Releases](../../releases/latest), запусти — всё включено.

**Из исходников:**
```bash
git clone https://github.com/serafimbelskih32-source/btc-key-hunter.git
cd btc-key-hunter
pip install -r requirements.txt
python btc_hunter_with_balance.py
```
Или просто двойной клик по `run.bat` — он сам найдёт Python и поставит зависимости.

## Файлы на выходе

| Файл | Содержимое |
|---|---|
| `btc_hunter.log` | Полный лог запуска, статистики, находок |
| `ADDRESSES_WITH_BALANCE.txt` | Все адреса с ненулевым балансом: адрес, WIF, приватный ключ |
| `FOUND.txt` | Создаётся только если найден конкретный `TARGET`-адрес из кода |

Все три файла пишутся на Рабочий стол.

## Сборка EXE самостоятельно

```bash
pip install -r requirements.txt pyinstaller
pyinstaller --onefile --console --name btc_hunter --icon btc_hunter.ico btc_hunter_with_balance.py
```
Готовый файл — в `dist/btc_hunter.exe`.

## Как это работает технически

- Собственная реализация secp256k1 (Jacobian-координаты) — без внешних крипто-библиотек
- `scantxoutset` вместо `importaddress`/`listunspent` — не требует импорта в кошелёк, не раздувает wallet.dat
- Адреса генерируются в отдельном потоке и складываются в очередь (`queue.Queue`), пока RPC-поток обрабатывает предыдущий батч — пайплайн без простоя
- `threading.Lock` вокруг `scantxoutset`, т.к. Bitcoin Core не умеет параллельные сканы

## Структура репозитория

```
btc_hunter_with_balance.py   — основное приложение (v3.1)
btc_hunter.ico                — иконка
requirements.txt              — зависимости (rich)
run.bat                       — запуск из исходников
setup_bitcoin_conf.bat        — автонастройка bitcoin.conf
assets/                       — иконка, скриншот
legacy/                       — старые экспериментальные версии (GUI, CLI без батча)
```

## Лицензия

[MIT](LICENSE)
