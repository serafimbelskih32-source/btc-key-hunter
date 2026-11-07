#!/usr/bin/env python3
"""
bitcoin_manager.py — управление Bitcoin Core для BTC Key Hunter.
Проверяет установку, скачивает блокчен, находит существующую копию.
"""

import os
import sys
import json
import subprocess
import shutil
import time
from pathlib import Path
from urllib.request import urlopen
import threading

class BitcoinManager:
    def __init__(self):
        self.bitcoin_path = Path("C:\\Program Files\\Bitcoin\\bitcoin-qt.exe")
        self.bitcoin_data_dir = Path(os.getenv("APPDATA")) / "Bitcoin"
        self.bitcoin_exe_dir = self.bitcoin_path.parent
        self.blockchain_dir = self.bitcoin_data_dir / "blocks"
        self.chainstate_dir = self.bitcoin_data_dir / "chainstate"

    def is_bitcoin_installed(self) -> bool:
        """Проверяет установлен ли Bitcoin Core."""
        return self.bitcoin_path.exists()

    def is_bitcoin_running(self) -> bool:
        """Проверяет запущен ли Bitcoin Core."""
        try:
            result = subprocess.run(
                ["tasklist"],
                capture_output=True,
                text=True
            )
            return "bitcoin-qt.exe" in result.stdout or "bitcoin.exe" in result.stdout
        except Exception:
            return False

    def get_blockchain_size(self) -> int:
        """Возвращает размер блокчена в байтах."""
        if not self.blockchain_dir.exists():
            return 0

        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(self.blockchain_dir):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except OSError:
                        pass
        except Exception:
            pass

        return total_size

    def get_blockchain_status(self) -> dict:
        """Возвращает статус блокчена."""
        return {
            "installed": self.is_bitcoin_installed(),
            "running": self.is_bitcoin_running(),
            "has_blockchain": self.blockchain_dir.exists(),
            "blockchain_size_gb": round(self.get_blockchain_size() / (1024**3), 2),
            "bitcoin_exe": str(self.bitcoin_path),
            "data_dir": str(self.bitcoin_data_dir),
        }

    def start_bitcoin(self) -> bool:
        """Запускает Bitcoin Core."""
        if not self.is_bitcoin_installed():
            return False

        if self.is_bitcoin_running():
            return True

        try:
            subprocess.Popen(
                [str(self.bitcoin_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(2)
            return self.is_bitcoin_running()
        except Exception as e:
            print(f"Error starting Bitcoin: {e}")
            return False

    def stop_bitcoin(self) -> bool:
        """Останавливает Bitcoin Core."""
        try:
            subprocess.run(
                ["taskkill", "/IM", "bitcoin-qt.exe", "/F"],
                capture_output=True
            )
            time.sleep(1)
            return not self.is_bitcoin_running()
        except Exception:
            return False

    def has_blockchain_copy_elsewhere(self) -> Path:
        """Ищет копию блокчена в других местах."""
        # Проверяем общие места
        common_drives = ["D:\\", "E:\\", "F:\\"]
        common_paths = [
            Path.home() / "bitcoin",
            Path.home() / "Bitcoin",
            Path.home() / ".bitcoin",
        ]

        for drive in common_drives:
            check_path = Path(drive) / "Bitcoin" / "blocks"
            if check_path.exists():
                return check_path.parent

        for check_path in common_paths:
            blocks = check_path / "blocks"
            if blocks.exists():
                return check_path

        return None

    def use_existing_blockchain(self, source_dir: Path) -> bool:
        """Использует существующую копию блокчена."""
        if not source_dir.exists():
            return False

        try:
            source_blocks = source_dir / "blocks"
            source_chainstate = source_dir / "chainstate"

            # Создаем директории если нужно
            self.bitcoin_data_dir.mkdir(parents=True, exist_ok=True)

            # Копируем блокчен
            if source_blocks.exists() and not self.blockchain_dir.exists():
                print(f"Copying blockchain from {source_blocks}...")
                shutil.copytree(source_blocks, self.blockchain_dir)
                print("✓ Blockchain copied")

            # Копируем chainstate
            if source_chainstate.exists() and not self.chainstate_dir.exists():
                print(f"Copying chainstate...")
                shutil.copytree(source_chainstate, self.chainstate_dir)
                print("✓ Chainstate copied")

            return True
        except Exception as e:
            print(f"Error copying blockchain: {e}")
            return False

    def get_bitcoin_info(self) -> dict:
        """Получает информацию о Bitcoin Core через RPC."""
        bitcoin_cli = self.bitcoin_exe_dir / "bitcoin-cli.exe"

        if not bitcoin_cli.exists():
            return {"error": "bitcoin-cli not found"}

        try:
            result = subprocess.run(
                [str(bitcoin_cli), "getblockchaininfo"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr}
        except Exception as e:
            return {"error": str(e)}

def test_bitcoin_manager():
    """Тестирует BitcoinManager."""
    mgr = BitcoinManager()

    print("Bitcoin Core Status")
    print("=" * 50)

    status = mgr.get_blockchain_status()
    print(f"Installed: {status['installed']}")
    print(f"Running: {status['running']}")
    print(f"Has blockchain: {status['has_blockchain']}")
    print(f"Blockchain size: {status['blockchain_size_gb']} GB")

    # Ищем блокчен в других местах
    existing = mgr.has_blockchain_copy_elsewhere()
    if existing:
        print(f"\nFound blockchain copy at: {existing}")
        print("Would you like to use it? (Y/n)")
        # response = input()
        # if response.lower() != 'n':
        #     mgr.use_existing_blockchain(existing)

if __name__ == "__main__":
    test_bitcoin_manager()
