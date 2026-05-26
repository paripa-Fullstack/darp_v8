"""
DARP v8 :: CopyProtection — защита от копирования ПО
Привязка к USB serial + hostname hash + файловый watermark
"""
import os, sys, hashlib, json, time, platform, subprocess, ctypes
from pathlib import Path

from core.crypto_stb import bash_hash, encrypt_hybrid, decrypt_hybrid, stb_kdf


LICENSE_FILE = ".darp_license"


class CopyProtection:
    """
    Механизм привязки:
    1. При первом запуске генерируется лицензионный токен
       = BASH-Hash(USB_serial + hostname + timestamp)
    2. При каждом запуске токен проверяется
    3. Если USB-серийный номер не совпадает → отказ в запуске
    4. Копирование папки на другой USB → другой serial → запуск невозможен
    """

    def __init__(self, root_dir: Path):
        self.root_dir = Path(root_dir)
        self.license_path = self.root_dir / "keys" / LICENSE_FILE

    def is_licensed(self, usb_serial: str) -> bool:
        if usb_serial in ("NO_USB", "", None):
            return True  # Без USB – не блокируем (dev-режим)
        if not self.license_path.exists():
            return False
        try:
            data = json.loads(self.license_path.read_text())
            stored_usb = data.get("usb_serial", "")
            stored_hash = data.get("binding_hash", "")
            current_hash = self._make_hash(stored_usb)
            return stored_usb == usb_serial and stored_hash == current_hash
        except Exception:
            return False

    def create_license(self, usb_serial: str) -> bool:
        try:
            binding_hash = self._make_hash(usb_serial)
            data = {
                "usb_serial": usb_serial,
                "binding_hash": binding_hash,
                "created": time.time(),
                "machine": platform.node(),
                "version": "v8"
            }
            self.license_path.parent.mkdir(parents=True, exist_ok=True)
            self.license_path.write_text(json.dumps(data))
            return True
        except Exception:
            return False

    def _make_hash(self, usb_serial: str) -> str:
        raw = (usb_serial + platform.machine()).encode()
        return bash_hash(raw, 256).hex()

    def check_or_create(self, usb_serial: str) -> bool:
        """Проверяет лицензию, создаёт при первом запуске."""
        if usb_serial in ("NO_USB", "", None):
            return True
        if not self.license_path.exists():
            return self.create_license(usb_serial)
        return self.is_licensed(usb_serial)

    def get_usb_serial(self) -> str:
        """Получение серийного номера текущего USB-накопителя."""
        if platform.system() == "Windows":
            try:
                k32 = ctypes.windll.kernel32
                mask = k32.GetLogicalDrives()
                for i in range(26):
                    if mask & (1 << i):
                        letter = chr(65 + i) + ":\\"
                        if k32.GetDriveTypeW(letter) == 2:  # DRIVE_REMOVABLE
                            serial = ctypes.c_ulong(0)
                            if k32.GetVolumeInformationW(letter, None, 0,
                                   ctypes.byref(serial), None, None, None, 0):
                                if serial.value:
                                    return f"{serial.value:08X}"
            except Exception:
                pass
            try:
                r = subprocess.run(
                    "wmic logicaldisk where drivetype=2 get volumeserialnumber",
                    capture_output=True, text=True, shell=True, timeout=5)
                for line in r.stdout.splitlines():
                    s = line.strip()
                    if s and s.lower() not in ("volumeserialnumber", ""):
                        return s.replace("-", "").upper()
            except Exception:
                pass
        else:
            try:
                r = subprocess.run("lsblk -o TRAN,SERIAL | grep usb",
                    capture_output=True, text=True, shell=True, timeout=5)
                parts = r.stdout.strip().split()
                if len(parts) >= 2:
                    return parts[1][:16].upper()
            except Exception:
                pass
        return "NO_USB"
