"""
DARP v8 :: Entry Point
══════════════════════════════════════════════════════════════════
Автоустановка зависимостей + скрытый запуск GUI
"""
import sys, os
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT))
os.chdir(str(ROOT))

# ── Автоустановка зависимостей ────────────────────────────────────
REQUIRED = [
    ("cryptography",  "cryptography"),
    ("pyotp",         "pyotp"),
    ("qrcode",        "qrcode[pil]"),
    ("PIL",           "pillow"),
    ("psutil",        "psutil"),
    ("requests",      "requests"),
]
OPTIONAL = [
    ("sounddevice",   "sounddevice"),
]

def _install(pkg):
    import subprocess
    subprocess.run(
        [sys.executable, "-m", "pip", "install", pkg, "-q",
         "--disable-pip-version-check"],
        capture_output=True)

def check_and_install():
    missing_required = []
    for mod, pkg in REQUIRED:
        try: __import__(mod)
        except ImportError:
            _install(pkg)
            try: __import__(mod)
            except ImportError: missing_required.append(pkg)

    for mod, pkg in OPTIONAL:
        try: __import__(mod)
        except ImportError: _install(pkg)

    if missing_required:
        # Показываем ошибку без консоли через tkinter
        try:
            import tkinter as tk
            from tkinter import messagebox
            r = tk.Tk(); r.withdraw()
            messagebox.showerror(
                "DARP v8 — Ошибка",
                "Не удалось установить зависимости:\n" +
                "\n".join(missing_required) +
                "\n\nПроверьте подключение к интернету.\n"
                "Или выполните вручную:\n"
                "pip install " + " ".join(missing_required)
            )
            r.destroy()
        except Exception: pass
        sys.exit(1)

check_and_install()

# ── Запуск ────────────────────────────────────────────────────────
from core.main_v8 import run_darp_v8
run_darp_v8()
