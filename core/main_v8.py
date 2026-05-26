"""
DARP v8 :: Главный модуль
Director And Restricted Partner — Encrypted P2P Terminal
═══════════════════════════════════════════════════════════════
Новшества v8:
  ✅ 2 пароля: доступ + уничтожение (panic password)
  ✅ Позывной — в хедере постоянно виден
  ✅ Песочница (Sandbox) — просмотр файлов из RAM без следов
  ✅ Голос: sounddevice→pyaudio→winsound (работает везде)
  ✅ Автоаудит хоста при запуске
  ✅ USB-блокировка — немедленная при извлечении
  ✅ security.py + geo.py — встроены, всегда работают
  ✅ Tor — расширенный поиск exe (Downloads, AppData, etc.)
  ✅ CMD-окно не открывается (DARP.vbs)
  ✅ Запускается на любом ПК с Python 3.9+
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading, time, os, sys, json
import ctypes, platform, subprocess, hashlib
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent.resolve()

# ── Криптография ──────────────────────────────────────────────────
from core.crypto_stb import (
    stb_kdf, hash_password_stb, verify_password_stb,
    encrypt_hybrid, decrypt_hybrid,
    bash_hash, crypto_info, secure_wipe, SALT_LEN
)
from modules.blockchain_log import EventBlockchain
from modules.stego        import StegoManager
from modules.voice        import VoiceRecorder
from modules.security     import SecurityModule
from modules.geo          import GeoModule
from modules.sandbox      import SandboxManager
from modules.host_scanner import HostScanner

try:
    from core.network import DARPNetwork, CHAT_PORT, PKT_DESTRUCT
    HAS_NETWORK = True
except ImportError:
    HAS_NETWORK = False; CHAT_PORT = 8888; PKT_DESTRUCT = 0xFF

try:
    import pyotp;   HAS_PYOTP   = True
except ImportError: HAS_PYOTP   = False
try:
    import qrcode;  HAS_QRCODE  = True
except ImportError: HAS_QRCODE  = False


# ════════════════════════════════════════════════════════════════════
#  ЦВЕТОВАЯ СХЕМА + ШРИФТЫ
# ════════════════════════════════════════════════════════════════════
C = {
    "bg":    "#050d05", "bg_p":  "#081208",
    "bg_in": "#040d04", "bg_h":  "#030903",
    "fg":    "#00ff41", "fg_d":  "#007a20",
    "fg_b":  "#80ff9f", "fg_w":  "#c8ffd4",
    "acc":   "#00dd38", "warn":  "#ffcc00",
    "danger":"#ff2222", "brd":   "#004d14",
    "brd_b": "#00ff41", "sel":   "#003010",
    "panic": "#ff0000", "cs":    "#00ffff",
}
MONO    = ("Courier New", 11)
MONO_SM = ("Courier New", 9)
MONO_LG = ("Courier New", 13, "bold")

LOGO = [
    "  ██████╗  █████╗ ██████╗ ██████╗  ",
    "  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗ ",
    "  ██║  ██║███████║██████╔╝██████╔╝ ",
    "  ██║  ██║██╔══██║██╔══██╗██╔═══╝  ",
    "  ██████╔╝██║  ██║██║  ██║██║  v8  ",
    "  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ",
]


# ════════════════════════════════════════════════════════════════════
#  ВИДЖЕТЫ
# ════════════════════════════════════════════════════════════════════

class PText(tk.Text):
    def __init__(self, master, **kw):
        kw.setdefault("bg", C["bg_p"]); kw.setdefault("fg", C["fg"])
        kw.setdefault("insertbackground", C["fg"])
        kw.setdefault("selectbackground", C["sel"])
        kw.setdefault("selectforeground", C["fg_b"])
        kw.setdefault("font", MONO); kw.setdefault("bd", 0)
        kw.setdefault("relief", "flat"); kw.setdefault("padx", 8)
        kw.setdefault("pady", 4); kw.setdefault("wrap", tk.WORD)
        super().__init__(master, **kw)
        for tag, fg in [
            ("sys",  C["fg_d"]), ("out",   C["fg_b"]),
            ("in",   C["fg_w"]), ("warn",  C["warn"]),
            ("err",  C["danger"]),("ok",   C["fg"]),
            ("voice","#aa88ff"), ("stego", "#ff88aa"),
            ("chain",C["acc"]),  ("ts",    C["fg_d"]),
            ("cs",   C["cs"]),   ("panic", C["panic"]),
            ("host", "#ffaa44"),
        ]:
            self.tag_configure(tag, foreground=fg)
        self.tag_configure("ts", font=MONO_SM)


class PBtn(tk.Button):
    _S = {
        "n": (C["fg"],     C["bg_p"],  C["sel"],   C["brd"]),
        "d": (C["danger"], "#0d0000",  "#200000",  "#440000"),
        "s": (C["bg"],     C["fg"],    C["fg_b"],  C["fg"]),
        "w": (C["bg"],     C["warn"],  "#ccaa00",  C["warn"]),
        "a": (C["bg"],     C["acc"],   C["fg"],    C["acc"]),
        "p": (C["bg"],     C["panic"], "#cc0000",  C["panic"]),
        "c": (C["bg"],     C["cs"],    C["fg_b"],  C["cs"]),
    }
    def __init__(self, master, text="", v="n", **kw):
        fg, bg, abg, brd = self._S.get(v, self._S["n"])
        kw.update(dict(text=text, fg=fg, bg=bg,
                       activeforeground=fg, activebackground=abg,
                       relief="flat", bd=0, padx=12, pady=5,
                       font=MONO, cursor="hand2",
                       highlightthickness=1,
                       highlightbackground=brd,
                       highlightcolor=brd))
        super().__init__(master, **kw)
        self._bg, self._abg = bg, abg
        self.bind("<Enter>", lambda e: self.config(bg=self._abg))
        self.bind("<Leave>", lambda e: self.config(bg=self._bg))


class PEntry(tk.Entry):
    def __init__(self, master, **kw):
        kw.setdefault("bg", C["bg_in"]); kw.setdefault("fg", C["fg"])
        kw.setdefault("insertbackground", C["fg"])
        kw.setdefault("selectbackground", C["sel"])
        kw.setdefault("font", MONO); kw.setdefault("relief", "flat")
        kw.setdefault("bd", 0); kw.setdefault("highlightthickness", 1)
        kw.setdefault("highlightbackground", C["brd"])
        kw.setdefault("highlightcolor", C["brd_b"])
        super().__init__(master, **kw)


def mkl(parent, text, size=11, color=None, bold=False, bg=None):
    return tk.Label(parent, text=text,
        font=("Courier New", size, "bold" if bold else "normal"),
        fg=color or C["fg_d"], bg=bg or C["bg"])


def hsep(parent, color=None):
    tk.Frame(parent, bg=color or C["brd"], height=1).pack(fill=tk.X)


# ════════════════════════════════════════════════════════════════════
#  USB
# ════════════════════════════════════════════════════════════════════

def get_usb_serial() -> str:
    if platform.system() == "Windows":
        try:
            k32 = ctypes.windll.kernel32
            mask = k32.GetLogicalDrives()
            for i in range(26):
                if mask & (1 << i):
                    letter = chr(65 + i) + ":\\"
                    if k32.GetDriveTypeW(letter) == 2:
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


# ════════════════════════════════════════════════════════════════════
#  AUTH MANAGER — 5FA + 2 пароля
# ════════════════════════════════════════════════════════════════════

class AuthManager:
    """
    5-факторная аутентификация + двойной пароль:
      пароль доступа  — нормальная работа
      пароль паники   — запуск + немедленное самоуничтожение данных
    """
    MAX_ATTEMPTS  = 5
    LOCKOUT_SECS  = 300
    CREDS_FILE    = "credentials_v8.enc"

    def __init__(self, keys_dir: Path):
        self.keys_dir    = keys_dir
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.creds_file  = keys_dir / self.CREDS_FILE
        self.state_file  = keys_dir / ".auth_state_v8"
        self.role        = "DIRECTOR"
        self.callsign    = "UNKNOWN-00"
        self.credentials = {}
        self._creds      = {}

    def is_setup(self) -> bool:
        return self.creds_file.exists()

    def setup(self, password: str, panic_password: str,
              role: str, usb_serial: str) -> str:
        """Создаёт учётные данные. Возвращает TOTP URI."""
        if HAS_PYOTP:
            totp_secret = pyotp.random_base32()
        else:
            import base64
            totp_secret = base64.b32encode(os.urandom(20)).decode().rstrip("=")

        pw_hash    = hash_password_stb(password)
        pan_hash   = hash_password_stb(panic_password)
        host_hash  = hashlib.sha256(platform.node().encode()).hexdigest()
        file_hash  = self._compute_file_hash()

        # Позывной — уникален для USB+пароль
        import random as _r
        _adj = ["ALPHA","BRAVO","CHARLIE","DELTA","ECHO","FOXTROT",
                "GHOST","HAWK","IRON","JADE","KILO","LION","NOVA",
                "OMEGA","PAPA","QUINN","ROMEO","SIGMA","TITAN","WOLF",
                "ZERO","XENON","VIPER","URAL","TALON","STORM","RAPTOR"]
        _seed = int(hashlib.sha256(
            (usb_serial + pw_hash["salt"]).encode()).hexdigest()[:8], 16)
        _r.seed(_seed)
        callsign = (_adj[_r.randint(0, len(_adj)-1)]
                    + "-" + str(_r.randint(10, 99)))

        creds = {
            "role":          role,
            "password_hash": pw_hash,
            "panic_hash":    pan_hash,
            "totp_secret":   totp_secret,
            "usb_serial":    usb_serial,
            "hostname_hash": host_hash,
            "file_hash":     file_hash,
            "callsign":      callsign,
            "created":       time.time(),
            "version":       "v8",
        }

        key  = stb_kdf(password, usb_serial.encode()[:32].ljust(32, b'\x00'))
        data = json.dumps(creds, ensure_ascii=False).encode()
        self.creds_file.write_bytes(encrypt_hybrid(data, key, use_stb=True))
        self._creds = creds
        self.credentials = creds
        self.role = role
        self.callsign = callsign

        if HAS_PYOTP:
            return pyotp.TOTP(totp_secret).provisioning_uri(
                name=f"DARP-{role}", issuer_name="DARP v8")
        return (f"otpauth://totp/DARP-{role}"
                f"?secret={totp_secret}&issuer=DARP_v8")

    def authenticate(self, password: str, totp_code: str,
                     usb_serial: str) -> tuple:
        """
        Возвращает (ok, is_panic, reason):
          is_panic=True — введён пароль паники → приложение запустится,
          но немедленно уничтожит данные.
        """
        if not self._check_lockout():
            return False, False, f"Блокировка {self._lockout_remaining()}с"

        # Пробуем нормальный пароль
        normal_ok = self._load_creds(password, usb_serial)
        # Пробуем пароль паники (с тем же USB)
        panic_ok  = False
        if not normal_ok:
            panic_ok = self._load_creds_panic(password, usb_serial)

        if not normal_ok and not panic_ok:
            self._inc_attempts()
            return False, False, "Неверный пароль"

        creds = self._creds

        # F1: USB
        stored_usb = creds.get("usb_serial", "NO_USB")
        if stored_usb != "NO_USB":
            if usb_serial == "NO_USB":
                self._inc_attempts()
                return False, False, "USB-накопитель не вставлен"
            if stored_usb != usb_serial:
                self._inc_attempts()
                return False, False, "Неверный USB-накопитель"

        # F3: TOTP
        if HAS_PYOTP:
            secret = creds.get("totp_secret", "")
            if not totp_code:
                return False, False, "Введите TOTP-код"
            if secret and not pyotp.TOTP(secret).verify(
                    totp_code.strip(), valid_window=1):
                self._inc_attempts()
                return False, False, "Неверный TOTP-код"

        # F4+F5: предупреждения
        host_hash = hashlib.sha256(platform.node().encode()).hexdigest()
        host_warn = (creds.get("hostname_hash","") and
                     creds.get("hostname_hash") != host_hash)
        file_warn = (creds.get("file_hash","") and
                     creds.get("file_hash") != self._compute_file_hash())

        self._reset_attempts()
        self.role     = creds.get("role", "DIRECTOR")
        self.callsign = creds.get("callsign", "UNKNOWN-00")
        self.credentials = creds

        warns = []
        if host_warn: warns.append("⚠ Имя компьютера изменилось")
        if file_warn: warns.append("⚠ Файлы программы изменились")

        return True, panic_ok, "\n".join(warns)

    def derive_session_key(self, password: str) -> bytes:
        usb  = self._creds.get("usb_serial", "NO_USB")
        salt = (password + usb).encode()[:32].ljust(32, b'\x00')
        return stb_kdf(password, salt, info=b"darp-v8-session")

    # ── Вспомогательные ──────────────────────────────────────────────
    def _load_creds(self, password: str, usb_serial: str) -> bool:
        if not self.creds_file.exists(): return False
        try:
            salt = usb_serial.encode()[:32].ljust(32, b'\x00')
            key  = stb_kdf(password, salt)
            data = decrypt_hybrid(self.creds_file.read_bytes(), key)
            creds = json.loads(data)
            if not verify_password_stb(password, creds.get("password_hash", {})):
                return False
            self._creds = creds
            return True
        except Exception:
            return False

    def _load_creds_panic(self, password: str, usb_serial: str) -> bool:
        """Пробует расшифровать с нормальным паролем, затем верифицировать panic_hash."""
        # Файл всегда зашифрован ОСНОВНЫМ паролем;
        # panic_password хранится как отдельный хэш внутри.
        # Нам нужно попробовать расшифровать — для этого нужен основной пароль.
        # Схема: пробуем расшифровать файл с паролем как обычным,
        # и если fail — нет варианта угадать основной без него.
        # Поэтому panic_password может быть только другим паролем,
        # а файл расшифрован через него напрямую тоже (дублируем шифрование).
        # ПРОСТАЯ РЕАЛИЗАЦИЯ: panic хэш хранится открыто (в отдельном файле)
        # и сравнивается по bcrypt/bashash, файл не трогается.
        panic_file = self.keys_dir / ".panic_hash"
        if not panic_file.exists(): return False
        try:
            data = json.loads(panic_file.read_text())
            if verify_password_stb(password, data):
                # Расшифровываем основной файл через основной пароль из panic_data
                main_pw_encrypted = data.get("main_pw_enc", "")
                if main_pw_encrypted:
                    key2 = stb_kdf(password, b"panic-darp-v8".ljust(32, b'\x00'))
                    main_pw_bytes = decrypt_hybrid(
                        bytes.fromhex(main_pw_encrypted), key2)
                    main_pw = main_pw_bytes.decode()
                    return self._load_creds(main_pw, usb_serial)
        except Exception:
            pass
        return False

    def save_panic_hash(self, panic_password: str, main_password: str):
        """Сохраняет хэш panic-пароля + зашифрованный основной пароль."""
        pan_hash = hash_password_stb(panic_password)
        key2 = stb_kdf(panic_password, b"panic-darp-v8".ljust(32, b'\x00'))
        enc_main = encrypt_hybrid(main_password.encode(), key2, use_stb=True)
        pan_hash["main_pw_enc"] = enc_main.hex()
        (self.keys_dir / ".panic_hash").write_text(
            json.dumps(pan_hash, ensure_ascii=False))

    def _compute_file_hash(self) -> str:
        h = hashlib.sha256()
        for name in ["run.py", "core/crypto_stb.py", "core/main_v8.py"]:
            p = ROOT / name
            if p.exists(): h.update(p.read_bytes())
        return h.hexdigest()

    def _check_lockout(self) -> bool:
        try:
            s = json.loads(self.state_file.read_text())
            if s.get("locked_until", 0) > time.time(): return False
        except Exception: pass
        return True

    def _lockout_remaining(self) -> int:
        try:
            s = json.loads(self.state_file.read_text())
            return max(0, int(s.get("locked_until", 0) - time.time()))
        except Exception: return 0

    def _inc_attempts(self):
        try: s = json.loads(self.state_file.read_text()) if self.state_file.exists() else {}
        except Exception: s = {}
        s["attempts"] = s.get("attempts", 0) + 1
        if s["attempts"] >= self.MAX_ATTEMPTS:
            s["locked_until"] = time.time() + self.LOCKOUT_SECS
            s["attempts"] = 0
        self.state_file.write_text(json.dumps(s))

    def _reset_attempts(self):
        self.state_file.write_text(json.dumps({"attempts": 0, "locked_until": 0}))


# ════════════════════════════════════════════════════════════════════
#  QR-КОД
# ════════════════════════════════════════════════════════════════════

def show_qr_window(parent_root, uri: str):
    win = tk.Toplevel(parent_root)
    win.title("DARP v8 — TOTP Setup")
    win.configure(bg=C["bg"]); win.resizable(False, False)
    win.grab_set(); win.focus_force()

    mkl(win, "TOTP QR-КОД", size=14, bold=True,
        color=C["fg"], bg=C["bg"]).pack(pady=(16, 4))
    mkl(win, "Aegis / Google Authenticator / Raivo",
        size=9, bg=C["bg"]).pack()

    if HAS_QRCODE:
        try:
            qr = qrcode.QRCode(version=None, border=2,
                               error_correction=qrcode.constants.ERROR_CORRECT_M)
            qr.add_data(uri); qr.make(fit=True)
            matrix = qr.get_matrix(); cell = 7; n = len(matrix); sz = n * cell
            outer = tk.Frame(win, bg=C["fg"], padx=2, pady=2); outer.pack(pady=12)
            cv = tk.Canvas(outer, width=sz, height=sz,
                           bg="#ffffff", highlightthickness=0); cv.pack()
            for y, row in enumerate(matrix):
                for x, filled in enumerate(row):
                    if filled:
                        cv.create_rectangle(x*cell, y*cell,
                            x*cell+cell, y*cell+cell,
                            fill="#000000", outline="#000000")
        except Exception as e:
            mkl(win, f"Ошибка QR: {e}", size=9, color=C["warn"], bg=C["bg"]).pack(pady=8)
    else:
        mkl(win, "qrcode не установлен — введите секрет вручную:",
            size=9, color=C["warn"], bg=C["bg"]).pack(pady=(12,4))

    # Секрет
    secret = ""
    try:
        for p in uri.split("?")[1].split("&"):
            if p.startswith("secret="): secret = p[7:]
    except Exception: pass
    if secret:
        mkl(win, "Секретный ключ:", size=9, bg=C["bg"]).pack(pady=(8,2))
        sf = tk.Frame(win, bg=C["bg_p"],
                      highlightbackground=C["brd_b"], highlightthickness=1)
        sf.pack(padx=20, pady=(0,8))
        tk.Label(sf, text=secret, font=("Courier New",15,"bold"),
                 fg=C["fg_b"], bg=C["bg_p"], padx=20, pady=10).pack()

    uf = tk.Frame(win, bg=C["bg_p"]); uf.pack(fill=tk.X, padx=20, pady=(0,6))
    uri_var = tk.StringVar(value=uri)
    tk.Entry(uf, textvariable=uri_var, font=("Courier New",8),
             fg=C["fg_d"], bg=C["bg_p"], relief="flat", state="readonly",
             readonlybackground=C["bg_p"]).pack(fill=tk.X, padx=8, pady=5)

    bf = tk.Frame(win, bg=C["bg"]); bf.pack(pady=(4,16))
    def copy():
        win.clipboard_clear(); win.clipboard_append(uri)
        cb.config(text="Скопировано!")
        win.after(2000, lambda: cb.config(text="Копировать"))
    cb = PBtn(bf, "Копировать", command=copy, width=14); cb.pack(side=tk.LEFT, padx=6)
    PBtn(bf, "Закрыть", v="s", command=win.destroy, width=12).pack(side=tk.LEFT, padx=6)

    win.update_idletasks()
    rx = parent_root.winfo_x() + parent_root.winfo_width()  // 2
    ry = parent_root.winfo_y() + parent_root.winfo_height() // 2
    win.geometry(f"+{rx - win.winfo_width()//2}+{ry - win.winfo_height()//2}")


# ════════════════════════════════════════════════════════════════════
#  ЭКРАН НАСТРОЙКИ
# ════════════════════════════════════════════════════════════════════

class SetupScreen(tk.Frame):
    def __init__(self, root, auth: AuthManager, on_done):
        super().__init__(root, bg=C["bg"])
        self.root = root; self.auth = auth; self.on_done = on_done
        self._build()

    def _build(self):
        self.pack(fill=tk.BOTH, expand=True)
        c = tk.Frame(self, bg=C["bg"])
        c.place(relx=.5, rely=.5, anchor="center")

        for line in LOGO:
            tk.Label(c, text=line, font=("Courier New",14,"bold"),
                     fg=C["fg"], bg=C["bg"]).pack()

        mkl(c, "ПЕРВИЧНАЯ НАСТРОЙКА  —  v8", size=14, bold=True,
            color=C["fg"], bg=C["bg"]).pack(pady=(14,4))
        mkl(c, "5FA: USB + Пароль + TOTP + Хост + Файлы",
            size=9, bg=C["bg"]).pack(pady=(0,8))
        mkl(c, "ДВОЙНОЙ ПАРОЛЬ: доступ + паника (самоуничтожение)",
            size=8, color=C["warn"], bg=C["bg"]).pack(pady=(0,10))
        tk.Frame(c, bg=C["brd"], height=1).pack(fill=tk.X, pady=(0,12))

        # USB
        usb = get_usb_serial()
        usb_color = C["fg"] if usb != "NO_USB" else C["danger"]
        usb_text  = f"[ USB: {usb} ✓ ]" if usb != "NO_USB" else "[ USB: НЕ НАЙДЕН — данные не привяжутся к носителю ]"
        mkl(c, usb_text, size=9, color=usb_color, bg=C["bg"]).pack(pady=(0,10))

        # Роль
        rrow = tk.Frame(c, bg=C["bg"]); rrow.pack(fill=tk.X, pady=3)
        mkl(rrow, "РОЛЬ         :", bg=C["bg"]).pack(side=tk.LEFT)
        self.role_var = tk.StringVar(value="DIRECTOR")
        for r in ["DIRECTOR", "PARTNER"]:
            tk.Radiobutton(rrow, text=r, variable=self.role_var, value=r,
                bg=C["bg"], fg=C["fg"], selectcolor=C["bg_p"],
                activebackground=C["bg"], activeforeground=C["fg_b"],
                font=MONO).pack(side=tk.LEFT, padx=8)

        self.pw_var   = tk.StringVar()
        self.pw2_var  = tk.StringVar()
        self.pan_var  = tk.StringVar()
        self.pan2_var = tk.StringVar()

        for var, prompt, show in [
            (self.pw_var,   "ПАРОЛЬ ДОСТУПА :", "●"),
            (self.pw2_var,  "ПОВТОР         :", "●"),
            (self.pan_var,  "ПАРОЛЬ ПАНИКИ  :", "●"),
            (self.pan2_var, "ПОВТОР ПАНИКИ  :", "●"),
        ]:
            row = tk.Frame(c, bg=C["bg"]); row.pack(fill=tk.X, pady=2)
            mkl(row, prompt, bg=C["bg"]).pack(side=tk.LEFT)
            PEntry(row, textvariable=var, show=show, width=24).pack(side=tk.LEFT, padx=6)

        tk.Frame(c, bg=C["brd"], height=1).pack(fill=tk.X, pady=12)
        self.status = tk.Label(c, text="", font=MONO_SM, fg=C["warn"], bg=C["bg"])
        self.status.pack(pady=(0,8))
        PBtn(c, "[ СОЗДАТЬ И ПОЛУЧИТЬ QR ]", v="s", command=self._create, width=32).pack()

    def _create(self):
        pw = self.pw_var.get(); pw2 = self.pw2_var.get()
        pan = self.pan_var.get(); pan2 = self.pan2_var.get()
        role = self.role_var.get()

        if len(pw) < 12:
            self.status.config(text="Пароль доступа: минимум 12 символов", fg=C["danger"]); return
        if pw != pw2:
            self.status.config(text="Пароли доступа не совпадают", fg=C["danger"]); return
        if len(pan) < 8:
            self.status.config(text="Пароль паники: минимум 8 символов", fg=C["danger"]); return
        if pan != pan2:
            self.status.config(text="Пароли паники не совпадают", fg=C["danger"]); return
        if pw == pan:
            self.status.config(text="Пароли должны быть разными!", fg=C["danger"]); return

        self.status.config(text="Генерация ключей...", fg=C["warn"]); self.update()

        def _work():
            usb = get_usb_serial()
            uri = self.auth.setup(pw, pan, role, usb)
            self.auth.save_panic_hash(pan, pw)
            def _done():
                self.destroy()
                show_qr_window(self.root, uri)
                self.on_done()
            self.root.after(0, _done)
        threading.Thread(target=_work, daemon=True).start()


# ════════════════════════════════════════════════════════════════════
#  ЭКРАН ВХОДА
# ════════════════════════════════════════════════════════════════════

class LoginScreen(tk.Frame):
    def __init__(self, root, auth: AuthManager, on_ok):
        super().__init__(root, bg=C["bg"])
        self.root = root; self.auth = auth; self.on_ok = on_ok
        self._blink = True
        self._build(); self._tick_cursor(); self._tick_totp(); self._tick_usb()

    def _build(self):
        self.pack(fill=tk.BOTH, expand=True)
        c = tk.Frame(self, bg=C["bg"])
        c.place(relx=.5, rely=.5, anchor="center")

        for line in LOGO:
            tk.Label(c, text=line, font=("Courier New",14,"bold"),
                     fg=C["fg"], bg=C["bg"]).pack()

        mkl(c, "DIRECTOR AND RESTRICTED PARTNER  v8",
            size=9, bg=C["bg"]).pack(pady=(2,0))
        mkl(c, "5FA | Belt-128 | BashHash | STB 34.101.31",
            size=8, bg=C["bg"]).pack(pady=(0,12))
        tk.Frame(c, bg=C["brd"], height=1).pack(fill=tk.X, pady=(0,12))

        self.usb_lbl = tk.Label(c, text="[ USB... ]",
                                font=MONO_SM, fg=C["warn"], bg=C["bg"])
        self.usb_lbl.pack(pady=(0,8))

        self.pw_var   = tk.StringVar()
        self.totp_var = tk.StringVar()

        for var, prompt, show, is_totp in [
            (self.pw_var,   "ПАРОЛЬ   :", "●", False),
            (self.totp_var, "TOTP-КОД :", "",  True),
        ]:
            row = tk.Frame(c, bg=C["bg"]); row.pack(fill=tk.X, pady=3)
            mkl(row, prompt, bg=C["bg"]).pack(side=tk.LEFT)
            e = PEntry(row, textvariable=var, show=show, width=22)
            e.pack(side=tk.LEFT, padx=6)
            e.bind("<Return>", lambda ev: self._do_login())
            if is_totp:
                self.totp_timer = mkl(row, "  [30s]", size=9, bg=C["bg"])
                self.totp_timer.pack(side=tk.LEFT)

        tk.Frame(c, bg=C["brd"], height=1).pack(fill=tk.X, pady=12)
        self.status = tk.Label(c, text="", font=MONO_SM, fg=C["warn"], bg=C["bg"])
        self.status.pack(pady=(0,8))
        self.login_btn = PBtn(c, "[ ВОЙТИ ]", v="s", command=self._do_login, width=28)
        self.login_btn.pack(pady=4)
        self.cursor_lbl = tk.Label(c, text="█", font=MONO, fg=C["fg"], bg=C["bg"])
        self.cursor_lbl.pack(pady=(12,0))
        mkl(c, "Пароль паники = немедленное самоуничтожение + запуск",
            size=7, color=C["danger"], bg=C["bg"]).pack(pady=(8,0))

    def _do_login(self):
        pw   = self.pw_var.get()
        totp = self.totp_var.get().strip()
        if not pw: self._st("Введите пароль", "warn"); return

        self._st("Проверка...", "warn")
        self.login_btn.config(state=tk.DISABLED)

        def _work():
            usb = get_usb_serial()
            ok, is_panic, reason = self.auth.authenticate(pw, totp, usb)
            if ok:
                key = self.auth.derive_session_key(pw)
                def _done():
                    if reason:
                        messagebox.showwarning("Предупреждения", reason)
                    self.on_ok(key, self.auth.role, is_panic)
                self.root.after(0, _done)
            else:
                self.root.after(0, lambda: [
                    self._st(f"✗ {reason}", "err"),
                    self.login_btn.config(state=tk.NORMAL)])
        threading.Thread(target=_work, daemon=True).start()

    def _st(self, text, k="warn"):
        self.status.config(text=text,
            fg={"warn": C["warn"], "err": C["danger"], "ok": C["fg"]}.get(k, C["warn"]))

    def _tick_cursor(self):
        if not self.winfo_exists(): return
        self._blink = not self._blink
        self.cursor_lbl.config(fg=C["fg"] if self._blink else C["bg"])
        self.after(550, self._tick_cursor)

    def _tick_totp(self):
        if not self.winfo_exists(): return
        rem = 30 - (int(time.time()) % 30)
        self.totp_timer.config(text=f"  [{rem:02d}s]",
            fg=C["danger"] if rem <= 5 else C["fg_d"])
        self.after(1000, self._tick_totp)

    def _tick_usb(self):
        if not self.winfo_exists(): return
        s = get_usb_serial()
        self.usb_lbl.config(
            text=f"[ USB: {s} ✓ ]" if s != "NO_USB" else "[ USB: НЕ НАЙДЕН ]",
            fg=C["fg"] if s != "NO_USB" else C["danger"])
        self.after(3000, self._tick_usb)


# ════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ ОКНО DARP v8
# ════════════════════════════════════════════════════════════════════

class DARPApp:
    def __init__(self, root, session_key: bytes, role: str, auth_mgr: AuthManager):
        self.root        = root
        self.session_key = session_key
        self.role        = role
        self.auth_mgr    = auth_mgr
        self.data_dir    = ROOT / "data"
        self.data_dir.mkdir(exist_ok=True)

        root.geometry("1150x740")
        root.configure(bg=C["bg"])
        root.minsize(900, 600)
        root.title(f"DARP v8  |  {role}  |  {auth_mgr.callsign}")
        root.update()

        # Модули
        self.blockchain = EventBlockchain(self.data_dir, session_key, role)
        self.stego_mgr  = StegoManager(self.data_dir, session_key)
        self.voice_rec  = VoiceRecorder(self.data_dir, session_key)
        self.security   = SecurityModule(ROOT)
        self.geo        = GeoModule(self.data_dir)
        self.sandbox    = SandboxManager(session_key)
        self.scanner    = HostScanner()
        self.network    = DARPNetwork(self.data_dir, session_key) if HAS_NETWORK else None

        self._peer_connected = False
        self._rec_active     = False
        self._rec_start      = 0.0
        self._locked         = False
        self._lock_frame     = None
        self._tor_process    = None
        self._onion_addr     = None
        self._scan_report    = {}

        try:
            usb = auth_mgr.credentials.get("usb_serial", "NO_USB")
        except Exception:
            usb = "NO_USB"
        self._usb_serial = usb

        self._build()
        self._tick_clock()
        self.blockchain.log_auth_ok(role)
        self.blockchain.log_system(f"DARP v8 | {role} | {auth_mgr.callsign} | Belt-128 | 5FA")

        # USB watchdog
        if usb not in ("NO_USB", "", None):
            self._start_usb_watchdog()

        # Автоаудит хоста в фоне
        self._clog("ХОСТ", "Автоаудит системы...", "host")
        self.scanner.run_full_scan(callback=self._on_scan_done)

        # Настройка сетевых колбэков
        if self.network:
            self.network.on_message    = self._on_net_msg
            self.network.on_connect    = self._on_net_connect
            self.network.on_disconnect = self._on_net_disconnect
            self.network.on_file       = self._on_net_file
            self.network.start_server()

    # ── ПОСТРОЕНИЕ UI ────────────────────────────────────────────────

    def _build(self):
        # Header
        h = tk.Frame(self.root, bg=C["bg_h"], height=52)
        h.pack(fill=tk.X); h.pack_propagate(False)

        tk.Label(h, text="  DARP v8",
                 font=("Courier New",15,"bold"),
                 fg=C["fg"], bg=C["bg_h"]).pack(side=tk.LEFT, pady=8)
        tk.Label(h, text=f" [{self.role}]", font=MONO,
                 fg=C["warn"] if self.role == "DIRECTOR" else C["fg_d"],
                 bg=C["bg_h"]).pack(side=tk.LEFT)

        # Позывной — всегда виден в хедере
        cs = self.auth_mgr.callsign
        tk.Label(h, text=f"  ◈ {cs} ◈",
                 font=("Courier New",12,"bold"),
                 fg=C["cs"], bg=C["bg_h"]).pack(side=tk.LEFT, padx=16)

        tk.Label(h, text="Belt-128 | BashHash | 5FA | STB 34.101.31-2020",
                 font=MONO_SM, fg=C["fg_d"], bg=C["bg_h"]).pack(side=tk.LEFT, padx=4)

        self.conn_lbl = tk.Label(h, text="OFFLINE",
                                 font=MONO_SM, fg=C["danger"], bg=C["bg_h"])
        self.conn_lbl.pack(side=tk.RIGHT, padx=12)
        self.time_lbl = tk.Label(h, text="", font=MONO_SM,
                                 fg=C["fg_d"], bg=C["bg_h"])
        self.time_lbl.pack(side=tk.RIGHT, padx=12)
        tk.Frame(self.root, bg=C["brd_b"], height=1).pack(fill=tk.X)

        # Notebook
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("D.TNotebook", background=C["bg"], borderwidth=0)
        style.configure("D.TNotebook.Tab", background=C["bg_p"],
            foreground=C["fg_d"], font=MONO, padding=[12,5], borderwidth=0)
        style.map("D.TNotebook.Tab",
            background=[("selected", C["bg_h"])],
            foreground=[("selected", C["fg"])])

        self.nb = ttk.Notebook(self.root, style="D.TNotebook")
        self.nb.pack(fill=tk.BOTH, expand=True)

        self._tab_chat()
        self._tab_voice()
        self._tab_stego()
        self._tab_sandbox()
        self._tab_chain()
        self._tab_security()
        self._tab_host()
        self._tab_sos()

        # Statusbar
        tk.Frame(self.root, bg=C["brd_b"], height=1).pack(fill=tk.X)
        sb = tk.Frame(self.root, bg=C["bg_h"], height=22)
        sb.pack(fill=tk.X, side=tk.BOTTOM); sb.pack_propagate(False)
        self.sb_l = tk.Label(sb, text=f"  DARP v8 | {self.auth_mgr.callsign} | Belt-128 | BashHash-256",
                             font=MONO_SM, fg=C["fg_d"], bg=C["bg_h"])
        self.sb_l.pack(side=tk.LEFT)
        self.sb_r = tk.Label(sb, text="", font=MONO_SM, fg=C["fg_d"], bg=C["bg_h"])
        self.sb_r.pack(side=tk.RIGHT, padx=8)

    # ── ЧАТ ──────────────────────────────────────────────────────────

    def _tab_chat(self):
        tab = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab, text="  ЧАТ  ")

        cf = tk.Frame(tab, bg=C["bg_p"]); cf.pack(fill=tk.X, padx=8, pady=4)
        mkl(cf, "IP/ONION:", bg=C["bg_p"]).pack(side=tk.LEFT)
        self.addr_var = tk.StringVar()
        ae = PEntry(cf, textvariable=self.addr_var, width=30, font=MONO_SM)
        ae.pack(side=tk.LEFT, padx=4)
        ae.bind("<Return>", lambda e: self._connect())
        PBtn(cf, "ПОДКЛЮЧИТЬ", v="a", command=self._connect).pack(side=tk.LEFT, padx=2)
        PBtn(cf, "TOR", command=self._tor_dialog).pack(side=tk.LEFT, padx=2)
        PBtn(cf, "СЛУШАТЬ", command=self._start_listen).pack(side=tk.LEFT, padx=2)
        self.peer_lbl = mkl(cf, "OFFLINE", size=9, bg=C["bg_p"], color=C["danger"])
        self.peer_lbl.pack(side=tk.RIGHT, padx=8)

        of = tk.Frame(tab, bg=C["bg_h"]); of.pack(fill=tk.X, padx=8, pady=(0,2))
        mkl(of, "МОЙ ONION:", size=9, bg=C["bg_h"]).pack(side=tk.LEFT)
        self.my_onion_var = tk.StringVar(value="--- нажми СТАРТ TOR ---")
        tk.Entry(of, textvariable=self.my_onion_var,
                 font=("Courier New",9), fg=C["fg_d"], bg=C["bg_h"],
                 relief="flat", state="readonly",
                 readonlybackground=C["bg_h"], width=56).pack(side=tk.LEFT, padx=4)
        PBtn(of, "КОПИРОВАТЬ", command=self._copy_onion, width=10).pack(side=tk.LEFT, padx=2)
        PBtn(of, "СТАРТ TOR", v="a", command=self._start_tor_hs).pack(side=tk.LEFT, padx=2)

        tk.Frame(tab, bg=C["brd"], height=1).pack(fill=tk.X)

        mf = tk.Frame(tab, bg=C["bg"]); mf.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        sb_s = tk.Scrollbar(mf, bg=C["bg"], troughcolor=C["bg"], width=8)
        sb_s.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat = PText(mf, yscrollcommand=sb_s.set, state=tk.DISABLED)
        self.chat.pack(fill=tk.BOTH, expand=True)
        sb_s.config(command=self.chat.yview)

        tk.Frame(tab, bg=C["brd_b"], height=1).pack(fill=tk.X)
        inp = tk.Frame(tab, bg=C["bg_p"], pady=6); inp.pack(fill=tk.X)
        inner = tk.Frame(inp, bg=C["bg_p"]); inner.pack(fill=tk.X, padx=8)
        mkl(inner, "MSG :", bg=C["bg_p"]).pack(side=tk.LEFT)
        self.msg_var = tk.StringVar()
        me = PEntry(inner, textvariable=self.msg_var)
        me.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        me.bind("<Return>", lambda e: self._send_msg())
        PBtn(inner, "ОТПРАВИТЬ", v="s", command=self._send_msg, width=12).pack(side=tk.LEFT)

        q = tk.Frame(inp, bg=C["bg_p"]); q.pack(fill=tk.X, padx=8, pady=(4,0))
        PBtn(q, "ГОЛОС",        command=lambda: self.nb.select(1)).pack(side=tk.LEFT, padx=2)
        PBtn(q, "ФАЙЛЫ",        command=self._file_manager).pack(side=tk.LEFT, padx=2)
        PBtn(q, "СТЕГО",        command=lambda: self.nb.select(2)).pack(side=tk.LEFT, padx=2)
        PBtn(q, "ОТПРАВИТЬ ФАЙЛ", command=self._send_file).pack(side=tk.LEFT, padx=2)

        self._clog("СИСТЕМА", f"DARP v8 | {self.role} | {self.auth_mgr.callsign} | Belt-128 | 5FA", "ok")
        if not HAS_NETWORK:
            self._clog("ИНФО", "network.py недоступен — P2P отключён", "warn")

    def _clog(self, sender, text, tag="sys"):
        self.chat.config(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self.chat.insert(tk.END, f"[{ts}] ", "ts")
        self.chat.insert(tk.END, f"{sender}: ", tag)
        self.chat.insert(tk.END, text + "\n", tag)
        self.chat.config(state=tk.DISABLED)
        self.chat.see(tk.END)

    def _send_msg(self):
        t = self.msg_var.get().strip()
        if not t: return
        self.msg_var.set("")
        self._clog("ВЫ", t, "out")
        self.blockchain.log_message("out", len(t.encode()))
        if self.network and self._peer_connected:
            try: self.network.send_message(t)
            except Exception as e: self._clog("ERR", str(e), "warn")

    def _connect(self):
        addr = self.addr_var.get().strip()
        if not addr: self._clog("ОШИБКА", "Введите IP или .onion адрес", "warn"); return
        if not self.network: self._clog("ОШИБКА", "network.py недоступен", "err"); return
        self._clog("СИСТЕМА", "Подключение к " + addr + "...", "warn")
        def _do():
            try:
                self.network.connect(addr); self._peer_connected = True
                self.root.after(0, lambda: [
                    self._clog("СИСТЕМА", "OK: " + addr, "ok"),
                    self.conn_lbl.config(text="ONLINE", fg=C["fg"]),
                    self.peer_lbl.config(text="OK: " + addr[:20]),
                    self.blockchain.log_connect(addr)])
            except Exception as e:
                self.root.after(0, lambda: self._clog("ОШИБКА", str(e), "err"))
        threading.Thread(target=_do, daemon=True).start()

    def _start_listen(self):
        if not self.network: self._clog("ОШИБКА", "network.py недоступен", "err"); return
        self._clog("СИСТЕМА", f"Ожидание подключений на порту {CHAT_PORT}...", "warn")

    def _start_tor_hs(self):
        self._clog("TOR", "Запуск Hidden Service...", "warn")
        self.my_onion_var.set("Запуск...")
        def _do():
            tor_exe = self._find_tor_exe()
            if not tor_exe:
                self.root.after(0, lambda: [
                    self.my_onion_var.set("tor не найден"),
                    self._clog("TOR", "Tor не найден! Проверь пути:", "err"),
                    self._clog("TOR", "1. torproject.org → установи Tor Browser", "warn"),
                    self._clog("TOR", "2. Или укажи путь в data/tor_path.txt", "warn")])
                return
            hs_dir = self.data_dir / "tor_hs"; hs_dir.mkdir(parents=True, exist_ok=True)
            torrc  = self.data_dir / "torrc_darp"
            torrc.write_text("\n".join([
                "HiddenServiceDir " + str(hs_dir),
                "HiddenServicePort 8888 127.0.0.1:8888",
                "SocksPort 9050", "Log notice stderr", ""]))
            try:
                self._tor_process = subprocess.Popen(
                    [tor_exe, "-f", str(torrc)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.root.after(0, lambda: self._clog("TOR", "Tor запущен, жди ~30с...", "warn"))
                hostname_file = hs_dir / "hostname"
                for _ in range(90):
                    time.sleep(1)
                    if hostname_file.exists():
                        onion = hostname_file.read_text().strip()
                        self._onion_addr = onion
                        self.root.after(0, lambda o=onion: [
                            self.my_onion_var.set(o),
                            self._clog("TOR", "Onion: " + o, "ok"),
                            self._clog("TOR", "Передай партнёру!", "warn"),
                            self.blockchain.log_system("TOR_STARTED: " + o)])
                        return
                self.root.after(0, lambda: self._clog("TOR", "Таймаут — Tor не запустился", "err"))
            except Exception as e:
                self.root.after(0, lambda: self._clog("TOR", str(e), "err"))
        threading.Thread(target=_do, daemon=True).start()

    def _tor_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("DARP — Tor соединение"); win.configure(bg=C["bg"])
        win.geometry("520x300"); win.resizable(False, False); win.grab_set(); win.focus_force()
        mkl(win, "ПОДКЛЮЧЕНИЕ ЧЕРЕЗ TOR", size=13, bold=True, color=C["fg"], bg=C["bg"]).pack(pady=(14,4))
        mkl(win, "Обменяйтесь .onion адресами заранее", size=9, bg=C["bg"]).pack(pady=(0,8))
        tk.Frame(win, bg=C["brd"], height=1).pack(fill=tk.X, padx=20, pady=(0,8))
        my_f = tk.Frame(win, bg=C["bg_p"],
                        highlightbackground=C["brd"], highlightthickness=1)
        my_f.pack(fill=tk.X, padx=20, pady=(0,8))
        mkl(my_f, "МОЙ АДРЕС:", size=9, bg=C["bg_p"]).pack(side=tk.LEFT, padx=8, pady=6)
        my_addr = self._onion_addr or "--- нажми СТАРТ TOR ---"
        my_color = C["fg_b"] if self._onion_addr else C["warn"]
        tk.Label(my_f, text=my_addr, font=("Courier New",9,"bold"),
                 fg=my_color, bg=C["bg_p"]).pack(side=tk.LEFT, padx=4)
        mkl(win, "АДРЕС ПАРТНЁРА (.onion):", size=9, bg=C["bg"]).pack(anchor=tk.W, padx=20, pady=(0,2))
        peer_var = tk.StringVar(value=self.addr_var.get())
        pe = PEntry(win, textvariable=peer_var, width=56); pe.pack(padx=20, pady=(0,6)); pe.focus_set()
        status = tk.Label(win, text="", font=MONO_SM, fg=C["warn"], bg=C["bg"]); status.pack()
        def do_connect():
            addr = peer_var.get().strip()
            if not addr: status.config(text="Введите .onion адрес партнёра"); return
            if addr.endswith(".onion") and ":" not in addr: addr += ":8888"
            self.addr_var.set(addr); win.destroy(); self._connect()
        bf = tk.Frame(win, bg=C["bg"]); bf.pack(pady=8)
        PBtn(bf, "ПОДКЛЮЧИТЬСЯ", v="s", command=do_connect, width=18).pack(side=tk.LEFT, padx=6)
        PBtn(bf, "СТАРТ TOR", v="a", command=lambda: [win.destroy(), self._start_tor_hs()], width=12).pack(side=tk.LEFT, padx=6)
        PBtn(bf, "ОТМЕНА", command=win.destroy, width=10).pack(side=tk.LEFT, padx=6)
        pe.bind("<Return>", lambda e: do_connect())

    def _copy_onion(self):
        if self._onion_addr:
            self.root.clipboard_clear(); self.root.clipboard_append(self._onion_addr)
            self._clog("TOR", "Скопировано: " + self._onion_addr, "sys")
        else: self._clog("TOR", "Сначала нажми СТАРТ TOR", "warn")

    def _file_manager(self):
        win = tk.Toplevel(self.root)
        win.title("DARP — Файловый менеджер"); win.configure(bg=C["bg"])
        win.geometry("720x540"); win.grab_set()
        mkl(win, "ФАЙЛОВЫЙ МЕНЕДЖЕР", size=13, bold=True, color=C["fg"], bg=C["bg"]).pack(pady=(12,4))
        tk.Frame(win, bg=C["brd"], height=1).pack(fill=tk.X, padx=10, pady=6)
        ff = tk.Frame(win, bg=C["bg"]); ff.pack(fill=tk.X, padx=10, pady=(0,4))
        self._fm_dir = tk.StringVar(value=str(self.data_dir))
        PEntry(ff, textvariable=self._fm_dir, width=50).pack(side=tk.LEFT, padx=(0,4))
        lf = tk.Frame(win, bg=C["bg"]); lf.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)
        sbf = tk.Scrollbar(lf, bg=C["bg"], troughcolor=C["bg"], width=8); sbf.pack(side=tk.RIGHT, fill=tk.Y)
        fl = tk.Listbox(lf, bg=C["bg_p"], fg=C["fg"], selectbackground=C["sel"],
                        selectforeground=C["fg_b"], font=MONO_SM, bd=0, relief="flat",
                        highlightthickness=1, highlightbackground=C["brd"],
                        yscrollcommand=sbf.set)
        fl.pack(fill=tk.BOTH, expand=True); sbf.config(command=fl.yview)
        sz_lbl = mkl(win, "", size=9, bg=C["bg"]); sz_lbl.pack(pady=2)

        def refresh():
            fl.delete(0, tk.END)
            try:
                p = Path(self._fm_dir.get()); total = cnt = 0
                for f in sorted(p.rglob("*")):
                    if f.is_file():
                        sz = f.stat().st_size; total += sz; cnt += 1
                        rel = str(f.relative_to(p))
                        szs = (str(sz//1024) + "KB" if sz >= 1024 else str(sz) + "B")
                        fl.insert(tk.END, "  " + rel.ljust(48) + szs.rjust(8))
                sz_lbl.config(text="Файлов: " + str(cnt) + "  Итого: " + str(total//1024) + "KB")
            except Exception as e: fl.insert(tk.END, "Ошибка: " + str(e))

        def browse():
            d = filedialog.askdirectory(parent=win)
            if d: self._fm_dir.set(d); refresh()

        def fm_open():
            sel = fl.curselection()
            if not sel: return
            fname = fl.get(sel[0]).strip().split()[0]
            fpath = Path(self._fm_dir.get()) / fname
            if not fpath.is_file(): return
            if fpath.suffix.lower() in {'.txt','.py','.json','.md','.log','.html','.csv','.ini','.cfg','.enc'}:
                self._view_text_win(fpath)
            else:
                try:
                    if platform.system() == "Windows": os.startfile(str(fpath))
                    else: subprocess.Popen(["xdg-open", str(fpath)])
                except Exception: self._view_text_win(fpath)

        def fm_send():
            sel = fl.curselection()
            if not sel: return
            fname = fl.get(sel[0]).strip().split()[0]
            fpath = Path(self._fm_dir.get()) / fname
            if fpath.is_file(): self._do_send_file(fpath)

        def fm_delete():
            sel = fl.curselection()
            if not sel: return
            fname = fl.get(sel[0]).strip().split()[0]
            fpath = Path(self._fm_dir.get()) / fname
            if not fpath.is_file(): return
            if messagebox.askyesno("Удалить", "Удалить " + fname + "?\n(безопасное затирание)"):
                try: secure_wipe(fpath)
                except Exception: fpath.unlink(missing_ok=True)
                refresh(); self.blockchain.log_system("DELETE: " + fname)

        fl.bind("<Double-Button-1>", lambda e: fm_open())
        PBtn(ff, "ОБЗОР",    command=browse,  width=8).pack(side=tk.LEFT, padx=2)
        PBtn(ff, "ОБНОВИТЬ", command=refresh, width=10).pack(side=tk.LEFT, padx=2)
        af = tk.Frame(win, bg=C["bg"]); af.pack(pady=8)
        PBtn(af, "ОТКРЫТЬ",          command=fm_open,   width=14).pack(side=tk.LEFT, padx=4)
        PBtn(af, "ОТПРАВИТЬ", v="a", command=fm_send,   width=14).pack(side=tk.LEFT, padx=4)
        PBtn(af, "УДАЛИТЬ",   v="d", command=fm_delete, width=10).pack(side=tk.LEFT, padx=4)
        refresh()

    def _view_text_win(self, fpath):
        win = tk.Toplevel(self.root); win.title("DARP — " + fpath.name)
        win.configure(bg=C["bg"]); win.geometry("740x540")
        hf = tk.Frame(win, bg=C["bg_h"]); hf.pack(fill=tk.X)
        mkl(hf, "  " + fpath.name, size=11, bold=True, color=C["fg"], bg=C["bg_h"]).pack(side=tk.LEFT, pady=6)
        mkl(hf, "  " + str(fpath.stat().st_size) + " байт", size=9, bg=C["bg_h"]).pack(side=tk.LEFT)
        tk.Frame(win, bg=C["brd_b"], height=1).pack(fill=tk.X)
        xsb = tk.Scrollbar(win, orient=tk.HORIZONTAL); xsb.pack(side=tk.BOTTOM, fill=tk.X)
        txt = PText(win, wrap=tk.NONE); txt.configure(xscrollcommand=xsb.set)
        xsb.config(command=txt.xview); txt.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        try: txt.insert(tk.END, fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            data = fpath.read_bytes()
            for i in range(0, min(len(data), 16384), 16):
                chunk = data[i:i+16]
                hs  = " ".join("{:02X}".format(b) for b in chunk)
                asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                txt.insert(tk.END, "{:08X}  {:<48}  {}\n".format(i, hs, asc))
        txt.config(state=tk.DISABLED)

    def _send_file(self):
        p = filedialog.askopenfilename(title="Файл для отправки")
        if p: self._do_send_file(Path(p))

    def _do_send_file(self, fpath):
        if not self.network or not self._peer_connected:
            self._clog("ОШИБКА", "Нет соединения с партнёром", "err"); return
        self._clog("ФАЙЛ", "Отправка: " + fpath.name, "out")
        def _do():
            try:
                self.network.send_file(str(fpath))
                self.root.after(0, lambda: self._clog("ФАЙЛ", "OK: " + fpath.name, "ok"))
            except Exception as e:
                self.root.after(0, lambda: self._clog("ОШИБКА", str(e), "err"))
        threading.Thread(target=_do, daemon=True).start()

    # Сетевые колбэки
    def _on_net_msg(self, msg):
        self.root.after(0, lambda: [
            self._clog("ПАРТНЁР", msg.get("text",""), "in"),
            self.blockchain.log_message("in", len(msg.get("text","").encode()))])

    def _on_net_connect(self, addr):
        self._peer_connected = True
        self.root.after(0, lambda: [
            self._clog("СИСТЕМА", "Партнёр подключён: " + addr, "ok"),
            self.conn_lbl.config(text="ONLINE", fg=C["fg"]),
            self.peer_lbl.config(text="ON: " + addr[:18])])

    def _on_net_disconnect(self, reason):
        self._peer_connected = False
        self.root.after(0, lambda: [
            self._clog("СИСТЕМА", "Партнёр отключился: " + reason, "warn"),
            self.conn_lbl.config(text="OFFLINE", fg=C["danger"]),
            self.peer_lbl.config(text="OFFLINE", fg=C["danger"])])

    def _on_net_file(self, fname, data):
        save_path = self.data_dir / fname
        save_path.write_bytes(data)
        self.root.after(0, lambda: self._clog(
            "ФАЙЛ", f"Получен: {fname} ({len(data)//1024+1}KB)", "ok"))

    # ── ГОЛОС ─────────────────────────────────────────────────────────

    def _tab_voice(self):
        tab = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab, text="  ГОЛОС  ")

        from modules.voice import VoiceRecorder as VR
        backend = VR.audio_backend()
        has_audio = VR.is_available()

        mkl(tab, "ГОЛОСОВЫЕ СООБЩЕНИЯ — Belt-128/CBC",
            size=13, bold=True, color=C["fg"], bg=C["bg"]).pack(pady=(12,2))
        mkl(tab, f"PCM 16kHz | zlib | STB 34.101.31-2020 | Бэкенд: {backend}",
            size=9, bg=C["bg"]).pack()
        if not has_audio:
            mkl(tab, "⚠ sounddevice/pyaudio не установлен — будет тест-сигнал",
                size=9, color=C["warn"], bg=C["bg"]).pack()
        hsep(tab, C["brd"]); tk.Frame(tab, height=8, bg=C["bg"]).pack()

        viz = tk.Frame(tab, bg=C["bg_p"],
                       highlightbackground=C["brd"], highlightthickness=1)
        viz.pack(fill=tk.X, padx=20, pady=(0,8))
        self.voice_cv = tk.Canvas(viz, height=54, bg=C["bg_p"], highlightthickness=0)
        self.voice_cv.pack(fill=tk.X, padx=4, pady=4)
        self._voice_idle()

        ctrl = tk.Frame(tab, bg=C["bg"]); ctrl.pack(pady=6)
        self.rec_btn = PBtn(ctrl, "● ЗАПИСЬ", v="d",
                            command=self._toggle_rec, width=14)
        self.rec_btn.pack(side=tk.LEFT, padx=6)
        self.rec_st = tk.Label(ctrl, text="[ ГОТОВ ]",
                               font=MONO, fg=C["fg"], bg=C["bg"])
        self.rec_st.pack(side=tk.LEFT, padx=10)
        self.rec_tm = tk.Label(ctrl, text="00:00",
                               font=("Courier New",20,"bold"), fg=C["fg"], bg=C["bg"])
        self.rec_tm.pack(side=tk.LEFT)

        hsep(tab, C["brd"]); tk.Frame(tab, height=4, bg=C["bg"]).pack()
        mkl(tab, "ЗАПИСАННЫЕ:", size=9, bg=C["bg"]).pack(anchor=tk.W, padx=20)

        lf = tk.Frame(tab, bg=C["bg"]); lf.pack(fill=tk.BOTH, expand=True, padx=20, pady=(4,2))
        sbv = tk.Scrollbar(lf, bg=C["bg"], troughcolor=C["bg"], width=8)
        sbv.pack(side=tk.RIGHT, fill=tk.Y)
        self.voice_lb = tk.Listbox(lf, bg=C["bg_p"], fg=C["fg"],
            selectbackground=C["sel"], font=MONO_SM, bd=0, relief="flat",
            highlightthickness=1, highlightbackground=C["brd"],
            yscrollcommand=sbv.set)
        self.voice_lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sbv.config(command=self.voice_lb.yview)
        self.voice_lb.bind("<Double-Button-1>", self._play_voice)

        bf2 = tk.Frame(tab, bg=C["bg"]); bf2.pack(pady=6)
        PBtn(bf2, "▶ ИГРАТЬ",   command=self._play_voice, width=10).pack(side=tk.LEFT, padx=4)
        PBtn(bf2, "ОТПРАВИТЬ",  v="a", command=self._send_voice, width=10).pack(side=tk.LEFT, padx=4)
        PBtn(bf2, "🗑 УДАЛИТЬ", v="d", command=self._del_voice, width=10).pack(side=tk.LEFT, padx=4)

        self.voice_rec.on_level    = self._voice_lvl
        self.voice_rec.on_recorded = self._on_recorded
        self._refresh_voices()

    def _voice_idle(self):
        self.voice_cv.delete("all")
        w = max(self.voice_cv.winfo_reqwidth(), 600); h = 54
        self.voice_cv.create_line(0, h//2, w, h//2, fill=C["fg_d"])
        for x in range(0, w, 20):
            self.voice_cv.create_line(x, h//2-3, x, h//2+3, fill=C["brd_b"])

    def _voice_lvl(self, level):
        self.voice_cv.delete("all")
        w = max(self.voice_cv.winfo_reqwidth(), 600); h = 54
        bars = w // 8
        import random
        for i in range(bars):
            bh = int(level * h/2 * (0.5 + random.random() * 0.5))
            x = i * 8; mid = h // 2
            col = C["danger"] if level > 0.8 else C["fg"]
            self.voice_cv.create_rectangle(x, mid-bh, x+6, mid+bh, fill=col, outline="")

    def _toggle_rec(self):
        if not self._rec_active: self._start_rec()
        else: self._stop_rec()

    def _start_rec(self):
        self._rec_active = True; self._rec_start = time.time()
        self.rec_btn.config(text="■ СТОП")
        self.rec_st.config(text="[ ЗАПИСЬ ]", fg=C["danger"])
        if not self.voice_rec.start_recording():
            self.rec_st.config(text="[ ТЕСТ-СИГНАЛ ]", fg=C["warn"])
        self._tick_rec()

    def _stop_rec(self):
        self._rec_active = False
        self.rec_btn.config(text="● ЗАПИСЬ")
        self.rec_st.config(text="[ СОХРАНЕНИЕ... ]", fg=C["warn"])
        self.rec_tm.config(text="00:00"); self._voice_idle()
        def _fin():
            msg = self.voice_rec.stop_recording()
            if msg is None:
                msg = self.voice_rec.create_test_voice("test")
            if msg:
                self.root.after(0, lambda m=msg: [
                    self._on_recorded(m),
                    self.rec_st.config(text="[ ГОТОВ ]", fg=C["fg"])])
            else:
                self.root.after(0, lambda:
                    self.rec_st.config(text="[ ОШИБКА ]", fg=C["danger"]))
        threading.Thread(target=_fin, daemon=True).start()

    def _tick_rec(self):
        if not self._rec_active: return
        e = time.time() - self._rec_start
        self.rec_tm.config(text=f"{int(e)//60:02d}:{int(e)%60:02d}")
        if e >= 120: self._stop_rec()
        else: self.root.after(200, self._tick_rec)

    def _on_recorded(self, msg):
        self.blockchain.log_voice(msg["duration"], msg["size"])
        self._clog("ГОЛОС",
            f"{VoiceRecorder.format_duration(msg['duration'])}  "
            f"{msg['size']//1024+1}KB  Belt-128", "voice")
        self._refresh_voices()

    def _refresh_voices(self):
        self.voice_lb.delete(0, tk.END)
        for vm in self.voice_rec.get_voice_list():
            dt = datetime.fromtimestamp(vm["timestamp"]).strftime("%H:%M:%S")
            self.voice_lb.insert(
                tk.END, f"  [{dt}]  {VoiceRecorder.format_duration(vm['duration'])}  {vm['size']//1024+1}KB")

    def _play_voice(self, event=None):
        sel = self.voice_lb.curselection()
        if not sel: return
        vl = self.voice_rec.get_voice_list()
        if sel[0] < len(vl):
            ok = self.voice_rec.play_voice_message(vl[sel[0]]["file"])
            self.rec_st.config(
                text="[ ▶ ИГРАЕТ ]" if ok else "[ НЕТ АУДИО-УСТРОЙСТВА ]",
                fg=C["fg_b"] if ok else C["warn"])

    def _send_voice(self):
        sel = self.voice_lb.curselection()
        if not sel: self._clog("ОШИБКА", "Выберите сообщение", "warn"); return
        vl = self.voice_rec.get_voice_list()
        if sel[0] >= len(vl): return
        vm = vl[sel[0]]
        if not self.network or not self._peer_connected:
            self._clog("ОШИБКА", "Нет соединения", "err"); return
        self._do_send_file(self.voice_rec.data_dir / vm["file"])

    def _del_voice(self):
        sel = self.voice_lb.curselection()
        if not sel: return
        vl = self.voice_rec.get_voice_list()
        if sel[0] < len(vl):
            self.voice_rec.delete_voice(vl[sel[0]]["file"])
            self._refresh_voices()

    # ── СТЕГО ────────────────────────────────────────────────────────

    def _tab_stego(self):
        tab = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab, text="  СТЕГО  ")
        mkl(tab, "СТЕГАНОГРАФИЯ — Belt-128 + LSB",
            size=13, bold=True, color=C["fg"], bg=C["bg"]).pack(pady=(12,2))
        hsep(tab, C["brd"]); tk.Frame(tab, height=8, bg=C["bg"]).pack()
        mf = tk.Frame(tab, bg=C["bg"]); mf.pack(padx=20, fill=tk.X)
        mkl(mf, "МЕТОД:", bg=C["bg"]).pack(side=tk.LEFT)
        self.stego_m = tk.StringVar(value="PNG")
        for m in ["PNG", "WAV", "TXT"]:
            tk.Radiobutton(mf, text=m, variable=self.stego_m, value=m,
                bg=C["bg"], fg=C["fg"], selectcolor=C["bg_p"],
                activebackground=C["bg"], font=MONO).pack(side=tk.LEFT, padx=8)
        mkl(tab, "СООБЩЕНИЕ:", size=9, bg=C["bg"]).pack(anchor=tk.W, padx=20, pady=(8,2))
        self.stego_txt = PText(tab, height=4)
        self.stego_txt.pack(fill=tk.X, padx=20, pady=(0,8))
        bf = tk.Frame(tab, bg=C["bg"]); bf.pack(padx=20)
        PBtn(bf, "ВСТРОИТЬ", v="a", command=self._s_embed).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "ИЗВЛЕЧЬ",          command=self._s_extract).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "АНАЛИЗ",           command=self._s_analyze).pack(side=tk.LEFT, padx=4)
        hsep(tab, C["brd"]); tk.Frame(tab, height=4, bg=C["bg"]).pack()
        self.stego_log = PText(tab, height=7, state=tk.DISABLED)
        self.stego_log.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0,10))

    def _sl(self, text, tag="sys"):
        self.stego_log.config(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self.stego_log.insert(tk.END, f"[{ts}] {text}\n", tag)
        self.stego_log.config(state=tk.DISABLED)
        self.stego_log.see(tk.END)

    def _s_embed(self):
        msg = self.stego_txt.get("1.0", tk.END).strip()
        if not msg: self._sl("Введите сообщение", "warn"); return
        m = self.stego_m.get()
        if m == "TXT":
            r = self.stego_mgr.embed_in_text("Совещание перенесено. Готовность в 09:00.", msg)
            self._sl(f"OK TXT: {len(msg)} байт скрыто", "ok")
        else:
            ft = [("PNG","*.png")] if m == "PNG" else [("WAV","*.wav")]
            p = filedialog.askopenfilename(title=f"Носитель {m}", filetypes=ft)
            if not p: return
            fn = self.stego_mgr.embed_in_image if m == "PNG" else self.stego_mgr.embed_in_audio
            r = fn(Path(p), msg)
            self._sl(f"{'OK: ' + r.name if r else 'ERR'}", "ok" if r else "err")
        self.blockchain.log_stego(m, "embed")

    def _s_extract(self):
        m = self.stego_m.get()
        if m == "TXT":
            r = self.stego_mgr.extract_from_text(self.stego_txt.get("1.0", tk.END))
            self._sl(f"{'OK: ' + r[:80] if r else 'Нет данных'}", "ok" if r else "warn")
        else:
            p = filedialog.askopenfilename(title="Носитель", filetypes=[("PNG/WAV","*.png *.wav")])
            if not p: return
            r = self.stego_mgr.extract_from_image(Path(p)) if m == "PNG" else None
            self._sl(f"{'OK: ' + r[:80] if r else 'Нет данных / неверный ключ'}", "ok" if r else "warn")

    def _s_analyze(self):
        p = filedialog.askopenfilename(title="Файл", filetypes=[("Изображения","*.png *.jpg")])
        if not p: return
        r = self.stego_mgr.analyze_file(Path(p))
        s = r.get("suspicious", False)
        self._sl(f"{'ПОДОЗРИТЕЛЬНО' if s else 'ЧИСТО'}: LSB={r.get('lsb_ratio','?')} conf={r.get('confidence','?')}",
                 "warn" if s else "ok")

    # ── SANDBOX ──────────────────────────────────────────────────────

    def _tab_sandbox(self):
        tab = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab, text="  SANDBOX  ")
        mkl(tab, "ПЕСОЧНИЦА — Просмотр файлов из RAM",
            size=13, bold=True, color=C["fg"], bg=C["bg"]).pack(pady=(12,2))
        mkl(tab, "Файлы загружаются в RAM и шифруются. На диске следов нет.",
            size=9, color=C["warn"], bg=C["bg"]).pack()
        hsep(tab, C["brd"]); tk.Frame(tab, height=8, bg=C["bg"]).pack()

        bf = tk.Frame(tab, bg=C["bg"]); bf.pack(padx=20, fill=tk.X, pady=(0,8))
        PBtn(bf, "ЗАГРУЗИТЬ ФАЙЛ", v="a", command=self._sbox_load).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "ОТКРЫТЬ",                command=self._sbox_view).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "УДАЛИТЬ ИЗ RAM", v="d",  command=self._sbox_del).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "ОЧИСТИТЬ ВСЁ",   v="d",  command=self._sbox_clear).pack(side=tk.LEFT, padx=4)

        lf = tk.Frame(tab, bg=C["bg"]); lf.pack(fill=tk.BOTH, expand=True, padx=20, pady=(4,10))
        sbv = tk.Scrollbar(lf, bg=C["bg"], troughcolor=C["bg"], width=8)
        sbv.pack(side=tk.RIGHT, fill=tk.Y)
        self.sbox_lb = tk.Listbox(lf, bg=C["bg_p"], fg=C["fg"],
            selectbackground=C["sel"], font=MONO_SM, bd=0, relief="flat",
            highlightthickness=1, highlightbackground=C["brd"],
            yscrollcommand=sbv.set)
        self.sbox_lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sbv.config(command=self.sbox_lb.yview)
        self.sbox_lb.bind("<Double-Button-1>", self._sbox_view)

        self.sbox_lbl = mkl(tab, "[ RAM: 0 файлов ]", size=9, bg=C["bg"])
        self.sbox_lbl.pack(pady=4)
        self._sbox_ids = []

    def _sbox_load(self):
        p = filedialog.askopenfilename(title="Загрузить в Sandbox")
        if not p: return
        try:
            fid, fname = self.sandbox.load_file(p)
            self._sbox_ids.append(fid)
            self._sbox_refresh()
            self._clog("SANDBOX", f"Загружен: {fname}", "ok")
        except Exception as e:
            messagebox.showerror("Sandbox", str(e))

    def _sbox_view(self, event=None):
        sel = self.sbox_lb.curselection()
        if not sel: return
        idx = sel[0]
        if idx >= len(self._sbox_ids): return
        fid = self._sbox_ids[idx]
        ok = self.sandbox.view_file(fid, self.root)
        if not ok: messagebox.showwarning("Sandbox", "Файл не найден в RAM")

    def _sbox_del(self):
        sel = self.sbox_lb.curselection()
        if not sel: return
        idx = sel[0]
        if idx >= len(self._sbox_ids): return
        fid = self._sbox_ids[idx]
        self.sandbox.remove_file(fid)
        self._sbox_ids.pop(idx)
        self._sbox_refresh()

    def _sbox_clear(self):
        if messagebox.askyesno("Sandbox", "Очистить всё из RAM?"):
            self.sandbox.clear_all(); self._sbox_ids.clear(); self._sbox_refresh()

    def _sbox_refresh(self):
        self.sbox_lb.delete(0, tk.END)
        items = self.sandbox.list_files()
        self._sbox_ids = [it[0] for it in items]
        for fid, fname, sz in items:
            self.sbox_lb.insert(tk.END, f"  🔒  {fname:<40s}  {sz//1024+1}KB  [{fid}]")
        self.sbox_lbl.config(text=f"[ RAM: {len(items)} файлов — зашифровано в памяти ]")

    # ── BLOCKCHAIN ───────────────────────────────────────────────────

    def _tab_chain(self):
        tab = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab, text="  ЦЕПЬ  ")
        mkl(tab, "BLOCKCHAIN LOG — BashHash (STB 34.101.77-2020)",
            size=13, bold=True, color=C["fg"], bg=C["bg"]).pack(pady=(12,2))
        self.chain_st = tk.Label(tab, text="", font=MONO_SM, fg=C["fg_d"], bg=C["bg"])
        self.chain_st.pack()
        hsep(tab, C["brd"]); tk.Frame(tab, height=8, bg=C["bg"]).pack()
        bf = tk.Frame(tab, bg=C["bg"]); bf.pack(padx=20, fill=tk.X, pady=(0,8))
        PBtn(bf, "ОБНОВИТЬ",    command=self._chain_refresh).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "ВЕРИФИКАЦИЯ", v="a", command=self._chain_verify).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "HTML",        command=self._chain_html).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "JSON",        command=self._chain_json).pack(side=tk.LEFT, padx=4)
        self.chain_txt = PText(tab, state=tk.DISABLED)
        self.chain_txt.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0,10))
        self._chain_refresh()

    def _chain_refresh(self):
        st = self.blockchain.get_stats()
        self.chain_st.config(
            text=f"Блоков: {st['chain_length']}  Событий: {st['total_events']}  Сессия: {st['session_start']}")
        self.chain_txt.config(state=tk.NORMAL); self.chain_txt.delete("1.0", tk.END)
        for b in self.blockchain.get_recent(50):
            ts  = datetime.fromtimestamp(b["timestamp"]).strftime("%H:%M:%S")
            evt = b["event_type"]
            tag = ("err"   if "DESTRUCT" in evt or "FAIL" in evt else
                   "ok"    if "SUCCESS" in evt or "CONNECT" in evt else
                   "voice" if "VOICE"   in evt else
                   "stego" if "STEGO"   in evt else "sys")
            self.chain_txt.insert(tk.END, f"[#{b['index']:04d}] {ts} ", "ts")
            self.chain_txt.insert(tk.END, f"{evt:<22} ", tag)
            d = json.dumps(b["data"], ensure_ascii=False)[:40]
            self.chain_txt.insert(tk.END, f"{b['hash'][:12]}... {d}\n", "sys")
        self.chain_txt.config(state=tk.DISABLED); self.chain_txt.see(tk.END)

    def _chain_verify(self):
        r = self.blockchain.verify_chain()
        if r["valid"]: messagebox.showinfo("Блокчейн", f"OK: {r['total_blocks']} блоков\n{r['algorithm']}")
        else: messagebox.showerror("Блокчейн", "ОШИБКИ:\n" + "\n".join(r["errors"][:5]))

    def _chain_html(self):
        p = filedialog.asksaveasfilename(defaultextension=".html", initialfile="darp_chain.html",
                                         filetypes=[("HTML","*.html")])
        if p: self.blockchain.export_html(Path(p)); messagebox.showinfo("OK", p)

    def _chain_json(self):
        p = filedialog.asksaveasfilename(defaultextension=".json", initialfile="darp_chain.json",
                                         filetypes=[("JSON","*.json")])
        if p: self.blockchain.export_json(Path(p)); messagebox.showinfo("OK", p)

    # ── БЕЗОПАСНОСТЬ ─────────────────────────────────────────────────

    def _tab_security(self):
        tab = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab, text="  ЗАЩИТА  ")
        mkl(tab, "МОДУЛЬ БЕЗОПАСНОСТИ",
            size=13, bold=True, color=C["fg"], bg=C["bg"]).pack(pady=(12,2))
        hsep(tab, C["brd"]); tk.Frame(tab, height=8, bg=C["bg"]).pack()
        bf = tk.Frame(tab, bg=C["bg"]); bf.pack(padx=20, fill=tk.X, pady=(0,8))
        PBtn(bf, "АУДИТ СИСТЕМЫ",    command=self._sec_full_audit).pack(side=tk.LEFT, padx=3)
        PBtn(bf, "ПОРТЫ",            command=self._sec_ports).pack(side=tk.LEFT, padx=3)
        PBtn(bf, "ПРОЦЕССЫ",         command=self._sec_processes).pack(side=tk.LEFT, padx=3)
        PBtn(bf, "УЯЗВИМОСТИ",  v="w", command=self._sec_vuln).pack(side=tk.LEFT, padx=3)
        PBtn(bf, "GEO + VPN",        command=self._sec_geo).pack(side=tk.LEFT, padx=3)
        PBtn(bf, "DNS-LEAK",         command=self._sec_dns).pack(side=tk.LEFT, padx=3)
        PBtn(bf, "АЛГОРИТМЫ",        command=self._sec_algo).pack(side=tk.LEFT, padx=3)
        PBtn(bf, "ОЧИСТИТЬ",   v="n", command=lambda:[
            self.sec_txt.config(state=tk.NORMAL),
            self.sec_txt.delete("1.0", tk.END),
            self.sec_txt.config(state=tk.DISABLED)]).pack(side=tk.RIGHT, padx=3)
        self.sec_txt = PText(tab, state=tk.DISABLED)
        self.sec_txt.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0,10))
        self._sec_algo()

    def _secl(self, text, tag="sys"):
        self.sec_txt.config(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self.sec_txt.insert(tk.END, f"[{ts}] {text}\n", tag)
        self.sec_txt.config(state=tk.DISABLED)
        self.sec_txt.see(tk.END)

    def _sec_full_audit(self):
        self._secl("═══ ПОЛНЫЙ АУДИТ СИСТЕМЫ ═══", "chain")
        def _do():
            d = self.security.full_system_audit()
            def _show():
                for k, v in d.items():
                    if isinstance(v, list):
                        self._secl(k + ":", "ok")
                        for item in v[:10]: self._secl("  " + str(item), "sys")
                    else: self._secl(k.ljust(20) + str(v), "sys")
                self._secl("═══ КОНЕЦ АУДИТА ═══", "chain")
            self.root.after(0, _show)
        threading.Thread(target=_do, daemon=True).start()

    def _sec_ports(self):
        self._secl("Сканирование ключевых портов...", "sys")
        def _do():
            result = self.security.scan_open_ports()
            def _show():
                if result:
                    for port, svc in result:
                        self._secl(f"⚠ ОТКРЫТ :{port} ({svc})", "warn")
                else: self._secl("✅ Подозрительных открытых портов нет", "ok")
            self.root.after(0, _show)
        threading.Thread(target=_do, daemon=True).start()

    def _sec_processes(self):
        self._secl("Анализ процессов...", "sys")
        def _do():
            apps = self.security.analyze_host_apps()
            found = self.security.scan_for_spyware()
            def _show():
                self._secl(f"Запущено процессов: {len(apps)}", "ok")
                for f in found: self._secl(f, "warn" if "✅" not in f else "ok")
            self.root.after(0, _show)
        threading.Thread(target=_do, daemon=True).start()

    def _sec_vuln(self):
        self._secl("═══ АНАЛИЗ УЯЗВИМОСТЕЙ ═══", "warn")
        def _do():
            issues = self.security.scan_vulnerabilities()
            def _show():
                for i in issues: self._secl(i, "ok" if "✅" in i else "warn")
                self._secl("═══ КОНЕЦ ═══", "chain")
            self.root.after(0, _show)
        threading.Thread(target=_do, daemon=True).start()

    def _sec_geo(self):
        self._secl("Геолокация + VPN-детекция...", "sys")
        def _do():
            geo = self.geo.get_location()
            vpn = self.geo.detect_vpn()
            def _show():
                if "error" in geo:
                    self._secl("Ошибка: " + geo["error"], "warn"); return
                self._secl(f"IP: {geo.get('query','?')} | {geo.get('city','?')} {geo.get('country','?')}", "ok")
                self._secl(f"ISP: {geo.get('isp','?')}", "sys")
                self._secl(f"Timezone: {geo.get('timezone','?')}", "sys")
                self._secl("VPN/Proxy ОБНАРУЖЕН!" if vpn["vpn_detected"] else "VPN не обнаружен",
                           "warn" if vpn["vpn_detected"] else "ok")
            self.root.after(0, _show)
        threading.Thread(target=_do, daemon=True).start()

    def _sec_dns(self):
        self._secl("DNS-leak тест...", "sys")
        def _do():
            results = self.geo.dns_leak_test()
            def _show():
                for r in results: self._secl("  " + r, "sys")
            self.root.after(0, _show)
        threading.Thread(target=_do, daemon=True).start()

    def _sec_algo(self):
        self._secl(f"─── DARP v8 | {self.auth_mgr.callsign} ───", "cs")
        for k, v in crypto_info().items():
            self._secl(f"  {k:<18} {v}", "sys")
        self._secl(f"  Позывной:         {self.auth_mgr.callsign}", "cs")
        self._secl(f"  Роль:             {self.role}", "sys")
        self._secl(f"  Аудио-бэкенд:     {VoiceRecorder.audio_backend()}", "sys")
        self._secl(f"  P2P сеть:         {'OK' if HAS_NETWORK else 'недоступна'}", "ok" if HAS_NETWORK else "warn")

    # ── АУДИТ ХОСТА ──────────────────────────────────────────────────

    def _tab_host(self):
        tab = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab, text="  ХОСТ  ")
        mkl(tab, "АУДИТ ХОСТ-СИСТЕМЫ",
            size=13, bold=True, color=C["fg"], bg=C["bg"]).pack(pady=(12,2))
        mkl(tab, "Автоматический анализ ПК при подключении флешки",
            size=9, color=C["warn"], bg=C["bg"]).pack()
        hsep(tab, C["brd"]); tk.Frame(tab, height=8, bg=C["bg"]).pack()
        bf = tk.Frame(tab, bg=C["bg"]); bf.pack(padx=20, fill=tk.X, pady=(0,8))
        PBtn(bf, "ПОЛНЫЙ СКАН",      command=self._host_scan).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "ПРОЦЕССЫ",         command=self._host_procs).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "ПОРТЫ",            command=self._host_ports).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "СОХРАНИТЬ ОТЧЁТ",  command=self._host_save).pack(side=tk.LEFT, padx=4)
        PBtn(bf, "ОЧИСТИТЬ",   v="n", command=lambda:[
            self.host_txt.config(state=tk.NORMAL),
            self.host_txt.delete("1.0",tk.END),
            self.host_txt.config(state=tk.DISABLED)]).pack(side=tk.RIGHT, padx=4)
        self.host_txt = PText(tab, state=tk.DISABLED)
        self.host_txt.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0,10))

    def _hlog(self, text, tag="host"):
        self.host_txt.config(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self.host_txt.insert(tk.END, f"[{ts}] {text}\n", tag)
        self.host_txt.config(state=tk.DISABLED)
        self.host_txt.see(tk.END)

    def _on_scan_done(self, report):
        self._scan_report = report
        def _show():
            self._hlog("═══ АВТОАУДИТ ХОСТА ═══", "chain")
            self._hlog(f"ОС: {report.get('os',{}).get('system','?')} {report.get('os',{}).get('release','?')}", "host")
            hw = report.get("hardware", {})
            self._hlog(f"CPU: {hw.get('cpu_count','?')} ядер  RAM: {hw.get('ram_total','?')} / {hw.get('ram_free','?')} свободно", "host")
            net = report.get("network", {})
            self._hlog(f"IP: {net.get('local_ip','?')}  Внешний: {net.get('external_ip','N/A')}", "host")
            if net.get("geo_country"): self._hlog(f"Страна: {net.get('geo_country')} / {net.get('geo_city')} / {net.get('geo_isp','')}", "host")
            if net.get("vpn_detected"): self._hlog("⚠ VPN/Proxy обнаружен на хосте!", "warn")
            procs = report.get("processes", {})
            self._hlog(f"Процессов запущено: {procs.get('count', '?')}", "host")
            sus = procs.get("suspicious", [])
            for s in sus: self._hlog(f"⚠ ПОДОЗРИТЕЛЬНЫЙ: {s}", "warn")
            ports = report.get("ports", [])
            self._hlog(f"Открытые порты: {', '.join(ports)}", "host" if ports else "ok")
            sec = report.get("security", {})
            for k, v in sec.items(): self._hlog(f"{k}: {v}", "ok" if "ON" in str(v) or "Включён" in str(v) else "warn")
            self._hlog("═══ АУДИТ ЗАВЕРШЁН ═══", "chain")
            self._clog("ХОСТ", "Аудит завершён. Подробности на вкладке ХОСТ", "host")
        self.root.after(0, _show)

    def _host_scan(self):
        self._hlog("Запуск полного скана...", "sys")
        self.scanner.run_full_scan(callback=self._on_scan_done)

    def _host_procs(self):
        self._hlog("=== ПРОЦЕССЫ ===", "chain")
        report = self.scanner.get_report()
        procs = report.get("processes", {})
        for p in (procs.get("list") or [])[:40]:
            self._hlog(p, "sys")
        sus = procs.get("suspicious") or []
        for s in sus: self._hlog("⚠ " + s, "warn")

    def _host_ports(self):
        self._hlog("=== ОТКРЫТЫЕ ПОРТЫ ===", "chain")
        report = self.scanner.get_report()
        for p in (report.get("ports") or []): self._hlog(p, "host")

    def _host_save(self):
        report = self.scanner.get_report()
        if not report: messagebox.showwarning("Хост", "Нет данных — запусти скан"); return
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="darp_host_report.txt",
                                         filetypes=[("TXT","*.txt")])
        if p:
            Path(p).write_text(self.scanner.format_report(report), encoding="utf-8")
            messagebox.showinfo("OK", "Отчёт сохранён: " + p)

    # ── SOS / УНИЧТОЖЕНИЕ ────────────────────────────────────────────

    def _tab_sos(self):
        tab = tk.Frame(self.nb, bg=C["bg"])
        self.nb.add(tab, text="  ⚠ SOS  ")
        mkl(tab, "ЭКСТРЕННЫЕ ФУНКЦИИ", size=16, bold=True,
            color=C["danger"], bg=C["bg"]).pack(pady=(16,4))
        mkl(tab, "НЕОБРАТИМЫЕ ДЕЙСТВИЯ — ДУМАЙ ДВАЖДЫ",
            color=C["warn"], bg=C["bg"]).pack()
        tk.Frame(tab, bg=C["danger"], height=2).pack(fill=tk.X, padx=20, pady=12)

        ct = tk.Frame(tab, bg=C["bg"]); ct.pack(fill=tk.BOTH, expand=True, padx=24)

        # Самоуничтожение
        b1 = tk.Frame(ct, bg="#080000",
                      highlightbackground=C["danger"], highlightthickness=2)
        b1.pack(fill=tk.X, pady=6)
        mkl(b1, "САМОУНИЧТОЖЕНИЕ", size=13, bold=True,
            color=C["danger"], bg="#080000").pack(pady=(10,4))
        mkl(b1, "Затирание всех данных (7 проходов DoD 5220.22-M)",
            size=9, color=C["warn"], bg="#080000").pack()
        PBtn(b1, "[ УНИЧТОЖИТЬ ВСЕ ДАННЫЕ ]", v="d",
             command=self._self_destruct, width=30).pack(pady=10)

        # Команда партнёру
        b2 = tk.Frame(ct, bg="#050000",
                      highlightbackground="#550000", highlightthickness=1)
        b2.pack(fill=tk.X, pady=6)
        mkl(b2, "КОМАНДА ПАРТНЁРУ (0xFF DESTRUCT)", size=12, bold=True,
            color="#ff6666", bg="#050000").pack(pady=(8,2))
        mkl(b2, "Отправка PKT_DESTRUCT — удалённое уничтожение",
            size=9, color="#664444", bg="#050000").pack()
        PBtn(b2, "[ КОМАНДА ПАРТНЁРУ ]", v="d",
             command=self._destruct_partner, width=26).pack(pady=8)

        # Хамелеон
        b3 = tk.Frame(ct, bg=C["bg_p"],
                      highlightbackground=C["warn"], highlightthickness=1)
        b3.pack(fill=tk.X, pady=6)
        mkl(b3, "РЕЖИМ ХАМЕЛЕОН", size=12, bold=True,
            color=C["warn"], bg=C["bg_p"]).pack(pady=(8,2))
        mkl(b3, "Маскировка под системный журнал. Выход: xXx",
            size=9, bg=C["bg_p"]).pack()
        PBtn(b3, "[ АКТИВИРОВАТЬ ]", v="w",
             command=self._chameleon, width=22).pack(pady=8)

    def _self_destruct(self):
        if not messagebox.askyesno("САМОУНИЧТОЖЕНИЕ",
            "Уничтожить ВСЕ данные?\nКлючи, сообщения, блокчейн.\nНЕОБРАТИМО!"):
            return
        self.blockchain.log_destruct("self")
        for d in [ROOT/"keys", ROOT/"data"]:
            if d.exists():
                for f in d.rglob("*"):
                    if f.is_file():
                        try: secure_wipe(f)
                        except Exception: f.unlink(missing_ok=True)
        self.sandbox.clear_all()
        messagebox.showinfo("Выполнено", "Данные уничтожены")
        self.root.destroy()

    def _destruct_partner(self):
        if not messagebox.askyesno("", "Отправить 0xFF партнёру?"): return
        self.blockchain.log_destruct("partner")
        if self.network and self._peer_connected:
            try:
                self.network.send_packet(PKT_DESTRUCT, b"")
                messagebox.showinfo("OK", "Команда отправлена")
            except Exception as e: messagebox.showwarning("Ошибка", str(e))
        else: messagebox.showwarning("", "Партнёр не подключён")

    def _chameleon(self):
        w = tk.Toplevel(self.root)
        w.title("System Log Viewer"); w.geometry("800x480"); w.configure(bg="#000")
        t = tk.Text(w, bg="#000", fg="#aaa", font=("Courier New", 10))
        t.pack(fill=tk.BOTH, expand=True)
        import random
        lines = [
            "[  OK  ] Started Journal Service.",
            "[  OK  ] Reached target Network.",
            "kernel: [2.341] EXT4-fs (sda1): mounted filesystem with ordered data mode",
            "systemd[1]: Started OpenSSH Server Daemon.",
            "NetworkManager: <info>  [1714123456.3451] address 192.168.1." + str(random.randint(2,254)),
            "[  OK  ] Started Daily apt upgrade and clean activities.",
            "kernel: [4.782] usb 2-1: new high-speed USB device number 3 using xhci_hcd",
            "systemd-logind[847]: New session 1 of user user.",
            "[  OK  ] Started CUPS Scheduler.",
        ]
        for line in lines: t.insert(tk.END, line + "\n")
        t.config(state=tk.DISABLED)
        buf = []
        def key(e):
            buf.append(e.char)
            if "xXx" in "".join(buf[-5:]): w.destroy()
        w.bind("<Key>", key)

    # ── USB WATCHDOG ─────────────────────────────────────────────────

    def _start_usb_watchdog(self):
        def _watch():
            while True:
                time.sleep(1)
                try:
                    if not self.root.winfo_exists(): break
                except Exception: break
                cur = get_usb_serial()
                if cur != self._usb_serial and not self._locked:
                    self._locked = True
                    self.root.after(0, self._show_lock_screen)
                elif cur == self._usb_serial and self._locked:
                    self._locked = False
                    self.root.after(0, self._hide_lock_screen)
        threading.Thread(target=_watch, daemon=True).start()

    def _show_lock_screen(self):
        if self._lock_frame: return
        self.blockchain.log_system("USB_REMOVED: LOCKED")
        self._lock_frame = tk.Frame(self.root, bg="#000000")
        self._lock_frame.place(x=0, y=0, relwidth=1, relheight=1)
        self._lock_frame.lift()
        c = tk.Frame(self._lock_frame, bg="#0a0000",
                     highlightbackground="#ff0000", highlightthickness=4)
        c.place(relx=.5, rely=.5, anchor="center", width=560, height=300)
        tk.Label(c, text="🔒  СИСТЕМА ЗАБЛОКИРОВАНА",
                 font=("Courier New",20,"bold"), fg="#ff2222", bg="#0a0000").pack(pady=(32,10))
        tk.Label(c, text="USB-накопитель извлечён",
                 font=("Courier New",13), fg="#ffaa00", bg="#0a0000").pack()
        tk.Label(c, text="Вставьте USB для разблокировки",
                 font=("Courier New",11), fg="#ff6666", bg="#0a0000").pack(pady=8)
        self._lock_t = 0
        self._lock_lbl = tk.Label(c, text="",
                 font=("Courier New",9), fg="#444444", bg="#0a0000")
        self._lock_lbl.pack()
        # Кнопка выхода
        PBtn(c, "ВЫЙТИ ИЗ DARP", v="d",
             command=self.root.destroy).pack(pady=(12,0))
        self._upd_lock_timer()

    def _upd_lock_timer(self):
        if not self._locked or not self._lock_frame: return
        self._lock_t += 1
        if hasattr(self, "_lock_lbl"):
            try: self._lock_lbl.config(text=f"Заблокировано {self._lock_t}с")
            except Exception: pass
        self.root.after(1000, self._upd_lock_timer)

    def _hide_lock_screen(self):
        if self._lock_frame:
            self._lock_frame.destroy()
            self._lock_frame = None
            self._clog("USB", "Флешка вставлена — разблокировано", "ok")
            self.blockchain.log_system("USB_INSERTED: UNLOCKED")

    # ── CLOCK ────────────────────────────────────────────────────────

    def _tick_clock(self):
        try:
            if not self.root.winfo_exists(): return
        except Exception: return
        self.time_lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.sb_r.config(
            text=f"Chain: {len(self.blockchain)} blk | {datetime.now().strftime('%H:%M:%S')}  ")
        self.root.after(1000, self._tick_clock)

    # ── TOR FINDER ───────────────────────────────────────────────────

    @staticmethod
    def _find_tor_exe() -> str:
        import shutil
        # 1. Проверяем пользовательский путь
        custom = ROOT / "data" / "tor_path.txt"
        if custom.exists():
            p = custom.read_text().strip()
            if os.path.isfile(p): return p
        # 2. PATH
        t = shutil.which("tor")
        if t: return t
        # 3. Широкий поиск
        u = os.environ.get("USERNAME","") or os.environ.get("USER","")
        bases = [
            os.environ.get("USERPROFILE",""),
            os.environ.get("APPDATA",""),
            os.environ.get("LOCALAPPDATA",""),
            os.environ.get("PROGRAMFILES",""),
            os.environ.get("PROGRAMFILES(X86)",""),
            f"C:\\Users\\{u}" if u else "",
        ]
        sub_paths = [
            "Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
            "Downloads\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
            "Downloads\\tor.exe",
            "AppData\\Local\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
            "Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
        ]
        fixed = [
            "C:\\Tor\\tor.exe",
            "C:\\Program Files\\Tor\\tor.exe",
            "C:\\Program Files\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
            "C:\\Program Files (x86)\\Tor\\tor.exe",
        ]
        candidates = list(fixed)
        for base in bases:
            if base:
                for sub in sub_paths:
                    candidates.append(os.path.join(base, sub))
        for c in candidates:
            if c and os.path.isfile(c): return c
        return ""


# ════════════════════════════════════════════════════════════════════
#  PANIC MODE — запуск + уничтожение
# ════════════════════════════════════════════════════════════════════

def panic_destruct(root_path: Path):
    """Немедленное уничтожение данных при panic-пароле."""
    for d in [root_path/"keys", root_path/"data"]:
        if d.exists():
            for f in d.rglob("*"):
                if f.is_file():
                    try: secure_wipe(f)
                    except Exception: f.unlink(missing_ok=True)


# ════════════════════════════════════════════════════════════════════
#  ТОЧКА ВХОДА
# ════════════════════════════════════════════════════════════════════

def run_darp_v8():
    root = tk.Tk()
    root.title("DARP v8")
    root.configure(bg=C["bg"])

    auth = AuthManager(ROOT / "keys")

    def show_login():
        root.geometry("440x540")
        try: root.minsize(0, 0)
        except Exception: pass
        LoginScreen(root, auth, on_login_ok)

    def on_login_ok(session_key, role, is_panic):
        # Паника — уничтожаем данные, потом показываем пустое приложение
        if is_panic:
            panic_destruct(ROOT)

        for w in root.winfo_children():
            w.destroy()
        try:
            DARPApp(root, session_key, role, auth_mgr=auth)
            if is_panic:
                # После уничтожения — закрыть через 3 сек
                root.after(3000, root.destroy)
        except Exception as e:
            import traceback
            err = traceback.format_exc()
            root.geometry("700x500"); root.configure(bg="#050d05")
            tk.Label(root, text="ОШИБКА ЗАПУСКА DARP",
                     font=("Courier New",14,"bold"),
                     fg="#ff2222", bg="#050d05").pack(pady=20)
            txt = tk.Text(root, bg="#0a0000", fg="#ff6666",
                          font=("Courier New",9), wrap=tk.WORD)
            txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            txt.insert(tk.END, f"Ошибка:\n{e}\n\nTraceback:\n{err}")
            txt.config(state=tk.DISABLED)
            tk.Button(root, text="Закрыть", command=root.destroy,
                      bg="#ff2222", fg="white",
                      font=("Courier New",11)).pack(pady=10)

    if auth.is_setup():
        show_login()
    else:
        root.geometry("460x620")
        SetupScreen(root, auth, on_done=show_login)

    root.mainloop()
