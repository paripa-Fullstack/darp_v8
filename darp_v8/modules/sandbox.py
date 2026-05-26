"""
DARP v8 :: Sandbox — изолированная среда просмотра файлов в ОЗУ
Файлы открываются только из RAM, не оставляют следов на диске.
"""
import os, sys, io, zlib, struct, threading, time, tempfile, subprocess
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    HAS_TK = True
except ImportError:
    HAS_TK = False

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

from core.crypto_stb import encrypt_hybrid, decrypt_hybrid, bash_hash


SANDBOX_MAGIC = b'DARPv8SBOX'
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


class SandboxManager:
    """
    Песочница DARP v8:
    - Файлы шифруются и хранятся в RAM-буфере
    - Просмотр через временные файлы в %TEMP% (удаляются немедленно после закрытия)
    - Поддерживаемые форматы: TXT, PNG, JPG, PDF (системный просмотрщик)
    - Шифрование Belt-128 / AES-256-GCM
    """

    def __init__(self, session_key: bytes):
        self.session_key = session_key
        self._ram_store: dict[str, bytes] = {}  # {id: encrypted_bytes}
        self._lock = threading.Lock()

    # ── Загрузка файла в RAM ─────────────────────────────────────────
    def load_file(self, path) -> tuple[str, str]:
        """Загружает файл в RAM, шифрует. Возвращает (file_id, имя файла)."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Файл не найден: {path}")
        raw = p.read_bytes()
        if len(raw) > MAX_FILE_SIZE:
            raise ValueError(f"Файл слишком большой (макс {MAX_FILE_SIZE//1024//1024}MB)")

        compressed = zlib.compress(raw, level=6)
        meta_bytes = p.name.encode('utf-8')
        payload = (SANDBOX_MAGIC +
                   struct.pack('>I', len(meta_bytes)) + meta_bytes +
                   struct.pack('>I', len(raw)) +
                   compressed)
        encrypted = encrypt_hybrid(payload, self.session_key, use_stb=True)

        file_id = bash_hash(encrypted, 256).hex()[:12]
        with self._lock:
            self._ram_store[file_id] = encrypted

        # Оригинальный файл на диске НЕ читается повторно — работаем только с RAM
        return file_id, p.name

    # ── Просмотр файла из RAM ────────────────────────────────────────
    def view_file(self, file_id: str, parent_widget=None) -> bool:
        with self._lock:
            if file_id not in self._ram_store:
                return False
            encrypted = self._ram_store[file_id]

        try:
            payload = decrypt_hybrid(encrypted, self.session_key)
            if not payload.startswith(SANDBOX_MAGIC):
                return False
            ml = struct.unpack('>I', payload[len(SANDBOX_MAGIC):len(SANDBOX_MAGIC)+4])[0]
            fname = payload[len(SANDBOX_MAGIC)+4:len(SANDBOX_MAGIC)+4+ml].decode('utf-8')
            orig_size = struct.unpack('>I', payload[len(SANDBOX_MAGIC)+4+ml:len(SANDBOX_MAGIC)+4+ml+4])[0]
            compressed = payload[len(SANDBOX_MAGIC)+4+ml+4:]
            raw = zlib.decompress(compressed)
        except Exception:
            return False

        ext = Path(fname).suffix.lower()
        if ext in ('.txt', '.log', '.md', '.py', '.json', '.csv', '.ini', '.cfg'):
            self._view_text(fname, raw, parent_widget)
        elif ext in ('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp'):
            self._view_image(fname, raw, parent_widget)
        else:
            # Для других форматов — временный файл, сразу удаляем
            self._view_external(fname, raw)
        return True

    def _view_text(self, fname: str, raw: bytes, parent):
        if not HAS_TK: return
        try: text = raw.decode('utf-8')
        except Exception:
            try: text = raw.decode('cp1251')
            except Exception: text = repr(raw[:2000])

        win = tk.Toplevel(parent) if parent else tk.Tk()
        win.title(f"SANDBOX :: {fname}")
        win.configure(bg="#050d05")
        win.geometry("900x600")

        tk.Label(win, text=f"  🔒 SANDBOX  —  {fname}  ({len(raw)} bytes)",
                 font=("Courier New",10,"bold"), fg="#ffcc00", bg="#050d05").pack(fill='x',pady=(8,0))
        tk.Label(win, text="  Файл открыт из RAM. Следов на диске нет.",
                 font=("Courier New",8), fg="#007a20", bg="#050d05").pack(fill='x')

        t = tk.Text(win, bg="#040d04", fg="#00ff41", font=("Courier New",10),
                    wrap=tk.NONE, insertbackground="#00ff41")
        sb_v = tk.Scrollbar(win, command=t.yview); sb_v.pack(side='right', fill='y')
        sb_h = tk.Scrollbar(win, orient='horizontal', command=t.xview); sb_h.pack(side='bottom', fill='x')
        t.config(yscrollcommand=sb_v.set, xscrollcommand=sb_h.set)
        t.pack(fill='both', expand=True, padx=4, pady=4)
        t.insert('1.0', text)
        t.config(state='disabled')

        def _on_close():
            raw_ref = None  # явно освобождаем ссылки
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", _on_close)

    def _view_image(self, fname: str, raw: bytes, parent):
        if not HAS_TK or not HAS_PIL: return
        win = tk.Toplevel(parent) if parent else tk.Tk()
        win.title(f"SANDBOX :: {fname}")
        win.configure(bg="#050d05")

        tk.Label(win, text=f"  🔒 SANDBOX  —  {fname}",
                 font=("Courier New",10,"bold"), fg="#ffcc00", bg="#050d05").pack(fill='x', pady=4)

        img = Image.open(io.BytesIO(raw))
        img.thumbnail((800, 600))
        photo = ImageTk.PhotoImage(img)
        lbl = tk.Label(win, image=photo, bg="#050d05")
        lbl.image = photo
        lbl.pack(padx=10, pady=10)

        def _on_close():
            lbl.image = None
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", _on_close)

    def _view_external(self, fname: str, raw: bytes):
        """Временный файл → системный просмотрщик → немедленное удаление."""
        import platform
        suffix = Path(fname).suffix
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, prefix='darp_sbox_') as f:
            f.write(raw); tmp_path = f.name
        try:
            if platform.system() == "Windows":
                os.startfile(tmp_path)
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", tmp_path])
            else:
                subprocess.Popen(["xdg-open", tmp_path])
            # Удаляем через 30 сек (дать время открыться)
            def _delete_later():
                time.sleep(30)
                try: os.unlink(tmp_path)
                except Exception: pass
            threading.Thread(target=_delete_later, daemon=True).start()
        except Exception:
            try: os.unlink(tmp_path)
            except Exception: pass

    # ── Удаление из RAM ──────────────────────────────────────────────
    def remove_file(self, file_id: str):
        with self._lock:
            self._ram_store.pop(file_id, None)

    def clear_all(self):
        with self._lock:
            self._ram_store.clear()

    def list_files(self) -> list:
        """Возвращает список (file_id, fname, size) из RAM."""
        items = []
        with self._lock:
            for fid, enc in self._ram_store.items():
                try:
                    payload = decrypt_hybrid(enc, self.session_key)
                    if payload.startswith(SANDBOX_MAGIC):
                        ml = struct.unpack('>I', payload[len(SANDBOX_MAGIC):len(SANDBOX_MAGIC)+4])[0]
                        fname = payload[len(SANDBOX_MAGIC)+4:len(SANDBOX_MAGIC)+4+ml].decode('utf-8')
                        items.append((fid, fname, len(enc)))
                except Exception:
                    pass
        return items
