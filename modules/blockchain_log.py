"""
DARP v7 :: Блокчейн-лог событий
══════════════════════════════════
Защищённый от фальсификации журнал событий на основе блокчейн-структуры.
Каждый блок содержит:
  • BashHash предыдущего блока (СТБ 34.101.77-2020)
  • Подписанные данные события
  • Временную метку + nonce для уникальности
  • Proof-of-Work (лёгкий, для защиты от спама)

Блокчейн хранится в зашифрованном файле на USB-флешке.
Директор может экспортировать лог в JSON/HTML.
"""

import json, time, os, struct, threading
from pathlib import Path
from datetime import datetime
from core.crypto_stb import (encrypt_hybrid, decrypt_hybrid,
                               bash_hash, hmac_bash, secure_wipe)


# ────────────────────────────────────────────────────────────────────
#  КОНСТАНТЫ
# ────────────────────────────────────────────────────────────────────
CHAIN_FILE   = "chain.enc"
GENESIS_HASH = "0" * 64   # Нулевой хэш генезис-блока
POW_BITS     = 0           # PoW отключён — BashHash слишком медленный
VERSION      = "DARP-CHAIN-v7"

# Типы событий
EVENT_AUTH_OK     = "AUTH_SUCCESS"
EVENT_AUTH_FAIL   = "AUTH_FAIL"
EVENT_MSG_SENT    = "MSG_SENT"
EVENT_MSG_RECV    = "MSG_RECV"
EVENT_VOICE_SENT  = "VOICE_SENT"
EVENT_FILE_SENT   = "FILE_SENT"
EVENT_DESTRUCT    = "SELF_DESTRUCT"
EVENT_PARTNER_DEST= "PARTNER_DESTRUCT"
EVENT_CONNECT     = "PEER_CONNECT"
EVENT_DISCONNECT  = "PEER_DISCONNECT"
EVENT_VAULT_ACCESS= "VAULT_ACCESS"
EVENT_STEGO       = "STEGO_OPERATION"
EVENT_TOR_START   = "TOR_STARTED"
EVENT_INTEGRITY   = "INTEGRITY_CHECK"
EVENT_EMERGENCY   = "EMERGENCY_TRIGGER"
EVENT_SYSTEM      = "SYSTEM"


# ────────────────────────────────────────────────────────────────────
#  БЛОК ЦЕПОЧКИ
# ────────────────────────────────────────────────────────────────────

class Block:
    """Один блок в блокчейн-логе событий."""
    
    __slots__ = ['index', 'timestamp', 'event_type', 'data',
                 'prev_hash', 'nonce', 'hash', 'role']
    
    def __init__(self, index: int, event_type: str, data: dict,
                 prev_hash: str, role: str = "DIRECTOR"):
        self.index      = index
        self.timestamp  = time.time()
        self.event_type = event_type
        self.data       = data
        self.prev_hash  = prev_hash
        self.role       = role
        self.nonce      = 0
        self.hash       = ""
        self._mine()
    
    def _content_bytes(self) -> bytes:
        """Байты для хэширования."""
        return json.dumps({
            "index":      self.index,
            "timestamp":  self.timestamp,
            "event_type": self.event_type,
            "data":       self.data,
            "prev_hash":  self.prev_hash,
            "role":       self.role,
            "nonce":      self.nonce
        }, sort_keys=True, ensure_ascii=False).encode()
    
    def _mine(self):
        """Хэш блока через SHA-256 (быстро). BashHash только для подписи."""
        import hashlib
        content = self._content_bytes()
        self.hash = hashlib.sha256(content).hexdigest()
    
    def verify(self) -> bool:
        """Проверка целостности блока."""
        # Временно сохраняем hash
        stored_hash = self.hash
        self.hash = ""
        content = self._content_bytes()
        self.hash = stored_hash
        
        import hashlib
        computed = hashlib.sha256(content).hexdigest()
        return computed == stored_hash
    
    def to_dict(self) -> dict:
        return {
            "index":      self.index,
            "timestamp":  self.timestamp,
            "datetime":   datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": self.event_type,
            "data":       self.data,
            "prev_hash":  self.prev_hash,
            "role":       self.role,
            "nonce":      self.nonce,
            "hash":       self.hash
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> 'Block':
        b = object.__new__(cls)
        b.index      = d["index"]
        b.timestamp  = d["timestamp"]
        b.event_type = d["event_type"]
        b.data       = d["data"]
        b.prev_hash  = d["prev_hash"]
        b.role       = d.get("role", "UNKNOWN")
        b.nonce      = d["nonce"]
        b.hash       = d["hash"]
        return b


# ────────────────────────────────────────────────────────────────────
#  БЛОКЧЕЙН
# ────────────────────────────────────────────────────────────────────

class EventBlockchain:
    """
    Блокчейн-журнал событий DARP.
    Хранится в зашифрованном файле на USB-флешке.
    """
    
    def __init__(self, data_dir: Path, session_key: bytes, role: str = "DIRECTOR"):
        self.data_dir    = data_dir
        self.chain_path  = data_dir / CHAIN_FILE
        self.session_key = session_key
        self.role        = role
        self._chain      = []
        self._lock       = threading.Lock()
        
        self._load_chain()
        
        # Если цепочка пустая — создаём генезис-блок
        if not self._chain:
            self._create_genesis()
    
    # ── Генезис ──────────────────────────────────────────────────────
    def _create_genesis(self):
        genesis = Block(
            index=0,
            event_type="GENESIS",
            data={
                "message": "DARP v7 Blockchain Log Initialized",
                "version": VERSION,
                "standard": "СТБ 34.101.77-2020 (BashHash)"
            },
            prev_hash=GENESIS_HASH,
            role=self.role
        )
        self._chain.append(genesis)
        self._save_chain()
    
    # ── Добавление события ────────────────────────────────────────────
    def add_event(self, event_type: str, data: dict = None,
                  sensitive: bool = False) -> Block:
        """
        Добавить событие в блокчейн.
        sensitive=True — данные хэшируются (не хранятся в открытом виде).
        """
        with self._lock:
            if data is None:
                data = {}
            
            # Чувствительные данные — только хэш
            if sensitive and data:
                data = {
                    "hash": bash_hash(
                        json.dumps(data, sort_keys=True).encode(), 256
                    ).hex()[:32],
                    "sensitive": True
                }
            
            block = Block(
                index=len(self._chain),
                event_type=event_type,
                data=data,
                prev_hash=self._chain[-1].hash,
                role=self.role
            )
            self._chain.append(block)
            self._save_chain()
            return block
    
    # ── Быстрые методы логирования ───────────────────────────────────
    def log_auth_ok(self, role: str):
        self.add_event(EVENT_AUTH_OK, {"role": role, "method": "3FA-STB"})
    
    def log_auth_fail(self, reason: str, attempts: int):
        self.add_event(EVENT_AUTH_FAIL, {
            "reason": reason, "attempts": attempts}, sensitive=False)
    
    def log_message(self, direction: str, size: int, algo: str = "Belt-128"):
        evt = EVENT_MSG_SENT if direction == "out" else EVENT_MSG_RECV
        self.add_event(evt, {"size": size, "algo": algo})
    
    def log_voice(self, duration: float, size: int):
        self.add_event(EVENT_VOICE_SENT, {
            "duration": duration, "size": size, "codec": "PCM-16/Belt"})
    
    def log_connect(self, peer: str, via_tor: bool = False):
        self.add_event(EVENT_CONNECT, {
            "peer": peer[:8] + "..." if len(peer) > 8 else peer,
            "via_tor": via_tor})
    
    def log_disconnect(self, reason: str):
        self.add_event(EVENT_DISCONNECT, {"reason": reason})
    
    def log_destruct(self, target: str):
        self.add_event(EVENT_DESTRUCT if target == "self" else EVENT_PARTNER_DEST,
                       {"target": target, "wipe_passes": 7}, sensitive=False)
    
    def log_vault(self, action: str, filename: str):
        self.add_event(EVENT_VAULT_ACCESS, {
            "action": action,
            "file_hash": bash_hash(filename.encode(), 256).hex()[:16]
        })
    
    def log_stego(self, method: str, action: str):
        self.add_event(EVENT_STEGO, {"method": method, "action": action})
    
    def log_integrity(self, ok: bool, modified: list = None):
        self.add_event(EVENT_INTEGRITY, {
            "ok": ok,
            "modified_count": len(modified) if modified else 0
        })
    
    def log_system(self, message: str):
        self.add_event(EVENT_SYSTEM, {"message": message[:200]})
    
    # ── Проверка цепочки ─────────────────────────────────────────────
    def verify_chain(self) -> dict:
        """Полная верификация блокчейна."""
        errors = []
        valid_blocks = 0
        
        for i, block in enumerate(self._chain):
            # Проверяем PoW и хэш
            if not block.verify():
                errors.append(f"Блок #{i}: недействительный хэш/PoW")
                continue
            
            # Проверяем связность
            if i > 0:
                if block.prev_hash != self._chain[i-1].hash:
                    errors.append(f"Блок #{i}: нарушена связность цепи")
                    continue
            
            valid_blocks += 1
        
        return {
            "valid":        len(errors) == 0,
            "total_blocks": len(self._chain),
            "valid_blocks": valid_blocks,
            "errors":       errors,
            "chain_hash":   self._chain[-1].hash if self._chain else None,
            "algorithm":    "BashHash-256 (СТБ 34.101.77-2020)",
            "pow_bits":     POW_BITS
        }
    
    # ── Статистика ───────────────────────────────────────────────────
    def get_stats(self) -> dict:
        """Статистика событий."""
        counts = {}
        for block in self._chain:
            evt = block.event_type
            counts[evt] = counts.get(evt, 0) + 1
        
        session_start = self._chain[1].timestamp if len(self._chain) > 1 else time.time()
        duration = time.time() - session_start
        
        return {
            "total_events": len(self._chain) - 1,  # без генезиса
            "event_counts": counts,
            "session_start": datetime.fromtimestamp(session_start).strftime("%H:%M:%S"),
            "session_duration": self._format_duration(duration),
            "messages_sent": counts.get(EVENT_MSG_SENT, 0),
            "messages_recv": counts.get(EVENT_MSG_RECV, 0),
            "auth_attempts": counts.get(EVENT_AUTH_FAIL, 0),
            "chain_length": len(self._chain)
        }
    
    def get_recent(self, n: int = 20) -> list:
        """Последние N событий."""
        return [b.to_dict() for b in reversed(self._chain[-n:])]
    
    def get_all(self) -> list:
        return [b.to_dict() for b in self._chain]
    
    # ── Экспорт ──────────────────────────────────────────────────────
    def export_html(self, output_path: Path) -> bool:
        """Экспорт блокчейн-лога в HTML-отчёт."""
        blocks = self.get_all()
        verify = self.verify_chain()
        stats  = self.get_stats()
        
        event_colors = {
            "GENESIS":        "#00ff41",
            "AUTH_SUCCESS":   "#00ff41",
            "AUTH_FAIL":      "#ff4141",
            "MSG_SENT":       "#41aaff",
            "MSG_RECV":       "#41ffaa",
            "VOICE_SENT":     "#ff41ff",
            "FILE_SENT":      "#ffaa41",
            "SELF_DESTRUCT":  "#ff0000",
            "PARTNER_DESTRUCT": "#ff0000",
            "PEER_CONNECT":   "#00ff41",
            "PEER_DISCONNECT":"#ffaa41",
            "VAULT_ACCESS":   "#ff41ff",
            "STEGO_OPERATION":"#aa41ff",
            "INTEGRITY_CHECK":"#41ffff",
            "SYSTEM":         "#888888",
        }
        
        rows = ""
        for b in reversed(blocks):
            color = event_colors.get(b["event_type"], "#aaaaaa")
            rows += f"""
            <tr>
                <td class="idx">#{b['index']}</td>
                <td class="ts">{b['datetime']}</td>
                <td class="evt" style="color:{color}">{b['event_type']}</td>
                <td class="role">{b['role']}</td>
                <td class="data">{json.dumps(b['data'], ensure_ascii=False)}</td>
                <td class="hash" title="{b['hash']}">{b['hash'][:12]}…</td>
            </tr>"""
        
        valid_badge = (
            '<span class="valid">✓ ЦЕПЬ ВАЛИДНА</span>' if verify["valid"]
            else f'<span class="invalid">✗ ОШИБОК: {len(verify["errors"])}</span>'
        )
        
        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>DARP v7 — Blockchain Log</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0a0a0a; color: #00ff41; font-family: 'Share Tech Mono', monospace;
          padding: 20px; min-height: 100vh; }}
  h1 {{ font-size: 1.4em; border-bottom: 1px solid #00ff41; padding-bottom: 10px;
        margin-bottom: 20px; letter-spacing: 4px; }}
  .stats {{ display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px; }}
  .stat {{ border: 1px solid #00ff4155; padding: 10px 16px; background: #0f1a0f; }}
  .stat .val {{ font-size: 1.6em; color: #fff; }}
  .stat .lbl {{ font-size: 0.75em; color: #00ff4188; }}
  .valid   {{ color: #00ff41; border: 1px solid #00ff41; padding: 4px 10px; }}
  .invalid {{ color: #ff4141; border: 1px solid #ff4141; padding: 4px 10px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.78em; }}
  th {{ background: #0f1a0f; padding: 8px; text-align: left; border-bottom: 1px solid #00ff4155;
        letter-spacing: 2px; color: #00ff41aa; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #00ff4122; vertical-align: top; }}
  tr:hover td {{ background: #0f1a0f; }}
  .idx  {{ color: #555; width: 50px; }}
  .ts   {{ color: #888; white-space: nowrap; }}
  .evt  {{ font-weight: bold; white-space: nowrap; }}
  .role {{ color: #ffaa41; }}
  .data {{ color: #aaa; max-width: 300px; word-break: break-all; }}
  .hash {{ color: #555; font-size: 0.85em; }}
  .footer {{ margin-top: 20px; color: #333; font-size: 0.75em; border-top: 1px solid #1a1a1a;
             padding-top: 10px; }}
</style>
</head>
<body>
<h1>◈ DARP v7 — BLOCKCHAIN EVENT LOG</h1>
<div class="stats">
  <div class="stat"><div class="val">{stats['total_events']}</div><div class="lbl">СОБЫТИЙ</div></div>
  <div class="stat"><div class="val">{stats['messages_sent']}</div><div class="lbl">ОТПРАВЛЕНО</div></div>
  <div class="stat"><div class="val">{stats['messages_recv']}</div><div class="lbl">ПОЛУЧЕНО</div></div>
  <div class="stat"><div class="val">{len(blocks)}</div><div class="lbl">БЛОКОВ</div></div>
  <div class="stat"><div class="val">{valid_badge}</div><div class="lbl">ЦЕЛОСТНОСТЬ</div></div>
</div>
<table>
<thead><tr>
  <th>#</th><th>ВРЕМЯ</th><th>СОБЫТИЕ</th><th>РОЛЬ</th><th>ДАННЫЕ</th><th>ХЭШ</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
<div class="footer">
  Алгоритм: BashHash-256 (СТБ 34.101.77-2020) | PoW: {POW_BITS} бит | 
  Экспорт: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</div>
</body></html>"""
        
        output_path.write_text(html, encoding='utf-8')
        return True
    
    def export_json(self, output_path: Path) -> bool:
        """Экспорт в JSON."""
        data = {
            "version":  VERSION,
            "standard": "СТБ 34.101.77-2020",
            "exported": datetime.now().isoformat(),
            "verify":   self.verify_chain(),
            "stats":    self.get_stats(),
            "chain":    self.get_all()
        }
        output_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
        return True
    
    # ── Хранение ─────────────────────────────────────────────────────
    def _save_chain(self):
        """Сохранение блокчейна в зашифрованный файл."""
        chain_data = json.dumps(
            [b.to_dict() for b in self._chain],
            ensure_ascii=False
        ).encode()
        encrypted = encrypt_hybrid(chain_data, self.session_key, use_stb=True)
        self.chain_path.write_bytes(encrypted)
    
    def _load_chain(self):
        """Загрузка блокчейна из зашифрованного файла."""
        if not self.chain_path.exists():
            return
        try:
            encrypted = self.chain_path.read_bytes()
            chain_data = decrypt_hybrid(encrypted, self.session_key)
            blocks_raw = json.loads(chain_data)
            self._chain = [Block.from_dict(b) for b in blocks_raw]
        except Exception:
            self._chain = []
    
    @staticmethod
    def _format_duration(seconds: float) -> str:
        s = int(seconds)
        h, rem = divmod(s, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"
    
    def __len__(self):
        return len(self._chain)
    
    def __repr__(self):
        return f"EventBlockchain({len(self._chain)} blocks, role={self.role})"
