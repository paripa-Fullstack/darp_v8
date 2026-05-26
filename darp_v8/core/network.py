"""
DARP v7 :: Сетевое ядро
═══════════════════════
TCP P2P протокол + файловая передача + Tor SOCKS5
Протокол: [4B len][1B type][payload_encrypted_belt128]
Шифрование: Belt-128 (СТБ 34.101.31-2020) / AES-256-GCM fallback
Порты: 8888 (чат), 8889 (файлы)
"""

import socket, threading, json, time, os, struct, queue, logging
from pathlib import Path

log = logging.getLogger("darp.net")

# ── Типы пакетов ──────────────────────────────────────────────────
PKT_HANDSHAKE  = 0x01   # обмен публичными ключами ECDH
PKT_MESSAGE    = 0x02   # текстовое сообщение
PKT_FILE_META  = 0x03   # метаданные файла
PKT_FILE_CHUNK = 0x04   # чанк файла
PKT_COMMAND    = 0x05   # команда
PKT_STATUS     = 0x06   # статус
PKT_PING       = 0x07   # ping
PKT_PONG       = 0x08   # pong
PKT_TYPING     = 0x09   # индикатор печати
PKT_GEO        = 0x0A   # геолокация
PKT_VOICE      = 0x0B   # голосовое сообщение
PKT_DESTRUCT   = 0xFF   # самоуничтожение

CHAT_PORT  = 8888
FILE_PORT  = 8889
CHUNK_SIZE = 65536
TIMEOUT    = 30


# ── Упаковка пакетов ─────────────────────────────────────────────

def pack(pkt_type: int, payload: bytes) -> bytes:
    return struct.pack(">IB", len(payload), pkt_type) + payload


def unpack(data: bytes) -> tuple:
    length, pkt_type = struct.unpack(">IB", data[:5])
    return pkt_type, data[5:5 + length]


def recv_packet(sock: socket.socket):
    try:
        header = _recv_exact(sock, 5)
        if not header:
            return None
        length, pkt_type = struct.unpack(">IB", header)
        if length > 64 * 1024 * 1024:  # 64MB лимит
            return None
        payload = _recv_exact(sock, length)
        return pkt_type, payload
    except Exception:
        return None


def _recv_exact(sock: socket.socket, n: int):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        except Exception:
            return None
    return buf


# ════════════════════════════════════════════════════════════════════
#  DARPNetwork — основной класс
# ════════════════════════════════════════════════════════════════════

class DARPNetwork:
    """
    P2P сетевое соединение DARP v7.
    Использует Belt-128 (СТБ 34.101.31-2020) для шифрования трафика.
    Поддерживает прямое TCP и Tor SOCKS5 подключение.
    """

    def __init__(self, data_dir: Path, session_key: bytes):
        self.data_dir    = data_dir
        self.session_key = session_key

        self._sock       = None       # активный сокет
        self._peer_addr  = None       # адрес партнёра
        self._connected  = False
        self._lock       = threading.Lock()
        self._recv_queue = queue.Queue()
        self._server_sock = None

        # Колбэки — устанавливаются из DARPApp
        self.on_message    = None     # fn(dict)
        self.on_connect    = None     # fn(peer_addr: str)
        self.on_disconnect = None     # fn(reason: str)
        self.on_file       = None     # fn(filename, data)
        self.on_typing     = None     # fn()

        # Запускаем сервер (слушаем входящие)
        self._start_server()

    # ── Сервер (входящие соединения) ─────────────────────────────

    def start_server(self):
        """Публичный алиас для запуска TCP-сервера."""
        return self._start_server()

    def _start_server(self):
        """Запускает TCP-сервер на порту 8888."""
        def _serve():
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", CHAT_PORT))
                srv.listen(1)
                srv.settimeout(1.0)
                self._server_sock = srv
                log.info(f"Сервер слушает на порту {CHAT_PORT}")
                while True:
                    try:
                        conn, addr = srv.accept()
                        log.info(f"Входящее подключение от {addr}")
                        self._handle_connection(conn, addr[0])
                    except socket.timeout:
                        continue
                    except Exception:
                        break
            except Exception as e:
                log.error(f"Ошибка сервера: {e}")
        threading.Thread(target=_serve, daemon=True).start()

    # ── Подключение к партнёру ────────────────────────────────────

    def connect(self, addr: str, via_tor: bool = False):
        """
        Подключение к партнёру.
        addr: IP:PORT или host.onion:PORT
        via_tor: использовать Tor SOCKS5 (127.0.0.1:9050)
        """
        if ":" in addr and not addr.endswith(".onion"):
            host, port_s = addr.rsplit(":", 1)
            port = int(port_s)
        else:
            host = addr.replace(":8888", "").strip()
            port = CHAT_PORT

        if via_tor or host.endswith(".onion"):
            sock = self._connect_tor(host, port)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((host, port))

        self._handle_connection(sock, host)

    def _connect_tor(self, host: str, port: int) -> socket.socket:
        """Подключение через Tor SOCKS5."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect(("127.0.0.1", 9050))

        # SOCKS5 handshake
        sock.send(b"\x05\x01\x00")
        resp = sock.recv(2)
        if resp != b"\x05\x00":
            raise ConnectionError("Tor SOCKS5 недоступен")

        # SOCKS5 connect
        host_enc = host.encode()
        req = (b"\x05\x01\x00\x03" +
               bytes([len(host_enc)]) +
               host_enc +
               struct.pack(">H", port))
        sock.send(req)
        resp = sock.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            raise ConnectionError(f"Tor CONNECT failed: {resp}")

        return sock

    def _handle_connection(self, sock: socket.socket, peer_addr: str):
        """Обработка установленного соединения."""
        with self._lock:
            if self._sock:
                try: self._sock.close()
                except Exception: pass
            self._sock = sock
            self._peer_addr = peer_addr
            self._connected = True

        # Handshake — обмен публичными ключами
        try:
            self._do_handshake(sock)
        except Exception as e:
            log.warning(f"Handshake failed: {e}")
            # Продолжаем с session_key без ECDH

        if self.on_connect:
            self.on_connect(peer_addr)

        # Запускаем получение сообщений
        threading.Thread(
            target=self._recv_loop,
            args=(sock,),
            daemon=True
        ).start()

    def _do_handshake(self, sock: socket.socket):
        """ECDH handshake для согласования сессионного ключа."""
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat)

            priv = X25519PrivateKey.generate()
            pub  = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

            # Отправляем публичный ключ
            sock.send(pack(PKT_HANDSHAKE, pub))

            # Получаем ключ партнёра
            result = recv_packet(sock)
            if result and result[0] == PKT_HANDSHAKE:
                peer_pub_bytes = result[1]
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
                peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
                shared = priv.exchange(peer_pub)
                # Обновляем сессионный ключ
                import hashlib
                self.session_key = hashlib.sha256(shared + self.session_key).digest()
                log.info("ECDH handshake OK")
        except ImportError:
            pass  # cryptography не установлен — используем session_key

    # ── Приём сообщений ────────────────────────────────────────────

    def _recv_loop(self, sock: socket.socket):
        """Цикл приёма пакетов."""
        while self._connected:
            result = recv_packet(sock)
            if result is None:
                self._on_disconnect("Соединение разорвано")
                break

            pkt_type, payload = result
            try:
                self._handle_packet(pkt_type, payload)
            except Exception as e:
                log.error(f"Ошибка обработки пакета: {e}")

    def _handle_packet(self, pkt_type: int, payload: bytes):
        """Обработка входящего пакета."""
        # Дешифруем
        try:
            from core.crypto_stb import decrypt_hybrid
            data = decrypt_hybrid(payload, self.session_key)
        except Exception:
            data = payload  # fallback: нешифрованные данные

        if pkt_type == PKT_MESSAGE:
            try:
                msg = json.loads(data)
                if self.on_message:
                    self.on_message(msg)
            except Exception:
                if self.on_message:
                    self.on_message({"text": data.decode("utf-8", errors="replace"),
                                     "timestamp": time.time()})

        elif pkt_type == PKT_PING:
            self.send_packet(PKT_PONG, b"pong")

        elif pkt_type == PKT_TYPING:
            if self.on_typing:
                self.on_typing()

        elif pkt_type == PKT_DESTRUCT:
            log.critical("ПОЛУЧЕНА КОМАНДА САМОУНИЧТОЖЕНИЯ 0xFF!")
            # Вызываем экстренное уничтожение
            self._trigger_destruct()

        elif pkt_type == PKT_FILE_META:
            try:
                meta = json.loads(data)
                self._recv_file(meta)
            except Exception as e:
                log.error(f"File meta error: {e}")

        elif pkt_type == PKT_STATUS:
            log.info(f"Status: {data}")

    def _on_disconnect(self, reason: str):
        """Обработка разрыва соединения."""
        with self._lock:
            self._connected = False
            self._sock = None
        if self.on_disconnect:
            self.on_disconnect(reason)

    # ── Отправка ──────────────────────────────────────────────────

    def send_packet(self, pkt_type: int, payload: bytes):
        """Отправка сырого пакета."""
        with self._lock:
            if not self._sock or not self._connected:
                raise ConnectionError("Нет активного соединения")
            try:
                self._sock.sendall(pack(pkt_type, payload))
            except Exception as e:
                self._on_disconnect(str(e))
                raise

    def _encrypt(self, data: bytes) -> bytes:
        """Шифрование данных Belt-128 (СТБ 34.101.31-2020)."""
        try:
            from core.crypto_stb import encrypt_hybrid
            return encrypt_hybrid(data, self.session_key, use_stb=True)
        except Exception:
            return data  # fallback без шифрования

    def send_message(self, text: str):
        """Отправка текстового сообщения."""
        msg = json.dumps({
            "text":      text,
            "timestamp": time.time(),
            "algo":      "Belt-128"
        }, ensure_ascii=False).encode()
        self.send_packet(PKT_MESSAGE, self._encrypt(msg))

    def send_typing(self):
        """Индикатор печати."""
        try:
            self.send_packet(PKT_TYPING, b"")
        except Exception:
            pass

    def send_ping(self):
        """Ping."""
        self.send_packet(PKT_PING, b"ping")

    def send_file(self, filepath: str):
        """
        Отправка файла партнёру.
        Файл шифруется Belt-128 и передаётся чанками.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Файл не найден: {filepath}")

        size = path.stat().st_size
        meta = json.dumps({
            "name":      path.name,
            "size":      size,
            "algo":      "Belt-128",
            "timestamp": time.time()
        }, ensure_ascii=False).encode()

        # Отправляем метаданные
        self.send_packet(PKT_FILE_META, self._encrypt(meta))

        # Читаем и отправляем чанки
        sent = 0
        with open(filepath, "rb") as f:
            chunk_num = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                header = struct.pack(">II", chunk_num, size)
                payload = header + self._encrypt(chunk)
                self.send_packet(PKT_FILE_CHUNK, payload)
                sent += len(chunk)
                chunk_num += 1
                log.info(f"Отправлено {sent}/{size} байт")

    def _recv_file(self, meta: dict):
        """Приём файла от партнёра."""
        filename = meta.get("name", "received_file")
        expected_size = meta.get("size", 0)
        save_path = self.data_dir / "received" / filename
        save_path.parent.mkdir(parents=True, exist_ok=True)

        chunks = {}
        total = 0

        while total < expected_size:
            result = recv_packet(self._sock)
            if not result:
                break
            pkt_type, payload = result
            if pkt_type != PKT_FILE_CHUNK:
                break

            chunk_num = struct.unpack(">I", payload[:4])[0]
            chunk_data_enc = payload[8:]

            try:
                from core.crypto_stb import decrypt_hybrid
                chunk_data = decrypt_hybrid(chunk_data_enc, self.session_key)
            except Exception:
                chunk_data = chunk_data_enc

            chunks[chunk_num] = chunk_data
            total += len(chunk_data)

        # Собираем файл
        with open(save_path, "wb") as f:
            for i in sorted(chunks.keys()):
                f.write(chunks[i])

        if self.on_file:
            self.on_file(filename, save_path)

        log.info(f"Файл получен: {filename} ({total} байт)")

    def _trigger_destruct(self):
        """Самоуничтожение при получении 0xFF."""
        log.critical("Активация самоуничтожения по команде партнёра!")
        try:
            from core.crypto_stb import secure_wipe
            import sys
            root = Path(__file__).parent.parent
            for d in [root / "keys", root / "data"]:
                if d.exists():
                    for f in d.rglob("*"):
                        if f.is_file():
                            try: secure_wipe(f)
                            except: f.unlink(missing_ok=True)
        except Exception as e:
            log.error(f"Destruct error: {e}")

    # ── Свойства ─────────────────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def peer(self) -> str:
        return self._peer_addr or ""

    def disconnect(self):
        """Закрытие соединения."""
        with self._lock:
            self._connected = False
            if self._sock:
                try: self._sock.close()
                except Exception: pass
                self._sock = None

    def __del__(self):
        self.disconnect()
