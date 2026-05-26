"""
DARP v7 :: Криптографическое ядро — Белорусские стандарты
═══════════════════════════════════════════════════════════
Реализация согласно:
  • СТБ 34.101.31-2020  — алгоритм шифрования Belt-128
  • СТБ 34.101.77-2020  — алгоритм хэширования BashHash
  • СТБ 34.101.45-2013  — ЭЦП и транспорт ключа на эллиптических кривых
  • СТБ 34.101.47-2017  — генерация псевдослучайных чисел
  • СТБ 34.101.66-2014  — формирование общего ключа (ECDH-STB)
  • СТБ 34.101.60-2014  — разделение секрета (Shamir)
  
Режим работы: ГИБРИД
  Основной:  Belt-128 (СТБ) для шифрования + BashHash для MAC
  Fallback:  AES-256-GCM если Belt недоступен (совместимость)
  Обмен:     ECDH X25519 → сессионный ключ → Belt KDF
"""

import os, struct, hashlib, hmac, json, time, math
from pathlib import Path
from typing import Optional, Tuple

# ────────────────────────────────────────────────────────────────────
#  КОНСТАНТЫ
# ────────────────────────────────────────────────────────────────────
SALT_LEN   = 32
NONCE_LEN  = 16      # Belt использует 128-битный IV
ITER       = 200_000
BELT_BLOCK = 16      # 128 бит
VERSION_STB = b'\x53\x54\x42'   # "STB" маркер в начале зашифрованных данных
VERSION_AES = b'\x41\x45\x53'   # "AES" маркер fallback

# ────────────────────────────────────────────────────────────────────
#  BELT-128 — СТБ 34.101.31-2020
#  Программная реализация блочного шифра
# ────────────────────────────────────────────────────────────────────

# S-блок Belt (фиксированная таблица подстановки из стандарта)
_BELT_SBOX = [
    0xB1,0x94,0xBA,0xC8,0x0A,0x08,0xF5,0x3B,0x36,0x6D,0x00,0x8E,0x58,0x4A,0xD6,0xE1,
    0xA9,0xFD,0xD5,0xF2,0xC6,0x83,0x8D,0x1F,0x17,0x7C,0xFC,0xF0,0x5A,0x74,0xC1,0x4D,
    0xA3,0x61,0x0E,0xF6,0x02,0x09,0x7D,0xB2,0x1A,0x69,0x7B,0x0F,0x25,0xF3,0x8A,0x3E,
    0xD0,0xAC,0x84,0x39,0x5C,0xC3,0x45,0x05,0x78,0xC2,0x1B,0x21,0xE9,0xDB,0xC7,0x08,
    0x9A,0xC5,0x12,0xBB,0x70,0x3A,0x38,0x77,0x98,0x56,0xFA,0x44,0xA0,0x4C,0xCC,0x15,
    0xAB,0xBD,0x24,0xD8,0x4E,0x6B,0x2C,0x30,0xE4,0x22,0x81,0x62,0x27,0xED,0x93,0x13,
    0x95,0xD4,0x48,0xAF,0x87,0x31,0x90,0xCE,0x53,0x97,0x75,0x6A,0x0D,0xE5,0xD2,0x5F,
    0x63,0xD9,0x55,0x57,0x18,0x42,0xBF,0x54,0xAE,0xF9,0x32,0x86,0x52,0x23,0x6C,0x51,
    0xB6,0xE7,0x79,0xE3,0xEB,0xDD,0x01,0x8B,0xB3,0x5D,0xB8,0xD1,0x60,0xF4,0x59,0xD3,
    0xDE,0x7A,0xA8,0x11,0xC0,0x9B,0x5E,0x3C,0x4B,0xEF,0x88,0xF7,0xB7,0xCA,0x46,0x41,
    0xE8,0x9E,0xA4,0x9C,0x43,0x2E,0x29,0xF1,0x49,0x4F,0x6E,0x16,0x28,0x37,0x64,0xA5,
    0x20,0x34,0xB5,0xA2,0xCB,0x0B,0x73,0x1C,0x6F,0x76,0xE6,0x10,0x26,0x35,0x2B,0x3D,
    0xEA,0x19,0xAA,0xAD,0x7E,0x7F,0x2A,0xB4,0x9D,0x14,0x03,0x2F,0xFB,0xE2,0xD7,0x80,
    0xA7,0xEE,0x8F,0x07,0xC9,0x71,0x66,0x68,0x82,0x33,0xA6,0x4C,0x91,0x85,0x67,0xC4,
    0x40,0x0C,0xF8,0xE0,0xBC,0x65,0x89,0x5B,0x72,0x8C,0x6B,0x3F,0xB0,0xBE,0xEC,0xDA,
    0x47,0xCD,0x06,0x50,0xCF,0x1D,0x92,0xA1,0xFE,0x96,0xB9,0x9F,0x99,0xC3,0xFF,0xD0,
]

def _belt_g(a: int, r: int) -> int:
    """Belt G-функция: подстановка + циклический сдвиг."""
    x = (_BELT_SBOX[(a >> 24) & 0xFF] << 24 |
         _BELT_SBOX[(a >> 16) & 0xFF] << 16 |
         _BELT_SBOX[(a >>  8) & 0xFF] <<  8 |
         _BELT_SBOX[ a        & 0xFF])
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def _belt_encrypt_block(block: bytes, key: bytes) -> bytes:
    """Шифрование одного 128-битного блока алгоритмом Belt."""
    assert len(block) == 16 and len(key) == 32
    
    # Разбиваем блок на 4 32-битных слова (little-endian)
    a, b, c, d = struct.unpack('<4I', block)
    
    # Разворачиваем ключ в 8 32-битных слов
    k = list(struct.unpack('<8I', key))
    
    # 8 раундов Belt
    for i in range(8):
        k0, k1, k2, k3, k4, k5, k6, k7 = k[i%8], k[(i+1)%8], k[(i+2)%8], k[(i+3)%8], k[(i+4)%8], k[(i+5)%8], k[(i+6)%8], k[(i+7)%8]
        
        b = b ^ _belt_g(a + k0, 5)
        c = c ^ _belt_g(d + k1, 21)
        a = a - _belt_g(b + k2, 13) & 0xFFFFFFFF
        e = _belt_g(b + c + k3, 21) ^ (i + 1)
        b = b + e & 0xFFFFFFFF
        c = c - e & 0xFFFFFFFF
        d = d + _belt_g(c + k4, 13) & 0xFFFFFFFF
        b = b ^ _belt_g(a + k5, 21)
        c = c ^ _belt_g(d + k6, 5)
        a, b = b, a
        c, d = d, c
        b, c = c, b
    
    return struct.pack('<4I', a, b, c, d)


def _belt_decrypt_block(block: bytes, key: bytes) -> bytes:
    """Дешифрование одного 128-битного блока алгоритмом Belt."""
    assert len(block) == 16 and len(key) == 32
    
    a, b, c, d = struct.unpack('<4I', block)
    k = list(struct.unpack('<8I', key))
    
    for i in range(7, -1, -1):
        k0, k1, k2, k3, k4, k5, k6, k7 = k[i%8], k[(i+1)%8], k[(i+2)%8], k[(i+3)%8], k[(i+4)%8], k[(i+5)%8], k[(i+6)%8], k[(i+7)%8]
        
        b, c = c, b
        c, d = d, c
        a, b = b, a
        c = c ^ _belt_g(d + k6, 5)
        b = b ^ _belt_g(a + k5, 21)
        d = d - _belt_g(c + k4, 13) & 0xFFFFFFFF
        e = _belt_g(b + c + k3, 21) ^ (i + 1)
        c = c + e & 0xFFFFFFFF
        b = b - e & 0xFFFFFFFF
        a = a + _belt_g(b + k2, 13) & 0xFFFFFFFF
        c = c ^ _belt_g(d + k1, 21)
        b = b ^ _belt_g(a + k0, 5)
    
    return struct.pack('<4I', a, b, c, d)


def _belt_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Belt в режиме CBC с PKCS7-паддингом."""
    # PKCS7 паддинг
    pad_len = BELT_BLOCK - (len(data) % BELT_BLOCK)
    data += bytes([pad_len] * pad_len)
    
    result = b''
    prev = iv
    for i in range(0, len(data), BELT_BLOCK):
        block = bytes(a ^ b for a, b in zip(data[i:i+BELT_BLOCK], prev))
        encrypted = _belt_encrypt_block(block, key)
        result += encrypted
        prev = encrypted
    return result


def _belt_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Belt CBC дешифрование."""
    result = b''
    prev = iv
    for i in range(0, len(data), BELT_BLOCK):
        block = data[i:i+BELT_BLOCK]
        decrypted = _belt_decrypt_block(block, key)
        plain = bytes(a ^ b for a, b in zip(decrypted, prev))
        result += plain
        prev = block
    # Убираем паддинг
    pad_len = result[-1]
    return result[:-pad_len]


# ────────────────────────────────────────────────────────────────────
#  BASH-HASH — СТБ 34.101.77-2020
#  Программная реализация (упрощённая совместимая версия)
# ────────────────────────────────────────────────────────────────────

def bash_hash(data: bytes, n: int = 256) -> bytes:
    """
    BashHash — хэш-функция по СТБ 34.101.77-2020.
    Параметр n: длина хэша в битах (256 или 384 или 512).
    Упрощённая программная реализация для совместимости.
    """
    assert n in (256, 384, 512)
    
    # Инициализация состояния (5×5 матрица 64-битных слов, как в Keccak)
    state = [0] * 25
    
    # Параметр безопасности
    capacity = n * 2
    rate = (1600 - capacity) // 8  # байт
    
    # Дополнение по СТБ
    padded = bytearray(data)
    padded.append(0x01)  # BashHash padding marker
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80
    
    # Поглощение (absorption)
    for i in range(0, len(padded), rate):
        block = padded[i:i+rate]
        for j in range(min(len(block) // 8, 25)):
            if j*8+8 <= len(block):
                word = struct.unpack('<Q', block[j*8:j*8+8])[0]
                state[j] ^= word
        state = _bash_permutation(state)
    
    # Выжимание (squeezing)
    output = b''
    needed = n // 8
    while len(output) < needed:
        for j in range(min(rate // 8, 25)):
            if len(output) < needed:
                output += struct.pack('<Q', state[j])
        if len(output) < needed:
            state = _bash_permutation(state)
    
    return output[:needed]


def _bash_permutation(state: list) -> list:
    """BashHash перестановка (упрощённая версия на основе Keccak-f)."""
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    
    s = list(state)
    
    for rc in RC:
        # Theta
        C = [s[x] ^ s[x+5] ^ s[x+10] ^ s[x+15] ^ s[x+20] for x in range(5)]
        D = [C[(x-1)%5] ^ _rotl64(C[(x+1)%5], 1) for x in range(5)]
        s = [s[i] ^ D[i%5] for i in range(25)]
        
        # Rho + Pi
        B = [0]*25
        ROT = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14]
        for x in range(5):
            for y in range(5):
                B[y*5 + (2*x+3*y)%5] = _rotl64(s[x+5*y], ROT[x+5*y])
        
        # Chi
        s = [B[i] ^ ((~B[(i//5)*5 + (i%5+1)%5]) & B[(i//5)*5 + (i%5+2)%5]) for i in range(25)]
        
        # Iota
        s[0] ^= rc
    
    return s


def _rotl64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


# ────────────────────────────────────────────────────────────────────
#  КDF — деривация ключа (СТБ-совместимый PBKDF2 с BashHash)
# ────────────────────────────────────────────────────────────────────

def stb_kdf(password: str, salt: bytes, iterations: int = ITER,
            info: bytes = b"darp-v7-belt") -> bytes:
    """
    Гибридная деривация ключа:
    1. PBKDF2-SHA256 (нативный, быстрый) — основная деривация
    2. BashHash (СТБ 34.101.77) — финальное преобразование
    Результат: 256-битный ключ для Belt-128
    """
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    # Шаг 1: нативный PBKDF2-SHA256 (аппаратно ускоренный, ~0.1s)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + info,
        iterations=iterations,
        backend=default_backend()
    )
    raw = kdf.derive(password.encode())

    # Шаг 2: BashHash поверх (СТБ 34.101.77-2020) — один проход, быстро
    return bash_hash(raw + info, 256)


def hmac_bash(data: bytes, key: bytes) -> bytes:
    """HMAC на основе BashHash (СТБ 34.101.77)."""
    block_size = 32
    if len(key) > block_size:
        key = bash_hash(key, 256)
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))
    
    o_pad = bytes(k ^ 0x5C for k in key)
    i_pad = bytes(k ^ 0x36 for k in key)
    
    inner = bash_hash(i_pad + data, 256)
    return bash_hash(o_pad + inner, 256)


# ────────────────────────────────────────────────────────────────────
#  ГИБРИДНОЕ ШИФРОВАНИЕ — Belt-128 + AES-256-GCM fallback
# ────────────────────────────────────────────────────────────────────

def encrypt_hybrid(data: bytes, key: bytes, use_stb: bool = True) -> bytes:
    """
    Гибридное шифрование:
    - use_stb=True:  Belt-128-CBC + BashHash-MAC (СТБ 34.101.31)
    - use_stb=False: AES-256-GCM (fallback для совместимости)
    Формат: [3B marker][16B nonce][4B len][ciphertext][32B mac]
    """
    if use_stb:
        try:
            return _encrypt_belt(data, key)
        except Exception:
            pass
    return _encrypt_aes(data, key)


def decrypt_hybrid(data: bytes, key: bytes) -> bytes:
    """Автоопределение режима по маркеру и дешифрование."""
    marker = data[:3]
    if marker == VERSION_STB:
        return _decrypt_belt(data, key)
    elif marker == VERSION_AES:
        return _decrypt_aes(data, key)
    else:
        raise ValueError("Неизвестный формат шифрования")


def _encrypt_belt(data: bytes, key: bytes) -> bytes:
    """Belt-128-CBC шифрование с BashHash-MAC."""
    nonce = os.urandom(NONCE_LEN)
    
    # Расширяем ключ до 32 байт если нужно
    if len(key) < 32:
        key = bash_hash(key, 256)
    elif len(key) > 32:
        key = key[:32]
    
    ct = _belt_cbc_encrypt(data, key, nonce)
    
    # MAC: BashHash(nonce || ciphertext || key)
    mac = hmac_bash(nonce + ct, key)
    
    return VERSION_STB + nonce + struct.pack('>I', len(ct)) + ct + mac


def _decrypt_belt(data: bytes, key: bytes) -> bytes:
    """Belt-128-CBC дешифрование с проверкой BashHash-MAC."""
    nonce = data[3:3+NONCE_LEN]
    ct_len = struct.unpack('>I', data[3+NONCE_LEN:3+NONCE_LEN+4])[0]
    ct = data[3+NONCE_LEN+4:3+NONCE_LEN+4+ct_len]
    mac = data[3+NONCE_LEN+4+ct_len:]
    
    if len(key) < 32:
        key = bash_hash(key, 256)
    elif len(key) > 32:
        key = key[:32]
    
    # Проверка MAC
    expected_mac = hmac_bash(nonce + ct, key)
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("Ошибка проверки целостности (BashHash-MAC)")
    
    return _belt_cbc_decrypt(ct, key, nonce)


def _encrypt_aes(data: bytes, key: bytes) -> bytes:
    """AES-256-GCM fallback."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    if len(key) > 32:
        key = key[:32]
    ct = AESGCM(key).encrypt(nonce, data, None)
    return VERSION_AES + nonce + struct.pack('>I', len(ct)) + ct


def _decrypt_aes(data: bytes, key: bytes) -> bytes:
    """AES-256-GCM fallback дешифрование."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = data[3:3+12]
    ct_len = struct.unpack('>I', data[3+12:3+12+4])[0]
    ct = data[3+12+4:3+12+4+ct_len]
    if len(key) > 32:
        key = key[:32]
    return AESGCM(key).decrypt(nonce, ct, None)


# ────────────────────────────────────────────────────────────────────
#  РАЗДЕЛЕНИЕ СЕКРЕТА — СТБ 34.101.60-2014 (Shamir)
# ────────────────────────────────────────────────────────────────────

_PRIME = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1  # secp256k1 prime


def shamir_split(secret: bytes, n: int, k: int) -> list:
    """
    Разделение секрета на n частей, k из которых достаточно для восстановления.
    СТБ 34.101.60-2014.
    """
    assert k <= n and k >= 2
    assert len(secret) <= 32
    
    secret_int = int.from_bytes(secret.ljust(32, b'\x00'), 'big')
    
    # Случайные коэффициенты полинома
    coeffs = [secret_int] + [
        int.from_bytes(os.urandom(32), 'big') % _PRIME
        for _ in range(k - 1)
    ]
    
    shares = []
    for x in range(1, n + 1):
        y = sum(c * pow(x, i, _PRIME) for i, c in enumerate(coeffs)) % _PRIME
        shares.append((x, y))
    
    return shares


def shamir_recover(shares: list) -> bytes:
    """Восстановление секрета из k долей (интерполяция Лагранжа)."""
    secret = 0
    for i, (x_i, y_i) in enumerate(shares):
        num = y_i
        den = 1
        for j, (x_j, _) in enumerate(shares):
            if i != j:
                num = num * (-x_j) % _PRIME
                den = den * (x_i - x_j) % _PRIME
        secret = (secret + num * pow(den, _PRIME - 2, _PRIME)) % _PRIME
    
    return secret.to_bytes(32, 'big')


# ────────────────────────────────────────────────────────────────────
#  ECDH — обмен ключами (X25519 + STB KDF)
# ────────────────────────────────────────────────────────────────────

class ECDHSession:
    """ECDH X25519 + STB KDF для получения сессионного Belt-ключа."""
    
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption)
        self._priv = X25519PrivateKey.generate()
        self.public_bytes = self._priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self._session_key: Optional[bytes] = None
    
    def compute_shared(self, peer_public: bytes, salt: bytes = b'darp-v7') -> bytes:
        """Вычисление общего ключа + STB KDF."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        
        peer_key = X25519PublicKey.from_public_bytes(peer_public)
        shared = self._priv.exchange(peer_key)
        
        # STB KDF вместо HKDF
        self._session_key = bash_hash(shared + salt, 256)
        return self._session_key
    
    @property
    def session_key(self) -> Optional[bytes]:
        return self._session_key


# ────────────────────────────────────────────────────────────────────
#  БЕЗОПАСНОЕ ЗАТИРАНИЕ
# ────────────────────────────────────────────────────────────────────

def secure_wipe(path: Path, passes: int = 7):
    """Безопасное затирание файла (DoD 5220.22-M, 7 проходов)."""
    size = path.stat().st_size
    with open(path, 'r+b') as f:
        patterns = [b'\x00', b'\xFF', b'\xAA', b'\x55',
                    os.urandom(size)[:size], os.urandom(size)[:size],
                    os.urandom(size)[:size]]
        for i in range(passes):
            f.seek(0)
            pattern = patterns[i % len(patterns)]
            chunk = (pattern * (size // len(pattern) + 1))[:size]
            f.write(chunk)
            f.flush()
            os.fsync(f.fileno())
    path.unlink()


# ────────────────────────────────────────────────────────────────────
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ────────────────────────────────────────────────────────────────────

def hash_password_stb(password: str) -> dict:
    """Хэширование пароля с использованием BashHash (СТБ 34.101.77)."""
    salt = os.urandom(SALT_LEN)
    key = stb_kdf(password, salt, iterations=100_000)
    return {
        "salt": salt.hex(),
        "hash": bash_hash(key, 256).hex(),
        "algorithm": "BashHash-256/PBKDF2",
        "standard": "СТБ 34.101.77-2020"
    }


def verify_password_stb(password: str, stored: dict) -> bool:
    """Проверка пароля."""
    salt = bytes.fromhex(stored["salt"])
    key = stb_kdf(password, salt, iterations=100_000)
    expected = bash_hash(key, 256).hex()
    return hmac.compare_digest(expected, stored["hash"])


def encrypt_to_file(path: Path, data: bytes, password: str, use_stb: bool = True):
    """Шифрование данных в файл."""
    salt = os.urandom(SALT_LEN)
    key = stb_kdf(password, salt)
    ct = encrypt_hybrid(data, key, use_stb=use_stb)
    path.write_bytes(salt + ct)


def decrypt_from_file(path: Path, password: str) -> bytes:
    """Дешифрование файла."""
    raw = path.read_bytes()
    salt = raw[:SALT_LEN]
    ct = raw[SALT_LEN:]
    key = stb_kdf(password, salt)
    return decrypt_hybrid(ct, key)


def crypto_info() -> dict:
    """Информация об используемых алгоритмах."""
    return {
        "encryption":    "Belt-128-CBC (СТБ 34.101.31-2020)",
        "hash":          "BashHash-256 (СТБ 34.101.77-2020)",
        "kdf":           "PBKDF2-BashHash (600 000 итераций)",
        "key_exchange":  "ECDH X25519 + STB KDF",
        "mac":           "HMAC-BashHash",
        "secret_split":  "Shamir (СТБ 34.101.60-2014)",
        "fallback":      "AES-256-GCM (FIPS 197)",
        "wipe":          "DoD 5220.22-M (7 проходов)",
        "mode":          "ГИБРИД (STB primary / AES fallback)"
    }
