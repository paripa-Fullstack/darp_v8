"""
DARP v7 :: Стеганография
══════════════════════════
Скрытие зашифрованных данных в медиафайлах.
Методы:
  PNG  — LSB (Least Significant Bit) в каналах RGB
  WAV  — LSB в сэмплах аудио (16-bit PCM)
  TXT  — Unicode Zero-Width символы (невидимый текст)

Шифрование: Belt-128 (СТБ 34.101.31-2020) перед встраиванием.
Детектор:   автоматическое определение наличия скрытых данных.
"""

import os, struct, zlib, json
from pathlib import Path
from core.crypto_stb import encrypt_hybrid, decrypt_hybrid, bash_hash

# Магический заголовок стеганографического контейнера
STEGO_MAGIC   = b'DARP\x07\x73\x74\x67'   # "DARPstg"
STEGO_VERSION = b'\x07'


# ════════════════════════════════════════════════════════════════════
#  PNG — LSB стеганография
# ════════════════════════════════════════════════════════════════════

class PNGSteganography:
    """Скрытие данных в PNG-изображении через LSB в RGB-каналах."""
    
    @staticmethod
    def embed(carrier_path: Path, secret_data: bytes, key: bytes,
              output_path: Path) -> bool:
        """
        Встраивание секретных данных в PNG.
        carrier_path  — исходное изображение-носитель
        secret_data   — данные для скрытия
        key           — ключ шифрования (Belt-128)
        output_path   — выходной файл с скрытыми данными
        """
        try:
            from PIL import Image
        except ImportError:
            return False
        
        # Шифруем данные перед встраиванием
        encrypted = encrypt_hybrid(secret_data, key, use_stb=True)
        
        # Пакет: [MAGIC][VERSION][4B len][data][16B hash]
        data_hash = bash_hash(encrypted, 256)[:16]
        payload = (STEGO_MAGIC + STEGO_VERSION +
                   struct.pack('>I', len(encrypted)) +
                   encrypted + data_hash)
        compressed = zlib.compress(payload, level=9)
        
        img = Image.open(carrier_path).convert('RGB')
        pixels = list(img.getdata())
        
        # Проверка вместимости (3 бита на пиксель в RGB)
        capacity_bits = len(pixels) * 3
        required_bits = len(compressed) * 8
        
        if required_bits > capacity_bits:
            raise ValueError(
                f"Носитель слишком мал: нужно {required_bits} бит, "
                f"доступно {capacity_bits} бит"
            )
        
        # Встраиваем побитно в LSB каналов R, G, B
        bit_stream = []
        for byte in compressed:
            for bit_pos in range(7, -1, -1):
                bit_stream.append((byte >> bit_pos) & 1)
        
        new_pixels = []
        bit_idx = 0
        
        for i, (r, g, b) in enumerate(pixels):
            if bit_idx < len(bit_stream):
                r = (r & 0xFE) | bit_stream[bit_idx]; bit_idx += 1
            if bit_idx < len(bit_stream):
                g = (g & 0xFE) | bit_stream[bit_idx]; bit_idx += 1
            if bit_idx < len(bit_stream):
                b = (b & 0xFE) | bit_stream[bit_idx]; bit_idx += 1
            new_pixels.append((r, g, b))
        
        out_img = Image.new('RGB', img.size)
        out_img.putdata(new_pixels)
        out_img.save(output_path, 'PNG', compress_level=0)
        return True
    
    @staticmethod
    def extract(stego_path: Path, key: bytes) -> bytes | None:
        """Извлечение и дешифрование скрытых данных из PNG."""
        try:
            from PIL import Image
        except ImportError:
            return None
        
        try:
            img = Image.open(stego_path).convert('RGB')
            pixels = list(img.getdata())
            
            # Извлекаем биты из LSB
            bits = []
            for r, g, b in pixels:
                bits.append(r & 1)
                bits.append(g & 1)
                bits.append(b & 1)
            
            # Собираем байты
            raw = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i+j]
                raw.append(byte)
            
            # Декомпрессия
            try:
                payload = zlib.decompress(bytes(raw))
            except Exception:
                return None
            
            # Проверяем магик
            if not payload.startswith(STEGO_MAGIC):
                return None
            
            offset = len(STEGO_MAGIC) + len(STEGO_VERSION)
            data_len = struct.unpack('>I', payload[offset:offset+4])[0]
            encrypted = payload[offset+4:offset+4+data_len]
            stored_hash = payload[offset+4+data_len:]
            
            # Проверяем хэш (BashHash)
            if bash_hash(encrypted, 256)[:16] != stored_hash:
                return None
            
            return decrypt_hybrid(encrypted, key)
            
        except Exception:
            return None
    
    @staticmethod
    def detect(image_path: Path) -> dict:
        """Детектирование стеганографии в PNG (статистический анализ LSB)."""
        try:
            from PIL import Image
        except ImportError:
            return {"error": "PIL недоступен"}
        
        try:
            img = Image.open(image_path).convert('RGB')
            pixels = list(img.getdata())
            
            # Считаем распределение LSB
            lsb_counts = [0, 0]
            for r, g, b in pixels:
                lsb_counts[r & 1] += 1
                lsb_counts[g & 1] += 1
                lsb_counts[b & 1] += 1
            
            total = sum(lsb_counts)
            ratio = lsb_counts[1] / total if total > 0 else 0
            
            # Если отношение близко к 0.5 — вероятно, скрытые данные
            suspicious = abs(ratio - 0.5) < 0.02
            
            return {
                "suspicious": suspicious,
                "lsb_ratio": round(ratio, 4),
                "confidence": round(1 - abs(ratio - 0.5) * 4, 2),
                "pixels": len(pixels),
                "capacity_bytes": len(pixels) * 3 // 8
            }
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def capacity(image_path: Path) -> int:
        """Максимальный объём данных для встраивания (байт)."""
        try:
            from PIL import Image
            img = Image.open(image_path)
            w, h = img.size
            return (w * h * 3) // 8
        except Exception:
            return 0


# ════════════════════════════════════════════════════════════════════
#  WAV — LSB стеганография в аудио
# ════════════════════════════════════════════════════════════════════

class WAVSteganography:
    """Скрытие данных в WAV-файле через LSB в 16-bit PCM сэмплах."""
    
    @staticmethod
    def embed(carrier_path: Path, secret_data: bytes, key: bytes,
              output_path: Path) -> bool:
        """Встраивание в WAV."""
        import wave
        
        encrypted = encrypt_hybrid(secret_data, key, use_stb=True)
        data_hash = bash_hash(encrypted, 256)[:16]
        payload = (STEGO_MAGIC + STEGO_VERSION +
                   struct.pack('>I', len(encrypted)) + encrypted + data_hash)
        compressed = zlib.compress(payload, level=9)
        
        try:
            with wave.open(str(carrier_path), 'rb') as wf:
                n_channels = wf.getnchannels()
                sampwidth  = wf.getsampwidth()
                framerate  = wf.getframerate()
                frames     = wf.readframes(wf.getnframes())
            
            if sampwidth != 2:
                raise ValueError("Поддерживается только 16-bit WAV")
            
            samples = list(struct.unpack(f'<{len(frames)//2}h', frames))
            
            if len(compressed) * 8 > len(samples):
                raise ValueError("Аудиофайл слишком короткий")
            
            # Встраиваем
            bit_stream = []
            for byte in compressed:
                for bit_pos in range(7, -1, -1):
                    bit_stream.append((byte >> bit_pos) & 1)
            
            for i, bit in enumerate(bit_stream):
                samples[i] = (samples[i] & ~1) | bit
            
            new_frames = struct.pack(f'<{len(samples)}h', *samples)
            
            with wave.open(str(output_path), 'wb') as wf:
                wf.setnchannels(n_channels)
                wf.setsampwidth(sampwidth)
                wf.setframerate(framerate)
                wf.writeframes(new_frames)
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def extract(stego_path: Path, key: bytes) -> bytes | None:
        """Извлечение из WAV."""
        import wave
        try:
            with wave.open(str(stego_path), 'rb') as wf:
                frames = wf.readframes(wf.getnframes())
            
            samples = struct.unpack(f'<{len(frames)//2}h', frames)
            
            bits = [s & 1 for s in samples]
            raw = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i+j]
                raw.append(byte)
            
            try:
                payload = zlib.decompress(bytes(raw))
            except Exception:
                return None
            
            if not payload.startswith(STEGO_MAGIC):
                return None
            
            offset = len(STEGO_MAGIC) + len(STEGO_VERSION)
            data_len = struct.unpack('>I', payload[offset:offset+4])[0]
            encrypted = payload[offset+4:offset+4+data_len]
            
            return decrypt_hybrid(encrypted, key)
        except Exception:
            return None


# ════════════════════════════════════════════════════════════════════
#  TXT — Zero-Width символы (Unicode стеганография)
# ════════════════════════════════════════════════════════════════════

class TextSteganography:
    """
    Скрытие данных в обычном тексте через невидимые Unicode символы.
    ZWS  (U+200B) = 0
    ZWNJ (U+200C) = 1
    Данные кодируются после первого слова текста.
    """
    
    ZWS  = '\u200B'   # Zero Width Space = бит 0
    ZWNJ = '\u200C'   # Zero Width Non-Joiner = бит 1
    SEP  = '\u200D'   # Zero Width Joiner = разделитель
    
    @classmethod
    def embed(cls, cover_text: str, secret_data: bytes, key: bytes) -> str:
        """Встраивание секрета в обычный текст."""
        encrypted = encrypt_hybrid(secret_data, key, use_stb=True)
        compressed = zlib.compress(
            STEGO_MAGIC + struct.pack('>I', len(encrypted)) + encrypted, 9)
        
        # Кодируем в Zero-Width символы
        hidden = cls.SEP
        for byte in compressed:
            for bit_pos in range(7, -1, -1):
                hidden += cls.ZWNJ if (byte >> bit_pos) & 1 else cls.ZWS
        hidden += cls.SEP
        
        # Вставляем после первого пробела
        parts = cover_text.split(' ', 1)
        if len(parts) >= 2:
            return parts[0] + hidden + ' ' + parts[1]
        return cover_text + hidden
    
    @classmethod
    def extract(cls, stego_text: str, key: bytes) -> bytes | None:
        """Извлечение из текста со скрытыми символами."""
        try:
            # Находим данные между разделителями
            start = stego_text.find(cls.SEP)
            end   = stego_text.find(cls.SEP, start + 1)
            if start == -1 or end == -1:
                return None
            
            hidden = stego_text[start+1:end]
            
            # Декодируем биты
            bits = []
            for ch in hidden:
                if ch == cls.ZWNJ:
                    bits.append(1)
                elif ch == cls.ZWS:
                    bits.append(0)
            
            raw = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i+j]
                raw.append(byte)
            
            payload = zlib.decompress(bytes(raw))
            if not payload.startswith(STEGO_MAGIC):
                return None
            
            data_len = struct.unpack('>I', payload[len(STEGO_MAGIC):len(STEGO_MAGIC)+4])[0]
            encrypted = payload[len(STEGO_MAGIC)+4:len(STEGO_MAGIC)+4+data_len]
            return decrypt_hybrid(encrypted, key)
        except Exception:
            return None
    
    @classmethod
    def has_hidden_data(cls, text: str) -> bool:
        """Проверяет, содержит ли текст скрытые данные."""
        return cls.SEP in text and any(
            c in text for c in [cls.ZWS, cls.ZWNJ])
    
    @classmethod
    def strip_hidden(cls, text: str) -> str:
        """Удаляет скрытые символы из текста."""
        return ''.join(
            c for c in text
            if c not in [cls.ZWS, cls.ZWNJ, cls.SEP])


# ════════════════════════════════════════════════════════════════════
#  МЕНЕДЖЕР СТЕГАНОГРАФИИ
# ════════════════════════════════════════════════════════════════════

class StegoManager:
    """Единый интерфейс для работы со стеганографией в DARP v7."""
    
    def __init__(self, data_dir: Path, session_key: bytes):
        self.data_dir    = data_dir / "stego"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.session_key = session_key
        self.log_file    = data_dir / "stego_log.enc"
        self._log        = []
    
    def embed_in_image(self, image_path: Path, message: str) -> Path | None:
        """Скрыть текстовое сообщение в изображении."""
        try:
            output = self.data_dir / f"stego_{image_path.stem}_{int(__import__('time').time())}.png"
            data = message.encode('utf-8')
            
            if PNGSteganography.embed(image_path, data, self.session_key, output):
                self._add_log("embed_png", str(image_path.name), len(data))
                return output
        except Exception:
            pass
        return None
    
    def extract_from_image(self, stego_path: Path) -> str | None:
        """Извлечь сообщение из изображения."""
        data = PNGSteganography.extract(stego_path, self.session_key)
        if data:
            self._add_log("extract_png", str(stego_path.name), len(data))
            try:
                return data.decode('utf-8')
            except Exception:
                return data.hex()
        return None
    
    def embed_in_audio(self, wav_path: Path, message: str) -> Path | None:
        """Скрыть сообщение в WAV-файле."""
        try:
            output = self.data_dir / f"stego_{wav_path.stem}_{int(__import__('time').time())}.wav"
            data = message.encode('utf-8')
            if WAVSteganography.embed(wav_path, data, self.session_key, output):
                self._add_log("embed_wav", str(wav_path.name), len(data))
                return output
        except Exception:
            pass
        return None
    
    def embed_in_text(self, cover_text: str, message: str) -> str:
        """Скрыть сообщение в тексте (Zero-Width)."""
        data = message.encode('utf-8')
        result = TextSteganography.embed(cover_text, data, self.session_key)
        self._add_log("embed_text", "zero-width", len(data))
        return result
    
    def extract_from_text(self, stego_text: str) -> str | None:
        """Извлечь сообщение из текста."""
        data = TextSteganography.extract(stego_text, self.session_key)
        if data:
            try:
                return data.decode('utf-8')
            except Exception:
                return data.hex()
        return None
    
    def analyze_file(self, file_path: Path) -> dict:
        """Анализ файла на наличие скрытых данных."""
        suffix = file_path.suffix.lower()
        result = {
            "file": file_path.name,
            "type": suffix,
            "has_stego": False
        }
        
        if suffix in ('.png', '.jpg', '.jpeg', '.bmp'):
            analysis = PNGSteganography.detect(file_path)
            result.update(analysis)
            result["has_stego"] = analysis.get("suspicious", False)
        
        return result
    
    def _add_log(self, action: str, target: str, size: int):
        """Логирование операций."""
        import time
        self._log.append({
            "action": action,
            "target": target,
            "size":   size,
            "ts":     time.time()
        })
    
    def get_log(self) -> list:
        return self._log.copy()
    
    @staticmethod
    def supported_formats() -> dict:
        return {
            "PNG": "LSB в RGB-каналах, до 3 бит/пиксель",
            "WAV": "LSB в 16-bit PCM сэмплах",
            "TXT": "Zero-Width Unicode символы (U+200B/U+200C)"
        }
