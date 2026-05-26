"""
DARP v8 :: Голосовые сообщения
Бэкенды: sounddevice -> pyaudio -> winsound -> simulated
"""
import os, wave, struct, zlib, threading, time, json, io, math, random
from pathlib import Path

HAS_SD = False
HAS_PA = False
try:
    import sounddevice as sd
    import numpy as np
    HAS_SD = True
except Exception:
    pass

if not HAS_SD:
    try:
        import pyaudio
        HAS_PA = True
    except Exception:
        pass

HAS_AUDIO = HAS_SD or HAS_PA

from core.crypto_stb import encrypt_hybrid, decrypt_hybrid, bash_hash

SAMPLE_RATE  = 16000
CHANNELS     = 1
SAMPLE_WIDTH = 2
CHUNK        = 1024
MAX_DURATION = 120
VOICE_MAGIC  = b'DARPv8VOICE'


class VoiceRecorder:
    def __init__(self, data_dir, session_key: bytes):
        self.data_dir    = Path(data_dir) / "voice"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.session_key = session_key
        self._recording   = False
        self._frames      = []
        self._record_thread = None
        self._start_time = 0.0
        self.on_recorded  = None
        self.on_level     = None

    def start_recording(self) -> bool:
        if self._recording:
            return False
        self._frames = []
        self._recording = True
        self._start_time = time.time()
        if HAS_SD:
            self._record_thread = threading.Thread(target=self._record_sd, daemon=True)
        elif HAS_PA:
            self._record_thread = threading.Thread(target=self._record_pa, daemon=True)
        else:
            self._recording = False
            return False
        self._record_thread.start()
        return True

    def _record_sd(self):
        try:
            with sd.InputStream(samplerate=SAMPLE_RATE, channels=CHANNELS,
                                dtype='int16', blocksize=CHUNK) as stream:
                while self._recording:
                    data, _ = stream.read(CHUNK)
                    self._frames.append(data.tobytes())
                    if self.on_level:
                        rms = float(np.sqrt(np.mean(data.astype('float32')**2)))
                        self.on_level(min(1.0, rms / 10000.0))
        except Exception:
            self._recording = False

    def _record_pa(self):
        import pyaudio
        pa = pyaudio.PyAudio()
        try:
            stream = pa.open(format=pyaudio.paInt16, channels=CHANNELS,
                             rate=SAMPLE_RATE, input=True, frames_per_buffer=CHUNK)
            while self._recording:
                data = stream.read(CHUNK, exception_on_overflow=False)
                self._frames.append(data)
                if self.on_level:
                    samples = struct.unpack(f'<{len(data)//2}h', data)
                    rms = math.sqrt(sum(s*s for s in samples)/len(samples)) if samples else 0
                    self.on_level(min(1.0, rms/10000.0))
            stream.stop_stream(); stream.close()
        except Exception:
            self._recording = False
        finally:
            pa.terminate()

    def stop_recording(self):
        self._recording = False
        if self._record_thread:
            self._record_thread.join(timeout=3)
            self._record_thread = None
        if not self._frames:
            return None
        raw_pcm = b''.join(self._frames)
        duration = len(raw_pcm) / (SAMPLE_RATE * CHANNELS * SAMPLE_WIDTH)
        wav_buf = io.BytesIO()
        with wave.open(wav_buf, 'wb') as wf:
            wf.setnchannels(CHANNELS); wf.setsampwidth(SAMPLE_WIDTH)
            wf.setframerate(SAMPLE_RATE); wf.writeframes(raw_pcm)
        return self._save(wav_buf.getvalue(), duration)

    def play_voice_message(self, fname: str) -> bool:
        fpath = self.data_dir / fname
        if not fpath.exists():
            return False
        try:
            payload = decrypt_hybrid(fpath.read_bytes(), self.session_key)
            if not payload.startswith(VOICE_MAGIC):
                return False
            ml = struct.unpack('>I', payload[len(VOICE_MAGIC):len(VOICE_MAGIC)+4])[0]
            wav_data = zlib.decompress(payload[len(VOICE_MAGIC)+4+ml:])
            threading.Thread(target=self._play_wav, args=(wav_data,), daemon=True).start()
            return True
        except Exception:
            return False

    def _play_wav(self, wav_data: bytes):
        wav_buf = io.BytesIO(wav_data)
        try:
            if HAS_SD:
                with wave.open(wav_buf, 'rb') as wf:
                    frames = wf.readframes(wf.getnframes())
                arr = np.frombuffer(frames, dtype=np.int16)
                sd.play(arr, samplerate=SAMPLE_RATE, blocking=True)
            elif HAS_PA:
                import pyaudio
                pa = pyaudio.PyAudio()
                with wave.open(wav_buf, 'rb') as wf:
                    stream = pa.open(format=pa.get_format_from_width(wf.getsampwidth()),
                                     channels=wf.getnchannels(), rate=wf.getframerate(), output=True)
                    data = wf.readframes(CHUNK)
                    while data:
                        stream.write(data); data = wf.readframes(CHUNK)
                    stream.stop_stream(); stream.close()
                pa.terminate()
            else:
                import platform
                if platform.system() == "Windows":
                    import winsound, tempfile
                    with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as f:
                        f.write(wav_data); tmp = f.name
                    try: winsound.PlaySound(tmp, winsound.SND_FILENAME)
                    finally: os.unlink(tmp)
        except Exception:
            pass

    def create_test_voice(self, text: str = "DARP v8") -> dict:
        duration = 2.0; samples = int(SAMPLE_RATE * duration)
        raw_pcm = b''
        for i in range(samples):
            t = i / SAMPLE_RATE
            amp = int(3000 * math.sin(2 * math.pi * 440 * t) * (1 + 0.2*random.random()))
            raw_pcm += struct.pack('<h', max(-32768, min(32767, amp)))
        wav_buf = io.BytesIO()
        with wave.open(wav_buf, 'wb') as wf:
            wf.setnchannels(CHANNELS); wf.setsampwidth(SAMPLE_WIDTH)
            wf.setframerate(SAMPLE_RATE); wf.writeframes(raw_pcm)
        return self._save(wav_buf.getvalue(), duration)

    def _save(self, wav_data: bytes, duration: float) -> dict:
        compressed = zlib.compress(wav_data, level=9)
        meta = {"duration": round(duration, 2), "sample_rate": SAMPLE_RATE,
                "channels": CHANNELS, "original_size": len(wav_data),
                "compressed_size": len(compressed), "timestamp": time.time(),
                "algorithm": "Belt-128/CBC (СТБ 34.101.31-2020)"}
        meta_bytes = json.dumps(meta, ensure_ascii=False).encode()
        payload = VOICE_MAGIC + struct.pack('>I', len(meta_bytes)) + meta_bytes + compressed
        encrypted = encrypt_hybrid(payload, self.session_key, use_stb=True)
        fname = f"voice_{int(time.time()*1000)}.enc"
        (self.data_dir / fname).write_bytes(encrypted)
        return {"type":"voice","file":fname,"duration":meta["duration"],
                "size":len(encrypted),"timestamp":meta["timestamp"],
                "hash":bash_hash(encrypted,256).hex()[:16]}

    def get_voice_list(self) -> list:
        msgs = []
        for f in sorted(self.data_dir.glob("*.enc")):
            try:
                payload = decrypt_hybrid(f.read_bytes(), self.session_key)
                if not payload.startswith(VOICE_MAGIC): continue
                ml = struct.unpack('>I', payload[len(VOICE_MAGIC):len(VOICE_MAGIC)+4])[0]
                meta = json.loads(payload[len(VOICE_MAGIC)+4:len(VOICE_MAGIC)+4+ml])
                msgs.append({"file":f.name,"duration":meta.get("duration",0),
                             "timestamp":meta.get("timestamp",0),"size":f.stat().st_size})
            except Exception: pass
        return msgs

    def delete_voice(self, fname: str) -> bool:
        fpath = self.data_dir / fname
        if fpath.exists(): fpath.unlink(); return True
        return False

    @staticmethod
    def is_available() -> bool: return HAS_AUDIO

    @staticmethod
    def audio_backend() -> str:
        if HAS_SD: return "sounddevice"
        if HAS_PA: return "pyaudio"
        return "winsound/simulated"

    @staticmethod
    def format_duration(seconds: float) -> str:
        s = int(seconds); m = s // 60; s = s % 60
        return f"{m}:{s:02d}"
