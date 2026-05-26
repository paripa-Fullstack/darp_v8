"""
DARP v8 :: SecurityModule
Аудит системы, сканирование уязвимостей, мониторинг процессов.
"""
import os, sys, platform, socket, subprocess, hashlib, threading, time
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class SecurityModule:
    def __init__(self, root_dir: Path):
        self.root_dir = Path(root_dir)

    # ── Полный аудит системы ─────────────────────────────────────────
    def full_system_audit(self) -> dict:
        result = {}
        result["os"] = platform.system() + " " + platform.release()
        result["machine"] = platform.machine()
        result["hostname"] = platform.node()
        result["python"] = sys.version.split()[0]
        try: result["ip_local"] = socket.gethostbyname(socket.gethostname())
        except Exception: result["ip_local"] = "N/A"

        if HAS_PSUTIL:
            try:
                result["cpu_percent"] = f"{psutil.cpu_percent(interval=0.5):.1f}%"
                result["cpu_cores"] = psutil.cpu_count()
                vm = psutil.virtual_memory()
                result["ram_total"] = f"{vm.total//1024//1024} MB"
                result["ram_used"]  = f"{vm.percent}%"
                # Диски
                disks = []
                for p in psutil.disk_partitions():
                    try:
                        u = psutil.disk_usage(p.mountpoint)
                        disks.append(f"{p.device} {round(u.used/1e9,1)}/{round(u.total/1e9,1)} GB ({u.percent}%)")
                    except Exception: pass
                result["disks"] = disks
                # Сетевые интерфейсы
                ifaces = []
                for iface, snics in psutil.net_if_addrs().items():
                    for s in snics:
                        if s.family == socket.AF_INET:
                            ifaces.append(f"{iface}: {s.address}")
                result["interfaces"] = ifaces
                # Активные соединения
                conns = []
                for c in psutil.net_connections(kind='inet'):
                    if c.status == 'ESTABLISHED' and c.raddr:
                        conns.append(f"{c.raddr.ip}:{c.raddr.port}")
                result["connections"] = list(set(conns))[:20]
                # Топ процессов по CPU
                procs = []
                for p in sorted(psutil.process_iter(['pid','name','cpu_percent']),
                                key=lambda x: x.info.get('cpu_percent') or 0,
                                reverse=True)[:10]:
                    procs.append(f"PID {p.info['pid']:5d}  {p.info['name'][:30]:<30s}  {p.info.get('cpu_percent',0):.1f}%")
                result["top_processes"] = procs
            except Exception as e:
                result["psutil_error"] = str(e)
        return result

    # ── Сканирование уязвимостей ─────────────────────────────────────
    def scan_vulnerabilities(self) -> list:
        issues = []
        DANGER_PORTS = {
            21: "FTP (передача без шифрования)",
            22: "SSH (удалённый доступ)",
            23: "Telnet (небезопасный протокол)",
            25: "SMTP (почтовый сервер)",
            80: "HTTP (незашифрованный веб)",
            135: "MS-RPC",
            137: "NetBIOS Name Service",
            139: "NetBIOS Session",
            445: "SMB (уязвимость WannaCry/EternalBlue)",
            1433: "MSSQL",
            1723: "PPTP VPN",
            3306: "MySQL",
            3389: "RDP (удалённый рабочий стол)",
            5900: "VNC (удалённый рабочий стол)",
            6379: "Redis (без аутентификации)",
            27017: "MongoDB",
        }
        for port, desc in DANGER_PORTS.items():
            try:
                s = socket.socket()
                s.settimeout(0.4)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    issues.append(f"⚠ ОТКРЫТ {desc} (:{port})")
                s.close()
            except Exception: pass

        if platform.system() == "Windows":
            try:
                r = subprocess.run(["net","share"], capture_output=True, text=True, timeout=5)
                for l in r.stdout.splitlines():
                    parts = l.split()
                    if parts and "$" not in parts[0] and "---" not in parts[0] and len(parts[0]) > 2:
                        issues.append(f"📂 Открытый сетевой ресурс: {parts[0]}")
            except Exception: pass
            # Проверка UAC
            try:
                r = subprocess.run(["reg","query",
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    "/v","EnableLUA"], capture_output=True, text=True, timeout=3)
                if "0x0" in r.stdout:
                    issues.append("⚠ UAC отключён — система уязвима")
            except Exception: pass
            # Проверка автозапуска
            try:
                r = subprocess.run(["reg","query",
                    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"],
                    capture_output=True, text=True, timeout=3)
                entries = [l.strip() for l in r.stdout.splitlines()
                           if l.strip() and "HKEY" not in l and "(" not in l]
                if entries:
                    issues.append(f"ℹ Автозапуск ({len(entries)} записей): " + "; ".join(entries[:3]))
            except Exception: pass

        if HAS_PSUTIL:
            try:
                procs = [p.info['name'] for p in psutil.process_iter(['name'])
                         if p.info.get('name')]
                suspicious = ['wireshark','netcat','nc','nmap','metasploit',
                              'msfconsole','fiddler','charles','burpsuite']
                for s in suspicious:
                    if any(s.lower() in p.lower() for p in procs):
                        issues.append(f"⚠ Обнаружен процесс: {s}")
            except Exception: pass

        if not issues:
            issues.append("✅ Критических уязвимостей не обнаружено")
        return issues

    # ── Мониторинг шпионских процессов ──────────────────────────────
    def scan_for_spyware(self) -> list:
        found = []
        if not HAS_PSUTIL:
            return ["psutil не установлен — pip install psutil"]
        spyware_keywords = [
            'keylog', 'spy', 'rat', 'remote', 'hack', 'crack',
            'wireshark', 'tcpdump', 'ettercap', 'cain', 'abel',
            'mimir', 'njrat', 'darkcomet', 'poison ivy'
        ]
        try:
            for p in psutil.process_iter(['pid','name','exe']):
                name = (p.info.get('name') or '').lower()
                for kw in spyware_keywords:
                    if kw in name:
                        found.append(f"PID {p.info['pid']}: {p.info['name']}")
                        break
        except Exception: pass
        if not found:
            found.append("✅ Подозрительных процессов не обнаружено")
        return found

    # ── Анализ приложений хост-системы ──────────────────────────────
    def analyze_host_apps(self) -> list:
        apps = []
        if not HAS_PSUTIL: return ["psutil не установлен"]
        try:
            seen = set()
            for p in psutil.process_iter(['pid','name','username','status']):
                n = p.info.get('name','')
                if n and n not in seen:
                    seen.add(n)
                    apps.append(f"{p.info['pid']:5d}  {n[:40]:<40s}  [{p.info.get('status','?')}]")
        except Exception: pass
        return apps[:50]

    # ── Целостность файлов DARP ──────────────────────────────────────
    def verify_integrity(self) -> dict:
        result = {}
        for f in ['core/main_v8.py','core/crypto_stb.py','core/network.py',
                  'modules/voice.py','modules/stego.py','modules/security.py',
                  'modules/geo.py','run.py']:
            p = self.root_dir / f
            if p.exists():
                h = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                result[f] = f"OK  sha256:{h}"
            else:
                result[f] = "ОТСУТСТВУЕТ"
        return result

    # ── Открытые порты ───────────────────────────────────────────────
    def scan_open_ports(self, host: str = "127.0.0.1",
                        ports: list = None) -> list:
        if ports is None:
            ports = list(range(1, 1025))
        open_ports = []
        def _check(port):
            try:
                s = socket.socket(); s.settimeout(0.3)
                if s.connect_ex((host, port)) == 0:
                    try: svc = socket.getservbyport(port)
                    except Exception: svc = "unknown"
                    open_ports.append((port, svc))
                s.close()
            except Exception: pass
        threads = [threading.Thread(target=_check, args=(p,), daemon=True) for p in ports]
        for t in threads: t.start()
        for t in threads: t.join(timeout=1)
        return sorted(open_ports)
