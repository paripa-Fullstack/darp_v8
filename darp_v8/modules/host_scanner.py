"""
DARP v8 :: HostScanner — полный аудит хост-системы при подключении флешки
Запускается автоматически при старте DARP и собирает информацию о хосте.
"""
import os, sys, socket, platform, subprocess, threading, time, hashlib
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class HostScanner:
    """
    Автоматический аудит при подключении флешки:
    - Базовые сведения об ОС
    - Аппаратная конфигурация
    - Запущенные процессы
    - Открытые порты
    - Сетевые соединения
    - Внешний IP и геолокация
    - Признаки мониторинга/кейлоггеров
    """

    def __init__(self):
        self._report = {}
        self._lock = threading.Lock()

    def run_full_scan(self, callback=None) -> dict:
        """Запускает полный скан в фоне. Callback(report) при завершении."""
        def _scan():
            report = {}
            report["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
            report["os"]        = self._os_info()
            report["hardware"]  = self._hardware_info()
            report["network"]   = self._network_info()
            report["processes"] = self._process_info()
            report["ports"]     = self._port_scan()
            report["security"]  = self._security_checks()
            with self._lock:
                self._report = report
            if callback:
                callback(report)
        t = threading.Thread(target=_scan, daemon=True)
        t.start()
        return {}

    def get_report(self) -> dict:
        with self._lock:
            return dict(self._report)

    # ── ОС ───────────────────────────────────────────────────────────
    def _os_info(self) -> dict:
        info = {
            "system":   platform.system(),
            "release":  platform.release(),
            "version":  platform.version()[:80],
            "machine":  platform.machine(),
            "hostname": platform.node(),
            "username": os.environ.get("USERNAME") or os.environ.get("USER","unknown"),
            "python":   sys.version.split()[0],
        }
        if platform.system() == "Windows":
            try:
                r = subprocess.run(["systeminfo"], capture_output=True,
                                   text=True, timeout=10)
                for line in r.stdout.splitlines():
                    if "OS Name" in line or "System Type" in line:
                        k, _, v = line.partition(":")
                        info[k.strip()] = v.strip()[:80]
            except Exception: pass
        return info

    # ── Железо ───────────────────────────────────────────────────────
    def _hardware_info(self) -> dict:
        info = {}
        if HAS_PSUTIL:
            try:
                info["cpu_count"]   = psutil.cpu_count()
                info["cpu_percent"] = f"{psutil.cpu_percent(interval=0.5):.1f}%"
                vm = psutil.virtual_memory()
                info["ram_total"]   = f"{vm.total//1024//1024} MB"
                info["ram_free"]    = f"{vm.available//1024//1024} MB"
                info["ram_used"]    = f"{vm.percent}%"
                disks = []
                for p in psutil.disk_partitions():
                    try:
                        u = psutil.disk_usage(p.mountpoint)
                        disks.append(f"{p.device} {round(u.used/1e9,1)}/{round(u.total/1e9,1)} GB")
                    except Exception: pass
                info["disks"] = disks
                # Battery
                try:
                    bat = psutil.sensors_battery()
                    if bat:
                        info["battery"] = f"{bat.percent:.0f}% {'заряжается' if bat.power_plugged else 'от батареи'}"
                except Exception: pass
            except Exception as e:
                info["error"] = str(e)
        return info

    # ── Сеть ─────────────────────────────────────────────────────────
    def _network_info(self) -> dict:
        info = {}
        try: info["local_ip"] = socket.gethostbyname(socket.gethostname())
        except Exception: info["local_ip"] = "N/A"
        # Интерфейсы
        if HAS_PSUTIL:
            try:
                ifaces = {}
                for iface, snics in psutil.net_if_addrs().items():
                    addrs = []
                    for s in snics:
                        if s.family == socket.AF_INET:
                            addrs.append(s.address)
                    if addrs:
                        ifaces[iface] = addrs
                info["interfaces"] = ifaces
            except Exception: pass
            try:
                conns = []
                for c in psutil.net_connections(kind='inet'):
                    if c.status == 'ESTABLISHED' and c.raddr:
                        conns.append(f"{c.raddr.ip}:{c.raddr.port}")
                info["active_connections"] = list(set(conns))[:20]
            except Exception: pass
        # Внешний IP
        if HAS_REQUESTS:
            try:
                r = requests.get("http://ip-api.com/json/", timeout=4)
                if r.status_code == 200:
                    geo = r.json()
                    info["external_ip"]  = geo.get("query","N/A")
                    info["geo_country"]  = geo.get("country","N/A")
                    info["geo_city"]     = geo.get("city","N/A")
                    info["geo_isp"]      = geo.get("isp","N/A")
                    info["vpn_detected"] = geo.get("proxy",False) or geo.get("hosting",False)
            except Exception: pass
        return info

    # ── Процессы ─────────────────────────────────────────────────────
    def _process_info(self) -> dict:
        if not HAS_PSUTIL:
            return {"error": "psutil not available"}
        try:
            procs = []
            suspicious = []
            spy_kw = ['keylog','wireshark','fiddler','charles','burp',
                      'tcpdump','ettercap','angry','nmap','metasploit']
            for p in psutil.process_iter(['pid','name','username','cpu_percent','status']):
                n = (p.info.get('name') or '').lower()
                entry = f"PID{p.info['pid']:5d} {p.info.get('name','?')[:35]:<35s} [{p.info.get('status','?')}]"
                procs.append(entry)
                for kw in spy_kw:
                    if kw in n:
                        suspicious.append(p.info.get('name','?'))
                        break
            return {"count": len(procs), "list": procs[:60],
                    "suspicious": suspicious or ["не обнаружено"]}
        except Exception as e:
            return {"error": str(e)}

    # ── Открытые порты ───────────────────────────────────────────────
    def _port_scan(self) -> list:
        """Быстрое сканирование ключевых портов на localhost."""
        PORTS = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",80:"HTTP",
                 135:"RPC",139:"NetBIOS",443:"HTTPS",445:"SMB",
                 1433:"MSSQL",3306:"MySQL",3389:"RDP",5900:"VNC",
                 8080:"HTTP-Alt",8888:"DARP"}
        open_ports = []
        def _chk(port, svc):
            try:
                s = socket.socket(); s.settimeout(0.3)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    open_ports.append(f":{port} {svc}")
                s.close()
            except Exception: pass
        threads = [threading.Thread(target=_chk, args=(p,s), daemon=True)
                   for p,s in PORTS.items()]
        for t in threads: t.start()
        for t in threads: t.join(timeout=1)
        return sorted(open_ports) or ["закрытых/нет слушающих портов"]

    # ── Проверки безопасности ────────────────────────────────────────
    def _security_checks(self) -> dict:
        checks = {}
        if platform.system() == "Windows":
            # Defender
            try:
                r = subprocess.run(
                    ["powershell","-Command",
                     "(Get-MpComputerStatus).AntivirusEnabled"],
                    capture_output=True, text=True, timeout=5)
                checks["antivirus"] = "Включён" if "True" in r.stdout else "Неизвестно/Отключён"
            except Exception:
                checks["antivirus"] = "N/A"
            # Firewall
            try:
                r = subprocess.run(
                    ["netsh","advfirewall","show","allprofiles","state"],
                    capture_output=True, text=True, timeout=5)
                checks["firewall"] = "ON" if "ON" in r.stdout else "OFF/N/A"
            except Exception:
                checks["firewall"] = "N/A"
            # Windows Update
            try:
                r = subprocess.run(
                    ["reg","query",
                     r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
                     "/v","AUOptions"],
                    capture_output=True, text=True, timeout=3)
                checks["auto_update"] = "Настроен" if "0x" in r.stdout else "Не настроен"
            except Exception:
                checks["auto_update"] = "N/A"
        return checks

    def format_report(self, report: dict) -> str:
        """Форматирует отчёт для отображения в UI."""
        lines = []
        lines.append("═" * 60)
        lines.append(f"  ОТЧЁТ АУДИТА ХОСТ-СИСТЕМЫ  —  {report.get('timestamp','')}")
        lines.append("═" * 60)

        os_info = report.get("os", {})
        lines.append("\n[ ОПЕРАЦИОННАЯ СИСТЕМА ]")
        for k, v in os_info.items():
            lines.append(f"  {k:<20s}: {v}")

        hw = report.get("hardware", {})
        lines.append("\n[ АППАРАТУРА ]")
        for k, v in hw.items():
            if isinstance(v, list):
                lines.append(f"  {k}:")
                for item in v: lines.append(f"    {item}")
            else:
                lines.append(f"  {k:<20s}: {v}")

        net = report.get("network", {})
        lines.append("\n[ СЕТЬ ]")
        for k, v in net.items():
            if isinstance(v, dict):
                lines.append(f"  {k}:")
                for ik, iv in v.items(): lines.append(f"    {ik}: {iv}")
            elif isinstance(v, list):
                lines.append(f"  {k}:")
                for item in v[:10]: lines.append(f"    {item}")
            else:
                lines.append(f"  {k:<20s}: {v}")

        procs = report.get("processes", {})
        lines.append(f"\n[ ПРОЦЕССЫ ]  ({procs.get('count',0)} запущено)")
        for s in (procs.get("suspicious") or []):
            lines.append(f"  ⚠ ПОДОЗРИТЕЛЬНЫЙ: {s}")

        ports = report.get("ports", [])
        lines.append("\n[ ОТКРЫТЫЕ ПОРТЫ ]")
        for p in ports: lines.append(f"  {p}")

        sec = report.get("security", {})
        if sec:
            lines.append("\n[ ЗАЩИТА ]")
            for k, v in sec.items(): lines.append(f"  {k:<20s}: {v}")

        lines.append("\n" + "═" * 60)
        return "\n".join(lines)
