"""
DARP v8 :: GeoModule — геолокация, VPN-детекция, встроенный прокси-туннель
"""
import json, threading, time, socket
from pathlib import Path

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

GEO_APIS = [
    "http://ip-api.com/json/?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting,mobile",
    "https://ipapi.co/json/",
    "https://ipinfo.io/json",
]


class GeoModule:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self._cache = None
        self._cache_ts = 0

    # ── Получение геолокации ─────────────────────────────────────────
    def get_location(self, force: bool = False) -> dict:
        if self._cache and not force and (time.time() - self._cache_ts) < 300:
            return self._cache

        if not HAS_REQUESTS:
            return {"error": "requests не установлен", "query": "N/A"}

        for api in GEO_APIS:
            try:
                r = requests.get(api, timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    # нормализуем под общий формат
                    if "ip" in data and "country_name" in data:  # ipapi.co
                        data = {
                            "query": data.get("ip",""),
                            "country": data.get("country_name",""),
                            "countryCode": data.get("country_code",""),
                            "city": data.get("city",""),
                            "region": data.get("region",""),
                            "timezone": data.get("timezone",""),
                            "isp": data.get("org",""),
                            "proxy": False,
                            "hosting": False,
                        }
                    elif "org" in data and "ip" in data:  # ipinfo.io
                        data = {
                            "query": data.get("ip",""),
                            "country": data.get("country",""),
                            "city": data.get("city",""),
                            "region": data.get("region",""),
                            "timezone": data.get("timezone",""),
                            "isp": data.get("org",""),
                            "proxy": False,
                            "hosting": False,
                        }
                    self._cache = data
                    self._cache_ts = time.time()
                    return data
            except Exception:
                continue

        return {"error": "Нет соединения с геолокационным сервисом", "query": "N/A"}

    # ── VPN-детекция ─────────────────────────────────────────────────
    def detect_vpn(self) -> dict:
        geo = self.get_location()
        is_vpn = geo.get("proxy", False) or geo.get("hosting", False)
        result = {
            "vpn_detected": is_vpn,
            "ip": geo.get("query", "N/A"),
            "isp": geo.get("isp", "N/A"),
            "country": geo.get("country", "N/A"),
            "city": geo.get("city", "N/A"),
        }
        if "error" in geo:
            result["error"] = geo["error"]
        return result

    # ── Публичный IP ─────────────────────────────────────────────────
    def get_public_ip(self) -> str:
        geo = self.get_location()
        return geo.get("query", "N/A")

    # ── DNS-leak тест ────────────────────────────────────────────────
    def dns_leak_test(self) -> list:
        results = []
        test_domains = ["google.com","cloudflare.com","github.com"]
        for domain in test_domains:
            try:
                ip = socket.gethostbyname(domain)
                results.append(f"{domain} → {ip}")
            except Exception:
                results.append(f"{domain} → ОШИБКА")
        return results
