# -*- coding: utf-8 -*-
"""Все настройки парсера в одном месте."""

SUBS_FILE    = "subs.txt"
WORK_FILE    = "work.txt"
UNKNOWN_FILE = "unknow.txt"
DEAD_FILE    = "dead.txt"
JSON_FILE    = "subwork.json"
RAW_FILE     = "subwork_raw.txt"

BRAND          = "@RUXVPN"
SUB_USER_AGENT = "Happ/4.2.1"
SUB_HEADERS    = {"X-Device-Os": "Android"}
SUB_HWID       = 5796126e-b9e9-4e3e-bfbc-4fe930796181              # свой hwid строкой; None = из токена ссылки или случайный
FETCH_TIMEOUT  = 25

THREADS      = 10
XRAY_DIR     = "bin"
XRAY_VERSION = "latest"

SKIP_HY2_OBFS = False              # True = скипать hysteria2+salamander (несовместим с xray, #5712)

# --- PING via PROXY GET + keepAlive (хосты пробуются по очереди) ---
PING_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/cdn-cgi/trace",
    "https://connectivitycheck.gstatic.com/generate_204",
]
PING_TIMEOUT  = 8
PING_REQUESTS = 2                  # 1-й — прогрев, 2-й — чистый замер по тому же TLS
MAX_PING_MS   = 3000

# --- SPEED (через тот же сеанс ядра) ---
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes={n}"
UPLOAD_URL   = "https://speed.cloudflare.com/__up"
# запасные зеркала — только если Cloudflare 429/5xx/таймаут
DOWNLOAD_FALLBACKS = [
    "https://nbg1-speed.hetzner.com/10MB.bin",
    "https://proof.ovh.net/files/10Mb.dat",
    "https://speedtest.tele2.net/10MB.zip",
]
UPLOAD_FALLBACKS = [
    "http://speedtest.tele2.net/upload.php",   # принимает POST/PUT, отвечает коротко
]
DOWNLOAD_BYTES   = 10_000_000
UPLOAD_BYTES     = 4_000_000
SPEED_TIME_LIMIT = 12
MIN_SPEED_MB_S   = 1.0             # МБ/с (мегаБАЙТ). 1 Мбит/с = 0.125

SPEED_RETRIES     = 2              # ретраев на хост при 429/5xx (с паузой + Retry-After)
SPEED_BACKOFF     = 1.5            # базовая пауза, дальше x2 + джиттер
SPEED_CONCURRENCY = 4              # максимум одновременных спидтестов (анти-429)

# --- GEO ---
GEO_URL      = "https://2ip.io/"
GEO_FALLBACK = True                # 2ip молчит -> ip-api.com -> ipwho.is -> country.is

# --- RECHECK ---
RECHECK                = True
RECHECK_DOWNLOAD_BYTES = 5_000_000
RECHECK_UPLOAD_BYTES   = 2_000_000

INCLUDE_RU_BYPASS = True
