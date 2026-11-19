# -*- coding: utf-8 -*-
"""Все настройки парсера в одном месте."""

SUBS_FILE    = "subs.txt"
WORK_FILE    = "work.txt"          # рабочие (после перепроверки — только подтверждённые)
UNKNOWN_FILE = "unknow.txt"        # быстрые, но без геолокации
DEAD_FILE    = "dead.txt"          # дохлые + причина (для дебага)
JSON_FILE    = "subwork.json"      # JSON-массив конфигов по странам (формат Happ)
RAW_FILE     = "subwork_raw.txt"   # base64-подписка всех рабочих ключей

BRAND          = "@RUXVPN"         # хвост в названиях ключей
SUB_USER_AGENT = "Happ/4.2.1"      # эмуляция Happ при запросе подписок
SUB_HEADERS    = {"X-Device-Os": "Android"}
FETCH_TIMEOUT  = 25

THREADS      = 10                  # параллельных xray-инстансов
XRAY_DIR     = "bin"
XRAY_VERSION = "latest"            # или конкретный тег, например "v26.11.9"

# --- PING via PROXY GET + keepAlive ---
PING_URL      = "https://www.gstatic.com/generate_204"
PING_TIMEOUT  = 8                  # секунд на один запрос
PING_REQUESTS = 2                  # 1-й — прогрев, 2-й — чистый замер по тому же TLS
MAX_PING_MS   = 3000               # выше — в мусор

# --- SPEED (через тот же сеанс ядра) ---
DOWNLOAD_URL     = "https://speed.cloudflare.com/__down?bytes={n}"
UPLOAD_URL       = "https://speed.cloudflare.com/__up"
DOWNLOAD_BYTES   = 10_000_000
UPLOAD_BYTES     = 4_000_000
SPEED_TIME_LIMIT = 12              # потолок секунд на один тест
MIN_SPEED_MB_S   = 1.0             # МБ/с (мегаБАЙТ/с). 1 Мбит/с = 0.125 МБ/с

# --- GEO ---
GEO_URL      = "https://2ip.io/"
GEO_FALLBACK = True                # 2ip молчит -> ip-api.com -> ipwho.is (через тот же прокси)

# --- RECHECK ---
RECHECK                = True
RECHECK_DOWNLOAD_BYTES = 5_000_000
RECHECK_UPLOAD_BYTES   = 2_000_000

INCLUDE_RU_BYPASS = True           # РФ-сайты напрямую в итоговых конфигах (как у vexaloria)
