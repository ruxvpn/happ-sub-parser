# -*- coding: utf-8 -*-
"""Проверка одного ключа: PING via PROXY GET (keepAlive) -> скорость -> гео.
Все запросы — в одной сессии requests через один инстанс xray (один транспорт).
429/5xx — ретраи с паузой и Retry-After, потом запасные зеркала скорости."""
import os, random, threading, time
import requests

import config
from core.xray import Xray, free_port, check_config
from core.geo import detect_geo

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_speed_sem = threading.Semaphore(config.SPEED_CONCURRENCY)


def _err(e):
    return (type(e).__name__ + ": " + str(e))[-180:]


class _Retryable(Exception):
    def __init__(self, status, resp=None):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.resp = resp


def _is_retryable(status):
    return status in (429, 500, 502, 503, 504)


def _backoff(attempt, resp=None):
    delay = config.SPEED_BACKOFF * (2 ** attempt) + random.uniform(0, 0.5)
    try:
        ra = resp.headers.get("Retry-After") if resp is not None else None
        if ra and str(ra).isdigit():
            delay = max(delay, min(int(ra), 8))
    except Exception:
        pass
    time.sleep(delay)


def measure_ping(session):
    """Первый GET прогревает TCP+TLS+прокси-рукопожатие, второй меряет чистый
    отклик по уже установленному соединению. Хосты PING_URLS — по очереди."""
    last = None
    for url in config.PING_URLS:
        try:
            times = []
            for _ in range(max(2, config.PING_REQUESTS)):
                t0 = time.perf_counter()
                r = session.get(url, timeout=config.PING_TIMEOUT)
                dt = (time.perf_counter() - t0) * 1000.0
                if r.status_code not in (200, 204):
                    raise RuntimeError(f"ping HTTP {r.status_code}")
                _ = r.content   # дочитать тело, чтобы коннект остался в пуле (keepAlive)
                r.close()
                times.append(dt)
            return times[-1]
        except Exception as e:
            last = e
    raise RuntimeError(_err(last))


def _download_once(session, url, nbytes):
    headers = {}
    if "__down" not in url:                      # статический файл — режем Range'ом
        headers["Range"] = f"bytes=0-{nbytes - 1}"
    got, t0 = 0, time.perf_counter()
    with session.get(url, stream=True, headers=headers,
                     timeout=(config.PING_TIMEOUT, config.SPEED_TIME_LIMIT)) as r:
        if _is_retryable(r.status_code):
            raise _Retryable(r.status_code, r)
        if r.status_code not in (200, 206):
            raise RuntimeError(f"download HTTP {r.status_code}")
        for chunk in r.iter_content(65536):
            got += len(chunk)
            if got >= nbytes or time.perf_counter() - t0 > config.SPEED_TIME_LIMIT:
                break
    dt = time.perf_counter() - t0
    if got == 0 or dt <= 0:
        raise RuntimeError("download пустой")
    return got / dt / 1e6


def measure_download(session, nbytes):
    urls = [config.DOWNLOAD_URL.format(n=nbytes)] + list(config.DOWNLOAD_FALLBACKS)
    last = None
    for i, url in enumerate(urls):
        if i == 0:   # прогрев хоста скорости — замер пойдёт по уже установленному TLS
            try:
                session.get(config.DOWNLOAD_URL.format(n=0),
                            timeout=config.PING_TIMEOUT).close()
            except Exception:
                pass
        for attempt in range(config.SPEED_RETRIES + 1):
            try:
                return _download_once(session, url, nbytes)
            except _Retryable as e:
                last = e
                if attempt < config.SPEED_RETRIES:
                    _backoff(attempt, e.resp)
            except Exception as e:               # таймаут/обрыв — сразу на зеркало
                last = e
                break
    raise RuntimeError("download: " + _err(last))


def _upload_once(session, url, payload):
    t0 = time.perf_counter()
    r = session.post(url, data=payload,
                     timeout=(config.PING_TIMEOUT, config.SPEED_TIME_LIMIT),
                     headers={"Content-Type": "application/octet-stream"})
    dt = time.perf_counter() - t0
    if r.status_code in (405, 501):              # некоторые зеркала принимают только PUT
        t0 = time.perf_counter()
        r = session.put(url, data=payload,
                        timeout=(config.PING_TIMEOUT, config.SPEED_TIME_LIMIT),
                        headers={"Content-Type": "application/octet-stream"})
        dt = time.perf_counter() - t0
    if _is_retryable(r.status_code):
        raise _Retryable(r.status_code, r)
    if r.status_code not in (200, 201, 204):
        raise RuntimeError(f"upload HTTP {r.status_code}")
    return len(payload) / dt / 1e6


def measure_upload(session, nbytes):
    payload = os.urandom(nbytes)                 # рандом, чтобы не жался компрессией
    last = None
    for url in [config.UPLOAD_URL] + list(config.UPLOAD_FALLBACKS):
        for attempt in range(config.SPEED_RETRIES + 1):
            try:
                return _upload_once(session, url, payload)
            except _Retryable as e:
                last = e
                if attempt < config.SPEED_RETRIES:
                    _backoff(attempt, e.resp)
            except Exception as e:
                last = e
                break
    raise RuntimeError("upload: " + _err(last))


def check(link, binary, quick=False):
    res = {"link": link, "ok": False, "unknown": False, "stage": "start", "error": "",
           "ping": None, "down": None, "up": None,
           "cc": None, "city": None, "ip": None, "geo_src": None}
    x = s = None
    try:
        port = free_port()
        x = Xray(binary, check_config(link, port), port)
        s = requests.Session()
        s.trust_env = False
        s.proxies = {"http": f"http://127.0.0.1:{port}",
                     "https": f"http://127.0.0.1:{port}"}
        s.headers.update({"User-Agent": BROWSER_UA, "Accept": "*/*",
                          "Accept-Language": "en-US,en;q=0.9"})

        res["stage"] = "ping"
        ping = measure_ping(s)                   # сам переберёт PING_URLS
        res["ping"] = round(ping, 1)
        if ping > config.MAX_PING_MS:
            raise RuntimeError(f"пинг {ping:.0f}мс > {config.MAX_PING_MS}мс")

        with _speed_sem:                         # не больше N спидтестов разом (анти-429)
            res["stage"] = "download"
            dbytes = config.RECHECK_DOWNLOAD_BYTES if quick else config.DOWNLOAD_BYTES
            res["down"] = round(measure_download(s, dbytes), 2)

            res["stage"] = "upload"
            ubytes = config.RECHECK_UPLOAD_BYTES if quick else config.UPLOAD_BYTES
            res["up"] = round(measure_upload(s, ubytes), 2)

        if res["down"] < config.MIN_SPEED_MB_S or res["up"] < config.MIN_SPEED_MB_S:
            raise RuntimeError(f"скорость ↓{res['down']} ↑{res['up']} МБ/с "
                               f"< {config.MIN_SPEED_MB_S} МБ/с")

        res["stage"] = "geo"
        if quick and link.get("_cc"):
            res.update(cc=link["_cc"], city=link.get("_city"),
                       ip=link.get("_ip"), geo_src="cache")
        else:
            cc, city, ip, src = detect_geo(s, config.GEO_URL, config.GEO_FALLBACK)
            res.update(cc=cc, city=city, ip=ip, geo_src=src)
            if not cc:
                res["unknown"] = True
                res["error"] = "локация не определена"
                return res

        res["ok"] = True
        res["stage"] = "done"
    except Exception as e:
        res["error"] = _err(e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
        if x is not None:
            x.stop()
    return res
