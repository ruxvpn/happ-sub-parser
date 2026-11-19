# -*- coding: utf-8 -*-
"""Проверка одного ключа: PING via PROXY GET (keepAlive) -> скорость -> гео.
Все запросы — в одной сессии requests через один инстанс xray (один транспорт)."""
import os, time
import requests

import config
from core.xray import Xray, free_port, check_config
from core.geo import detect_geo

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def _err(e):
    return (type(e).__name__ + ": " + str(e))[-180:]


def measure_ping(session):
    """Первый GET прогревает TCP+TLS+прокси-рукопожатие, второй меряет чистый
    отклик по уже установленному соединению (keepAlive, тот же инстанс ядра)."""
    times = []
    for _ in range(max(2, config.PING_REQUESTS)):
        t0 = time.perf_counter()
        r = session.get(config.PING_URL, timeout=config.PING_TIMEOUT)
        dt = (time.perf_counter() - t0) * 1000.0
        if r.status_code not in (200, 204):
            raise RuntimeError(f"ping HTTP {r.status_code}")
        r.close()
        times.append(dt)
    return times[-1]


def measure_download(session, nbytes):
    # прогрев хоста скорости, чтобы замер шёл по уже установленному TLS
    session.get(config.DOWNLOAD_URL.format(n=0), timeout=config.PING_TIMEOUT).close()
    got, t0 = 0, time.perf_counter()
    with session.get(config.DOWNLOAD_URL.format(n=nbytes), stream=True,
                     timeout=(config.PING_TIMEOUT, config.SPEED_TIME_LIMIT)) as r:
        if r.status_code != 200:
            raise RuntimeError(f"download HTTP {r.status_code}")
        for chunk in r.iter_content(65536):
            got += len(chunk)
            if time.perf_counter() - t0 > config.SPEED_TIME_LIMIT:
                break
    dt = time.perf_counter() - t0
    if got == 0 or dt <= 0:
        raise RuntimeError("download пустой")
    return got / dt / 1e6


def measure_upload(session, nbytes):
    payload = os.urandom(nbytes)  # рандом, чтобы не жался компрессией
    t0 = time.perf_counter()
    r = session.post(config.UPLOAD_URL, data=payload,
                     timeout=(config.PING_TIMEOUT, config.SPEED_TIME_LIMIT),
                     headers={"Content-Type": "application/octet-stream"})
    dt = time.perf_counter() - t0
    if r.status_code not in (200, 204):
        raise RuntimeError(f"upload HTTP {r.status_code}")
    return nbytes / dt / 1e6


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
        ping, last = None, None
        for _ in range(2):
            try:
                ping = measure_ping(s)
                break
            except Exception as e:
                last = e
                time.sleep(0.3)
        if ping is None:
            raise RuntimeError(_err(last))
        res["ping"] = round(ping, 1)
        if ping > config.MAX_PING_MS:
            raise RuntimeError(f"пинг {ping:.0f}мс > {config.MAX_PING_MS}мс")

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
