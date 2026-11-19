# -*- coding: utf-8 -*-
"""Забор подписок с эмуляцией Happ.

Порядок добычи для ссылок вида .../sub/<token>:
1) POST /api/android/sync {"token": ...} — эндпоинт панели отдаёт конфиги
   по токену БЕЗ привязки к устройству (хвид не нужен, ссылка не "сжигается").
2) Фолбэк: GET с X-Hwid (хвид из токена / из config / стабильный случайный).
Пустой ответ дампуется в debug/."""
import json, os, re, uuid
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import requests

import config
from core.links import parse_link, outbound_to_link, b64d

HWID = uuid.uuid4().hex
_SCHEME_RE = re.compile(r'(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s"\'<>]+', re.I)
_SYNC_RE = re.compile(r'^(https?://[^/]+)/sub/([^/?#]+)', re.I)


def _lines_with_links(text):
    return [l.strip() for l in text.splitlines()
            if l.strip().lower().startswith(("vless://", "vmess://", "trojan://",
                                             "ss://", "hysteria2://", "hy2://"))]


def _from_json(j):
    cfgs = j if isinstance(j, list) else [j]
    out = []
    for cfg in cfgs:
        if not isinstance(cfg, dict):
            continue
        for ob in cfg.get("outbounds") or []:
            d = outbound_to_link(ob)
            if d:
                out.append(d["raw"])
    return out


def extract_raw_links(text, depth=0):
    t = (text or "").strip()
    if not t:
        return []
    if t[0] in "[{":
        try:
            out = _from_json(json.loads(t))
            if out:
                return out
        except Exception:
            pass
    found = _lines_with_links(t)
    if found:
        return found
    if depth < 2:
        try:
            dec = b64d(t)
            if "://" in dec or dec.strip()[:1] in "[{":
                out = extract_raw_links(dec, depth + 1)
                if out:
                    return out
        except Exception:
            pass
    return _SCHEME_RE.findall(t)


def _hwid_from_url(url):
    """Токен часто JWT-подобный: base64(JSON {"d": ...}).signature.
    Декодируем только payload (до точки), хвост-подпись игнорим."""
    try:
        seg = urlsplit(url).path.rstrip("/").split("/")[-1]
        dec = b64d(seg.split(".")[0])
        j, _ = json.JSONDecoder().raw_decode(dec)
        if isinstance(j, dict):
            for k in ("d", "hwid", "device", "deviceId", "device_id"):
                v = j.get(k)
                if isinstance(v, str) and 8 <= len(v) <= 64:
                    return v
    except Exception:
        pass
    return None


def _dump_empty(url, r):
    try:
        os.makedirs("debug", exist_ok=True)
        name = re.sub(r"[^a-zA-Z0-9.-]", "_", urlsplit(url).netloc)[:60]
        path = os.path.join("debug", f"sub_{name}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"URL: {url}\nSTATUS: {r.status_code}\n"
                    f"Content-Type: {r.headers.get('Content-Type')}\n"
                    f"Bytes: {len(r.content)}\n\n{r.text[:20000]}")
        print(f"[sub] ⚠️ 0 ключей — ответ сохранён в {path}", flush=True)
    except Exception:
        pass


def _with_hwid_query(url, hwid):
    u = urlsplit(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q["hwid"] = hwid
    return urlunsplit((u.scheme, u.netloc, u.path, urlencode(q), u.fragment))


def _try_android_sync(url):
    """Обход привязки к устройству: для .../sub/<token> пробуем
    POST /api/android/sync {"token": ...}. Возвращает
    {"success": true, "configs": [полные xray-конфиги]} — хвид не нужен,
    ссылка не привязывается к парсеру."""
    m = _SYNC_RE.match(url)
    if not m:
        return []
    base, token = m.group(1), m.group(2)
    try:
        r = requests.post(base + "/api/android/sync", json={"token": token},
                          headers={"User-Agent": config.SUB_USER_AGENT,
                                   "Accept": "application/json"},
                          timeout=config.FETCH_TIMEOUT)
        if r.status_code != 200:
            return []
        j = r.json()
        if not (isinstance(j, dict) and j.get("success")):
            return []
        configs = j.get("configs")
        if not (isinstance(configs, list) and configs):
            return []
        if all(isinstance(c, str) for c in configs):
            return configs                      # вдруг там сразу ссылки
        return _from_json(configs)              # конфиги -> ссылки по outbounds
    except Exception:
        return []


def fetch_subscription(url):
    token_hwid = _hwid_from_url(url)

    # 1) пробуем эндпоинт панели без привязки к устройству
    raws = _try_android_sync(url)
    if raws:
        print(f"[sub] {urlsplit(url).netloc}: via /api/android/sync "
              f"({len(raws)} ключей, без привязки)", flush=True)
    else:
        # 2) фолбэк: GET с X-Hwid
        hwid = token_hwid or getattr(config, "SUB_HWID", None) or HWID
        if token_hwid:
            print(f"[sub] hwid из токена: {token_hwid}", flush=True)
        headers = {"User-Agent": config.SUB_USER_AGENT, "Accept": "*/*",
                   "X-Hwid": hwid, **config.SUB_HEADERS}
        r = requests.get(url, headers=headers, timeout=config.FETCH_TIMEOUT)
        r.raise_for_status()
        raws = extract_raw_links(r.text)
        if not raws and token_hwid:
            # часть панелей читает хвид из query
            try:
                r2 = requests.get(_with_hwid_query(url, hwid), headers=headers,
                                  timeout=config.FETCH_TIMEOUT)
                if r2.status_code == 200:
                    raws2 = extract_raw_links(r2.text)
                    if raws2:
                        r, raws = r2, raws2
            except Exception:
                pass
        if not raws:
            _dump_empty(url, r)

    links, bad = [], 0
    for raw in raws:
        d = parse_link(raw)
        if d is None:
            bad += 1
            continue
        if getattr(config, "SKIP_HY2_OBFS", False) and d["scheme"] == "hy2" and d["obfs"]:
            bad += 1
            continue
        links.append(d)
    return links, bad
