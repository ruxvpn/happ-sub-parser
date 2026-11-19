# -*- coding: utf-8 -*-
"""Забор подписок с эмуляцией Happ: base64 / plain-ссылки / Happ-JSON.
X-Hwid берётся из токена в URL (device-id), пустой ответ дампуется в debug/."""
import json, os, re, uuid
from urllib.parse import urlsplit
import requests

import config
from core.links import parse_link, outbound_to_link, b64d

HWID = uuid.uuid4().hex
_SCHEME_RE = re.compile(r'(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s"\'<>]+', re.I)


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
    """В токене подписки часто зашит device-id: base64(JSON {"d": "..."})."""
    try:
        seg = urlsplit(url).path.rstrip("/").split("/")[-1]
        j = json.loads(b64d(seg))
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


def fetch_subscription(url):
    hwid = getattr(config, "SUB_HWID", None) or _hwid_from_url(url) or HWID
    headers = {"User-Agent": config.SUB_USER_AGENT, "Accept": "*/*",
               "X-Hwid": hwid, **config.SUB_HEADERS}
    r = requests.get(url, headers=headers, timeout=config.FETCH_TIMEOUT)
    r.raise_for_status()
    raws = extract_raw_links(r.text)
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
