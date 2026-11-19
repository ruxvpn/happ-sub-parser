# -*- coding: utf-8 -*-
"""Забор подписок с эмуляцией Happ: base64 / plain-ссылки / Happ-JSON (массив конфигов)."""
import json, re, uuid
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


def fetch_subscription(url):
    headers = {"User-Agent": config.SUB_USER_AGENT, "Accept": "*/*",
               "X-Hwid": HWID, **config.SUB_HEADERS}
    r = requests.get(url, headers=headers, timeout=config.FETCH_TIMEOUT)
    r.raise_for_status()
    raws = extract_raw_links(r.text)
    links, bad = [], 0
    for raw in raws:
        d = parse_link(raw)
        if d:
            links.append(d)
        else:
            bad += 1
    return links, bad
