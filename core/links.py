# -*- coding: utf-8 -*-
"""Парсинг share-ссылок (vless/vmess/trojan/ss/hysteria2) -> канонический dict,
сборка Xray outbound, обратная сериализация и дедуп-ключи."""
import base64, json, re
from urllib.parse import urlsplit, parse_qs, unquote, quote

SUPPORTED = ("vless", "vmess", "trojan", "ss", "hysteria2", "hy2")
_NET_ALIAS = {"raw": "tcp", "splithttp": "xhttp", "http": "h2"}


def b64d(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "replace")


def b64e(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _q(q, k, d=""):
    return (q.get(k, [d])[0] or "").strip()


def _bool(v):
    return str(v).lower() in ("1", "true", "yes")


def _hostport(addr, port):
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


def parse_link(url: str):
    """share-ссылка -> канонический dict или None (неподдерживаемый/битый ключ)."""
    url = url.strip()
    low = url.lower()
    if not low.startswith(tuple(s + "://" for s in SUPPORTED)):
        return None
    try:
        if low.startswith("vmess://"):
            d = _parse_vmess(url)
        elif low.startswith("ss://"):
            d = _parse_ss(url)
        else:
            d = _parse_url(url)
        if not d or not d.get("address") or not d.get("port"):
            return None
        if not (1 <= int(d["port"]) <= 65535):
            return None
        d["port"] = int(d["port"])
        d["raw"] = url
        return d
    except Exception:
        return None


def _parse_url(url):
    u = urlsplit(url)
    scheme = u.scheme.lower()
    scheme = "hy2" if scheme == "hysteria2" else scheme
    q = parse_qs(u.query, keep_blank_values=True)
    addr = u.hostname or ""
    port = u.port or 0
    cred = unquote(u.username or "")
    if u.password is not None:
        cred += ":" + unquote(u.password)
    remark = unquote(u.fragment or "")

    if scheme == "hy2":
        return dict(scheme="hy2", id=cred, address=addr, port=port, net="hysteria",
                    security="tls", sni=_q(q, "sni"), fp="", pbk="", sid="", spx="",
                    alpn=[a for a in _q(q, "alpn", "h3").split(",") if a],
                    allow_insecure=_bool(_q(q, "insecure", "0")) or _bool(_q(q, "allowInsecure", "0")),
                    flow="", host="", path="", service="", authority="", mode="",
                    extra=None, header="none", aid=0, scy="", method="",
                    obfs=_q(q, "obfs"), obfs_password=_q(q, "obfs-password"), remark=remark)

    net = _NET_ALIAS.get(_q(q, "type", "tcp").lower(), _q(q, "type", "tcp").lower())
    sec = _q(q, "security", "tls" if scheme == "trojan" else "none").lower()
    if sec not in ("none", "tls", "reality"):
        sec = "none"
    pbk = _q(q, "pbk")
    if sec == "reality" and not pbk:
        return None
    fp = _q(q, "fp")
    if sec == "reality" and not fp:
        fp = "chrome"
    mode = _q(q, "mode")
    if net == "grpc" and not mode:
        mode = "gun"
    if net == "xhttp" and not mode:
        mode = "auto"
    extra = None
    if _q(q, "extra"):
        try:
            extra = json.loads(_q(q, "extra"))
        except Exception:
            extra = None
    path = _q(q, "path")
    if net in ("ws", "xhttp", "httpupgrade", "h2") and not path:
        path = "/"
    return dict(scheme=scheme, id=cred, address=addr, port=port, net=net, security=sec,
                sni=_q(q, "sni") or _q(q, "peer"), fp=fp, pbk=pbk, sid=_q(q, "sid"),
                spx=_q(q, "spx", "/") if sec == "reality" else "",
                alpn=[a for a in _q(q, "alpn").split(",") if a],
                allow_insecure=_bool(_q(q, "allowInsecure", "0")) or _bool(_q(q, "insecure", "0")),
                flow=_q(q, "flow") if net == "tcp" else "",
                host=_q(q, "host"), path=path, service=_q(q, "serviceName"),
                authority=_q(q, "authority"), mode=mode, extra=extra,
                header=_q(q, "headerType", "none").lower(), aid=0, scy="", method="",
                obfs="", obfs_password="", remark=remark)


def _parse_vmess(url):
    j = json.loads(b64d(url[8:]))
    net = str(j.get("net", "tcp")).lower()
    net = _NET_ALIAS.get(net, net)
    tls = str(j.get("tls", "")).lower() in ("tls", "1", "true")
    path = str(j.get("path", "") or "")
    service = path if net == "grpc" else ""
    if net in ("ws", "xhttp", "httpupgrade", "h2") and not path:
        path = "/"
    return dict(scheme="vmess", id=str(j.get("id", "")), address=str(j.get("add", "")),
                port=int(j.get("port") or 0), net=net, security="tls" if tls else "none",
                sni=str(j.get("sni", "") or ""), fp=str(j.get("fp", "") or ""),
                pbk="", sid="", spx="",
                alpn=[a for a in str(j.get("alpn", "") or "").split(",") if a],
                allow_insecure=_bool(j.get("allowInsecure", "")), flow="",
                host=str(j.get("host", "") or ""), path=path, service=service,
                authority="", mode="gun" if net == "grpc" else "", extra=None,
                header=str(j.get("type", "none") or "none").lower(),
                aid=int(j.get("aid") or 0), scy=str(j.get("scy") or j.get("security") or "auto"),
                method="", obfs="", obfs_password="", remark=str(j.get("ps", "") or ""))


def _parse_ss(url):
    if "plugin=" in url:          # obfs/v2ray-plugin xray не умеет
        return None
    u = urlsplit(url)
    remark = unquote(u.fragment or "")
    method = password = ""
    addr, port = u.hostname or "", u.port or 0
    if addr and u.username is not None:
        userinfo = unquote(u.username)
        if u.password is not None:
            userinfo += ":" + unquote(u.password)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            method, password = b64d(userinfo).split(":", 1)
    else:
        body = url[5:].split("#")[0].split("?")[0]
        dec = b64d(body)
        m = re.match(r"^([^:]+):(.*)@(.+):(\d+)$", dec, re.S)
        if not m:
            return None
        method, password, addr, port = m.group(1), m.group(2), m.group(3), int(m.group(4))
    if not method or not password:
        return None
    return dict(scheme="ss", id=password, method=method.lower(), address=addr, port=port,
                net="tcp", security="none", sni="", fp="", pbk="", sid="", spx="",
                alpn=[], allow_insecure=False, flow="", host="", path="", service="",
                authority="", mode="", extra=None, header="none", aid=0, scy="",
                obfs="", obfs_password="", remark=remark)


_IGNORE = {"remark", "raw"}

def canon_key(d: dict) -> str:
    """Ключ дедупликации: всё, что влияет на подключение, кроме названия."""
    return json.dumps({k: v for k, v in sorted(d.items())
                       if k not in _IGNORE and not k.startswith("_")},
                      sort_keys=True, ensure_ascii=False)


def build_outbound(d: dict, tag="proxy") -> dict:
    scheme, net, sec = d["scheme"], d["net"], d["security"]
    stream = {"network": "http" if net == "h2" else net, "security": sec}

    if scheme == "hy2":
        stream = {"network": "hysteria", "security": "tls",
                  "tlsSettings": {"serverName": d["sni"] or d["address"],
                                  "allowInsecure": d["allow_insecure"],
                                  "alpn": d["alpn"] or ["h3"]},
                  "hysteriaSettings": {"version": 2, "auth": d["id"]}}
        if d["obfs"] == "salamander":
            stream["hysteriaSettings"]["obfs"] = "salamander"
            stream["hysteriaSettings"]["obfsPassword"] = d["obfs_password"]
        return {"protocol": "hysteria",
                "settings": {"version": 2, "address": d["address"], "port": d["port"]},
                "streamSettings": stream, "tag": tag}

    if sec == "tls":
        tls = {"serverName": d["sni"] or d["host"] or d["address"],
               "allowInsecure": d["allow_insecure"]}
        if d["alpn"]:
            tls["alpn"] = d["alpn"]
        if d["fp"]:
            tls["fingerprint"] = d["fp"]
        stream["tlsSettings"] = tls
    elif sec == "reality":
        stream["realitySettings"] = {"serverName": d["sni"] or d["address"],
                                     "fingerprint": d["fp"] or "chrome",
                                     "publicKey": d["pbk"], "shortId": d["sid"],
                                     "spiderX": d["spx"] or "/"}

    if net == "tcp" and d["header"] == "http":
        stream["tcpSettings"] = {"header": {"type": "http", "request": {
            "version": "1.1", "method": "GET", "path": [d["path"] or "/"],
            "headers": {"Host": [d["host"]] if d["host"] else [],
                        "User-Agent": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"],
                        "Accept-Encoding": ["gzip, deflate"],
                        "Connection": ["keep-alive"], "Pragma": "no-cache"}}}}
    elif net == "ws":
        ws = {"path": d["path"] or "/"}
        if d["host"]:
            ws["headers"] = {"Host": d["host"]}
        stream["wsSettings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": d["service"],
                                  "authority": d["authority"],
                                  "multiMode": d["mode"] == "multi"}
    elif net == "h2":
        stream["httpSettings"] = {"host": [d["host"]] if d["host"] else [],
                                  "path": d["path"] or "/"}
    elif net == "httpupgrade":
        hu = {"path": d["path"] or "/"}
        if d["host"]:
            hu["host"] = d["host"]
        stream["httpupgradeSettings"] = hu
    elif net == "xhttp":
        x = {"path": d["path"] or "/", "mode": d["mode"] or "auto"}
        if d["host"]:
            x["host"] = d["host"]
        if d["extra"]:
            x["extra"] = d["extra"]
        stream["xhttpSettings"] = x

    if scheme == "vless":
        user = {"id": d["id"], "encryption": "none"}
        if d["flow"]:
            user["flow"] = d["flow"]
        settings = {"vnext": [{"address": d["address"], "port": d["port"], "users": [user]}]}
    elif scheme == "vmess":
        settings = {"vnext": [{"address": d["address"], "port": d["port"],
                               "users": [{"id": d["id"], "alterId": d["aid"],
                                          "security": d["scy"] or "auto"}]}]}
    elif scheme == "trojan":
        settings = {"servers": [{"address": d["address"], "port": d["port"],
                                 "password": d["id"]}]}
    else:  # ss
        settings = {"servers": [{"address": d["address"], "port": d["port"],
                                 "method": d["method"], "password": d["id"]}]}
    return {"protocol": scheme, "settings": settings, "streamSettings": stream, "tag": tag}


def serialize(d: dict) -> str:
    """канонический dict -> share-ссылка (с текущим remark)."""
    remark = quote(d.get("remark", ""), safe="")
    hp = _hostport(d["address"], d["port"])
    scheme = d["scheme"]

    if scheme == "vmess":
        j = {"v": "2", "ps": d.get("remark", ""), "add": d["address"], "port": d["port"],
             "id": d["id"], "aid": d["aid"], "scy": d["scy"] or "auto",
             "net": "http" if d["net"] == "h2" else d["net"],
             "type": d["header"], "host": d["host"],
             "path": d["service"] if d["net"] == "grpc" else d["path"],
             "tls": "tls" if d["security"] == "tls" else "", "sni": d["sni"],
             "alpn": ",".join(d["alpn"]), "fp": d["fp"]}
        return "vmess://" + b64e(json.dumps(j, ensure_ascii=False, separators=(",", ":")))

    if scheme == "ss":
        userinfo = quote(b64e(f'{d["method"]}:{d["id"]}'), safe="")
        return f"ss://{userinfo}@{hp}#{remark}"

    if scheme == "hy2":
        p = {"sni": d["sni"], "insecure": "1" if d["allow_insecure"] else "0"}
        if d["obfs"]:
            p["obfs"] = d["obfs"]; p["obfs-password"] = d["obfs_password"]
        if d["alpn"] and d["alpn"] != ["h3"]:
            p["alpn"] = ",".join(d["alpn"])
        qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in p.items() if v != "")
        return f'hysteria2://{quote(d["id"], safe="")}@{hp}?{qs}#{remark}'

    p = {"type": d["net"]}
    if scheme == "vless":
        p["encryption"] = "none"
    if d["security"] != "none":
        p["security"] = d["security"]
    if d["flow"]:
        p["flow"] = d["flow"]
    if d["sni"]:
        p["sni"] = d["sni"]
    if d["fp"]:
        p["fp"] = d["fp"]
    if d["security"] == "reality":
        p["pbk"] = d["pbk"]
        if d["sid"]:
            p["sid"] = d["sid"]
        if d["spx"] and d["spx"] != "/":
            p["spx"] = d["spx"]
    if d["alpn"]:
        p["alpn"] = ",".join(d["alpn"])
    if d["allow_insecure"]:
        p["allowInsecure"] = "1"
    if d["header"] not in ("", "none"):
        p["headerType"] = d["header"]
    if d["host"]:
        p["host"] = d["host"]
    if d["net"] in ("ws", "h2", "httpupgrade", "xhttp") and d["path"]:
        p["path"] = d["path"]
    if d["net"] == "grpc":
        p["serviceName"] = d["service"]
        if d["authority"]:
            p["authority"] = d["authority"]
        if d["mode"] and d["mode"] != "gun":
            p["mode"] = d["mode"]
    if d["net"] == "xhttp":
        if d["mode"] and d["mode"] != "auto":
            p["mode"] = d["mode"]
        if d["extra"]:
            p["extra"] = json.dumps(d["extra"], separators=(",", ":"))
    qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in p.items() if v != "")
    return f'{scheme}://{quote(d["id"], safe="")}@{hp}?{qs}#{remark}'


def outbound_to_link(ob: dict):
    """Xray outbound (из Happ-JSON подписки) -> канонический dict."""
    proto = (ob.get("protocol") or "").lower()
    if proto not in ("vless", "vmess", "trojan", "shadowsocks", "hysteria"):
        return None
    ss = ob.get("streamSettings") or {}
    st = ob.get("settings") or {}
    net = (ss.get("network") or ss.get("method") or "tcp").lower()
    net = _NET_ALIAS.get(net, net)
    sec = (ss.get("security") or "none").lower()
    tls = ss.get("tlsSettings") or {}
    rl = ss.get("realitySettings") or {}
    d = dict(scheme=proto, id="", address="", port=0, net=net, security=sec,
             sni=tls.get("serverName") or rl.get("serverName") or "",
             fp=tls.get("fingerprint") or rl.get("fingerprint") or "",
             pbk=rl.get("publicKey") or "", sid=rl.get("shortId") or "",
             spx=rl.get("spiderX") or ("/" if sec == "reality" else ""),
             alpn=tls.get("alpn") or [], allow_insecure=bool(tls.get("allowInsecure")),
             flow="", host="", path="", service="", authority="", mode="",
             extra=None, header="none", aid=0, scy="", method="",
             obfs="", obfs_password="", remark=ob.get("tag", ""))
    try:
        if proto in ("vless", "vmess"):
            v = st["vnext"][0]; u = v["users"][0]
            d["address"], d["port"], d["id"] = v["address"], int(v["port"]), u["id"]
            if proto == "vless":
                d["flow"] = u.get("flow", "") if net == "tcp" else ""
            else:
                d["aid"] = int(u.get("alterId") or 0)
                d["scy"] = u.get("security") or "auto"
        elif proto == "trojan":
            s = st["servers"][0]
            d["address"], d["port"], d["id"] = s["address"], int(s["port"]), s["password"]
        elif proto == "shadowsocks":
            s = st["servers"][0]
            d.update(scheme="ss", address=s["address"], port=int(s["port"]),
                     id=s["password"], method=s["method"].lower())
        elif proto == "hysteria":
            hs = ss.get("hysteriaSettings") or {}
            d.update(scheme="hy2", address=st["address"], port=int(st["port"]),
                     id=hs.get("auth", ""), net="hysteria", security="tls",
                     obfs=hs.get("obfs", ""), obfs_password=hs.get("obfsPassword", ""))
            if not d["alpn"]:
                d["alpn"] = ["h3"]
        if net == "tcp":
            h = (ss.get("tcpSettings") or {}).get("header") or {}
            if h.get("type") == "http":
                d["header"] = "http"
                req = h.get("request") or {}
                d["path"] = (req.get("path") or ["/"])[0]
                d["host"] = ((req.get("headers") or {}).get("Host") or [""])[0]
        elif net == "ws":
            w = ss.get("wsSettings") or {}
            d["path"] = w.get("path") or "/"
            d["host"] = w.get("host") or (w.get("headers") or {}).get("Host") or ""
        elif net == "grpc":
            g = ss.get("grpcSettings") or {}
            d["service"] = g.get("serviceName", "")
            d["authority"] = g.get("authority", "")
            d["mode"] = "multi" if g.get("multiMode") else "gun"
        elif net == "h2":
            h = ss.get("httpSettings") or {}
            d["host"] = (h.get("host") or [""])[0]
            d["path"] = h.get("path") or "/"
        elif net == "httpupgrade":
            h = ss.get("httpupgradeSettings") or {}
            d["path"], d["host"] = h.get("path") or "/", h.get("host") or ""
        elif net == "xhttp":
            x = ss.get("xhttpSettings") or {}
            d["path"], d["host"] = x.get("path") or "/", x.get("host") or ""
            d["mode"] = x.get("mode") or "auto"
            d["extra"] = x.get("extra")
        if not d["address"] or not d["port"]:
            return None
        if sec == "reality" and not d["pbk"]:
            return None
        if sec == "reality" and not d["fp"]:
            d["fp"] = "chrome"
        d["raw"] = serialize(d)
        return d
    except Exception:
        return None
