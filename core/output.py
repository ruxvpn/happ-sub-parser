# -*- coding: utf-8 -*-
"""Выгрузка: work.txt / unknow.txt / dead.txt / subwork.json / subwork_raw.txt.
subwork.json — массив полных Xray-конфигов, по одному на страну (формат Happ,
как format=json у vexaloria-воркера): outbounds + observatory + leastPing."""
import base64, json
from collections import defaultdict

import config
from core.links import serialize, build_outbound
from core.geo import flag, ru_name, en_name

RU_DOMAINS = [
    "geosite:category-ru", "regexp:.(ru|su|xn--p1ai)$",
    "gosuslugi.ru", "mos.ru", "nalog.ru", "sberbank.ru", "sber.ru", "tinkoff.ru",
    "tbank.ru", "vtb.ru", "alfabank.ru", "yoomoney.ru", "ozon.ru", "wildberries.ru",
    "avito.ru", "yandex.ru", "ya.ru", "vk.com", "ok.ru", "rutube.ru", "dzen.ru",
    "kinopoisk.ru", "max.ru", "rustore.ru", "hh.ru", "2gis.ru", "rzd.ru",
]


def group_by_country(results):
    g = defaultdict(list)
    for r in results:
        g[r["cc"]].append(r)
    for cc in g:
        g[cc].sort(key=lambda r: r["ping"] if r["ping"] is not None else 9e9)
    return dict(sorted(g.items(), key=lambda kv: ru_name(kv[0])))


def enriched_link(r, idx):
    d = dict(r["link"])
    d["remark"] = (f'{flag(r["cc"])} {en_name(r["cc"])} {idx} | '
                   f'↓{r["down"]:.1f} ↑{r["up"]:.1f} MB/s | {r["ping"]:.0f} ms')
    return serialize(d)


def _write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def write_work(results, path):
    groups = group_by_country(results)
    lines = []
    for cc, items in groups.items():
        for i, r in enumerate(items, 1):
            lines.append(enriched_link(r, i))
    _write_lines(path, lines)


def write_plain(results, path):
    _write_lines(path, [r["link"].get("raw") or serialize(r["link"]) for r in results])


def write_dead(results, path):
    _write_lines(path, [f'{r["link"].get("raw", "")}  # {r["stage"]}: {r["error"]}'
                        for r in results])


def build_country_json(results):
    groups = group_by_country(results)
    configs = []
    for cc, items in groups.items():
        prefix = f"{cc.lower()}-g-"
        outbounds = [build_outbound(r["link"], f"{prefix}{i:03d}")
                     for i, r in enumerate(items, 1)]
        outbounds += [{"protocol": "freedom", "tag": "direct"},
                      {"protocol": "blackhole", "tag": "block"}]
        rules = [
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
        ]
        if config.INCLUDE_RU_BYPASS:
            rules.append({"type": "field", "domain": RU_DOMAINS, "outboundTag": "direct"})
            rules.append({"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"})
        rules.append({"type": "field", "network": "tcp,udp", "balancerTag": prefix + "balancer"})
        configs.append({
            "remarks": f'{flag(cc)} {ru_name(cc)} | {config.BRAND}',
            "log": {"loglevel": "warning"},
            "dns": {"queryStrategy": "UseIP",
                    "servers": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]},
            "inbounds": [
                {"listen": "127.0.0.1", "port": 10808, "protocol": "socks",
                 "settings": {"auth": "noauth", "udp": True},
                 "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
                 "tag": "socks"},
                {"listen": "127.0.0.1", "port": 10809, "protocol": "http",
                 "settings": {"allowTransparent": False},
                 "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
                 "tag": "http"},
            ],
            "outbounds": outbounds,
            "observatory": {"subjectSelector": [prefix],
                            "probeUrl": "https://www.gstatic.com/generate_204",
                            "probeInterval": "5m", "enableConcurrency": True},
            "routing": {"domainMatcher": "hybrid", "domainStrategy": "IPIfNonMatch",
                        "rules": rules,
                        "balancers": [{"tag": prefix + "balancer", "selector": [prefix],
                                       "strategy": {"type": "leastPing"}}]},
        })
    return configs


def write_json(results, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(build_country_json(results), f, ensure_ascii=False, indent=2)


def write_raw(results, path):
    groups = group_by_country(results)
    lines = []
    for cc, items in groups.items():
        for i, r in enumerate(items, 1):
            d = dict(r["link"])
            d["remark"] = f'{flag(cc)} {en_name(cc)} {i} | {config.BRAND}'
            lines.append(serialize(d))
    blob = base64.b64encode("\n".join(lines).encode("utf-8")).decode("ascii")
    with open(path, "w", encoding="utf-8") as f:
        f.write(blob + "\n")
