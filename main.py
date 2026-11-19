# -*- coding: utf-8 -*-
"""Happ Sub Parser: subs.txt -> сбор -> дедуп -> ping(keepAlive)+speed+geo ->
work.txt / unknow.txt -> перепроверка -> subwork.json (+ subwork_raw.txt)."""
import sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
from core.fetcher import fetch_subscription
from core.links import canon_key
from core.xray import ensure_xray
from core.checker import check
from core import output
from core.geo import flag, en_name

_lock = threading.Lock()


def log(msg):
    with _lock:
        print(msg, flush=True)


def load_subs():
    try:
        with open(config.SUBS_FILE, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except FileNotFoundError:
        log(f"нет файла {config.SUBS_FILE}")
        return []


def collect(subs):
    seen, links, total = set(), [], 0
    for url in subs:
        try:
            got, bad = fetch_subscription(url)
        except Exception as e:
            log(f"[sub] ❌ {url[:80]} -> {type(e).__name__}: {str(e)[:120]}")
            continue
        total += len(got)
        added = 0
        for d in got:
            k = canon_key(d)
            if k not in seen:
                seen.add(k)
                links.append(d)
                added += 1
        log(f"[sub] {url[:80]}: {len(got)} ключей (+{added} новых, {bad} битых)")
    log(f"[sub] всего {total}, после дедупа {len(links)}")
    return links


def run_pass(links, binary, quick=False, label="check"):
    results, n, done, t0 = [], len(links), 0, time.time()
    with ThreadPoolExecutor(max_workers=config.THREADS) as ex:
        futs = [ex.submit(check, d, binary, quick) for d in links]
        try:
            for fut in as_completed(futs):
                r = fut.result()
                results.append(r)
                done += 1
                d = r["link"]
                hp = f'{d["address"]}:{d["port"]}'
                if r["ok"]:
                    log(f'[{label} {done}/{n}] ✅ {flag(r["cc"])} {r["cc"]} {hp} '
                        f'{r["ping"]:.0f}ms ↓{r["down"]} ↑{r["up"]} MB/s')
                elif r["unknown"]:
                    log(f"[{label} {done}/{n}] ❓ {hp} быстрый, но гео неизвестно")
                else:
                    log(f'[{label} {done}/{n}] ❌ {hp} [{r["stage"]}] {r["error"][:100]}')
        except KeyboardInterrupt:
            log("останавливаюсь, гашу xray-процессы...")
            ex.shutdown(wait=False, cancel_futures=True)
            raise
    log(f"[{label}] готово за {time.time() - t0:.0f}с")
    return results


def main():
    log("=== HAPP SUB PARSER ===")
    subs = load_subs()
    if not subs:
        return
    binary = ensure_xray()
    links = collect(subs)
    if not links:
        log("нечего проверять")
        return

    results = run_pass(links, binary, label="check")
    ok = [r for r in results if r["ok"]]
    unknown = [r for r in results if r["unknown"]]
    dead = [r for r in results if not r["ok"] and not r["unknown"]]

    for r in ok:  # кэш гео для перепроверки
        r["link"]["_cc"], r["link"]["_city"], r["link"]["_ip"] = r["cc"], r["city"], r["ip"]

    output.write_work(ok, config.WORK_FILE)
    output.write_plain(unknown, config.UNKNOWN_FILE)
    output.write_dead(dead, config.DEAD_FILE)
    log(f"[pass1] рабочих {len(ok)}, без гео {len(unknown)}, дохлых {len(dead)}")

    confirmed = ok
    if config.RECHECK and ok:
        log(f"=== перепроверка {len(ok)} рабочих ===")
        results2 = run_pass([r["link"] for r in ok], binary, quick=True, label="recheck")
        confirmed = [r for r in results2 if r["ok"]]
        failed = [r for r in results2 if not r["ok"]]
        for r in failed:
            r["stage"] = "recheck:" + r["stage"]
        dead += failed
        output.write_work(confirmed, config.WORK_FILE)
        output.write_dead(dead, config.DEAD_FILE)
        log(f"[recheck] подтверждено {len(confirmed)}, отвалилось {len(failed)}")

    output.write_json(confirmed, config.JSON_FILE)
    output.write_raw(confirmed, config.RAW_FILE)

    groups = output.group_by_country(confirmed)
    log("=== ИТОГ ===")
    for cc, items in groups.items():
        log(f"{flag(cc)} {en_name(cc)}: {len(items)}")
    log(f"subwork.json: {len(confirmed)} ключей / {len(groups)} стран")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
