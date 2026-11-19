# -*- coding: utf-8 -*-
"""Бинарник Xray: автозагрузка с GitHub, запуск инстанса на ключ, чистка процессов."""
import atexit, json, os, platform, socket, subprocess, tempfile, time, zipfile, io
import requests

import config
from core.links import build_outbound

_procs = []


def _cleanup():
    for p in list(_procs):
        try:
            p.kill()
        except Exception:
            pass


atexit.register(_cleanup)


def _asset_name():
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64-v8a"
    elif machine in ("i386", "i686", "x86"):
        arch = "32"
    else:
        raise RuntimeError(f"неизвестная архитектура: {machine}")
    osname = {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(system)
    if not osname:
        raise RuntimeError(f"неизвестная ОС: {system}")
    return f"Xray-{osname}-{arch}.zip"


def ensure_xray():
    exe = "xray.exe" if platform.system().lower() == "windows" else "xray"
    path = os.path.join(config.XRAY_DIR, exe)
    if os.path.exists(path):
        return path
    os.makedirs(config.XRAY_DIR, exist_ok=True)
    tag = "latest" if config.XRAY_VERSION == "latest" else f'tags/{config.XRAY_VERSION}'
    api = f"https://api.github.com/repos/XTLS/Xray-core/releases/{tag}"
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    rel = requests.get(api, headers=headers, timeout=30).json()
    name = _asset_name()
    asset = next(a for a in rel["assets"] if a["name"] == name)
    print(f"[xray] качаю {name} ({rel.get('tag_name')})...")
    data = requests.get(asset["browser_download_url"], timeout=120).content
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        with open(path, "wb") as f:
            f.write(z.read(exe))
    if platform.system().lower() != "windows":
        os.chmod(path, 0o755)
    return path


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def check_config(link, port):
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http",
                      "settings": {"allowTransparent": False, "timeout": 3600},
                      "tag": "in"}],
        "outbounds": [build_outbound(link, "proxy")],
    }


class Xray:
    """Один инстанс ядра на один ключ. Вся проверка — одна сессия транспорта."""

    def __init__(self, binary, cfg, port):
        fd, self.cfg_path = tempfile.mkstemp(suffix=".json", prefix="xray_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False)
        self.proc = subprocess.Popen([binary, "run", "-c", self.cfg_path],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        _procs.append(self.proc)
        deadline = time.time() + 6
        while time.time() < deadline:
            if self.proc.poll() is not None:
                err = (self.proc.stderr.read() or b"").decode("utf-8", "replace")
                raise RuntimeError("xray упал: " + err.strip()[-300:])
            try:
                socket.create_connection(("127.0.0.1", port), 0.25).close()
                return
            except OSError:
                time.sleep(0.05)
        self.stop()
        raise RuntimeError("xray не открыл порт за 6с")

    def stop(self):
        try:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        except Exception:
            pass
        if self.proc in _procs:
            _procs.remove(self.proc)
        try:
            os.unlink(self.cfg_path)
        except Exception:
            pass
