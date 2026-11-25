#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PluginVault — локальний каталог музичних плагінів.

  python3 pluginvault.py serve            відкрити веб-інтерфейс (за замовчуванням)
  python3 pluginvault.py scan [--mode standard|full]
  python3 pluginvault.py schedule install|remove|status
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pv_core as core

PORT = int(os.environ.get("PLUGINVAULT_PORT", "8765"))
UI_PATH = os.path.join(core.APP_DIR, "ui.html")
ALLOWED_HOSTS = None  # заповнюється під час старту


def get_mode(con):
    return core.get_setting(con, "scan_mode", "full")


def start_scan_thread(mode, trigger="manual"):
    if core.STATE["running"]:
        return False

    def run():
        try:
            core.scan(mode=mode, trigger=trigger)
        except Exception as ex:  # помилку показуємо в інтерфейсі
            core.STATE["error"] = str(ex)

    threading.Thread(target=run, daemon=True).start()
    time.sleep(0.05)
    return True


class Handler(BaseHTTPRequestHandler):
    server_version = "PluginVault/" + core.VERSION

    def log_message(self, fmt, *args):
        pass

    # --- допоміжні
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, dict) and isinstance(body.get("error"), str):
            body = dict(body, error=core.tr(body["error"], self._lang()))
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _lang(self):
        return core.lang_of(urlparse(self.path).query)

    def _host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        return host in ("127.0.0.1", "localhost")

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except ValueError:
            return None

    def _guard_write(self):
        if not self._host_ok():
            self._send(403, {"error": "forbidden host"})
            return False
        ct = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ct != "application/json":
            self._send(415, {"error": "потрібен application/json"})
            return False
        origin = self.headers.get("Origin")
        if origin:
            h = urlparse(origin).hostname
            if h not in ("127.0.0.1", "localhost"):
                self._send(403, {"error": "forbidden origin"})
                return False
        return True

    # --- GET
    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "forbidden host"})
        path, lang = urlparse(self.path).path, self._lang()
        try:
            if path in ("/", "/index.html"):
                with open(UI_PATH, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if path == "/api/ping":
                return self._send(200, {"app": "pluginvault", "version": core.VERSION})
            con = core.connect()
            try:
                if path == "/api/plugins":
                    return self._send(200, core.localize(core.list_plugins(con), lang))
                if path == "/api/products":
                    return self._send(200, core.localize(core.list_products(con), lang))
                if path == "/api/status":
                    st = dict(core.STATE)
                    st["last_scan_at"] = core.get_setting(con, "last_scan_at", "")
                    st["scan_mode"] = get_mode(con)
                    st["mac_setup_at"] = core.get_setting(con, "mac_setup_at", "")
                    st["schedule"] = core.schedule_status()
                    st["home"] = core.HOME
                    st["version"] = core.VERSION
                    st["is_mac"] = core.IS_MAC
                    st["plugin_count"] = con.execute("SELECT COUNT(*) FROM plugins").fetchone()[0]
                    return self._send(200, core.localize_status(st, lang))
                if path == "/api/history":
                    return self._send(200, core.localize_history(core.history(con), lang))
                if path == "/api/export.csv":
                    data = core.export_csv(con, lang=lang)
                    return self._send(200, data, "text/csv; charset=utf-8",
                                      {"Content-Disposition": 'attachment; filename="pluginvault.csv"'})
            finally:
                con.close()
            self._send(404, {"error": "not found"})
        except Exception as ex:
            self._send(500, {"error": str(ex)})

    # --- POST / PATCH
    def do_POST(self):
        if not self._guard_write():
            return
        path = urlparse(self.path).path
        data = self._body()
        if data is None:
            return self._send(400, {"error": "некоректний JSON"})
        try:
            if path == "/api/scan":
                con = core.connect()
                try:
                    mode = data.get("mode") or get_mode(con)
                finally:
                    con.close()
                if mode not in ("standard", "full"):
                    return self._send(400, {"error": "невідомий режим"})
                ok = start_scan_thread(mode)
                return self._send(200 if ok else 409, {"started": ok})
            if path == "/api/ack-new":
                con = core.connect()
                try:
                    con.execute("UPDATE plugins SET is_new=0 WHERE is_new=1")
                    con.commit()
                finally:
                    con.close()
                return self._send(200, {"ok": True})
            if path == "/api/scan/cancel":
                core.STATE["cancel"] = True
                return self._send(200, {"ok": True})
            if path == "/api/settings":
                con = core.connect()
                try:
                    if data.get("scan_mode") in ("standard", "full"):
                        core.set_setting(con, "scan_mode", data["scan_mode"])
                finally:
                    con.close()
                return self._send(200, {"ok": True})
            if path == "/api/schedule":
                res = core.schedule_install() if data.get("enable") else core.schedule_remove()
                res["status"] = core.schedule_status()
                return self._send(200 if res.get("ok") else 500, res)
            if path == "/api/reveal":
                con = core.connect()
                try:
                    r = con.execute("SELECT path FROM plugins WHERE id=?", (int(data.get("id", 0)),)).fetchone()
                finally:
                    con.close()
                if not r:
                    return self._send(404, {"error": "не знайдено"})
                if not core.IS_MAC:
                    return self._send(400, {"error": "Показ у Finder працює лише на macOS"})
                if not os.path.exists(r["path"]):
                    return self._send(404, {"error": "файл більше не існує"})
                subprocess.Popen(["open", "-R", r["path"]])
                return self._send(200, {"ok": True})
            if path == "/api/quit":
                self._send(200, {"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            self._send(404, {"error": "not found"})
        except Exception as ex:
            self._send(500, {"error": str(ex)})

    def do_PATCH(self):
        if not self._guard_write():
            return
        path = urlparse(self.path).path
        data = self._body()
        if not isinstance(data, dict):
            return self._send(400, {"error": "некоректний JSON"})
        try:
            if path.startswith("/api/products/"):
                pid = int(path.rsplit("/", 1)[1])
                con = core.connect()
                try:
                    ok = core.update_product(con, pid, data)
                    p = core.product_of(con, pid)
                    p = p and core.localize([p], self._lang())[0]
                    return self._send(200 if ok else 404, p if ok else {"error": "не знайдено"})
                finally:
                    con.close()
            if path.startswith("/api/plugins/"):
                pid = int(path.rsplit("/", 1)[1])
                con = core.connect()
                try:
                    ok = core.update_manual(con, pid, data)
                    row = con.execute("SELECT * FROM plugins WHERE id=?", (pid,)).fetchone()
                    return self._send(200 if ok else 404, core.localize([core.row_to_dict(row)], self._lang())[0] if row else {"error": "не знайдено"})
                finally:
                    con.close()
            self._send(404, {"error": "not found"})
        except Exception as ex:
            self._send(500, {"error": str(ex)})


def cmd_serve(args):
    core.ensure_home()
    core.connect().close()
    url = "http://127.0.0.1:%d/" % PORT
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    except OSError:
        # можливо, уже запущено
        try:
            import urllib.request
            with urllib.request.urlopen(url + "api/ping", timeout=2) as r:
                if b"pluginvault" in r.read():
                    print("Plugius уже запущено — відкриваю браузер.")
                    if not args.no_browser:
                        webbrowser.open(url)
                    return 0
        except Exception:
            pass
        print("Порт %d зайнятий іншою програмою. Задайте інший: PLUGINVAULT_PORT=8800" % PORT)
        return 1
    print("Plugius працює: %s\nДані: %s\nЗавершити: Ctrl+C або кнопка «Вимкнути» в застосунку." % (url, core.HOME))
    # автоматичний перший скан, якщо база порожня
    con = core.connect()
    first = con.execute("SELECT COUNT(*) FROM plugins").fetchone()[0] == 0
    never = not core.get_setting(con, "last_scan_at")
    con.close()
    if first and never and not args.no_autoscan:
        start_scan_thread("standard", "first-run")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    srv.server_close()
    return 0


def cmd_scan(args):
    core.ensure_home()
    con = core.connect()
    mode = args.mode or get_mode(con)
    con.close()
    if not args.quiet:
        print("Сканування (%s)…" % mode)
    res = core.scan(mode=mode, trigger=args.trigger)
    print(json.dumps(res, ensure_ascii=False))
    return 0 if "error" not in res else 1


def cmd_schedule(args):
    if args.action == "install":
        print(json.dumps(core.schedule_install(), ensure_ascii=False))
    elif args.action == "remove":
        print(json.dumps(core.schedule_remove(), ensure_ascii=False))
    else:
        print(json.dumps(core.schedule_status(), ensure_ascii=False))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pluginvault")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("serve")
    s.add_argument("--no-browser", action="store_true")
    s.add_argument("--no-autoscan", action="store_true")
    sc = sub.add_parser("scan")
    sc.add_argument("--mode", choices=["standard", "full"])
    sc.add_argument("--trigger", default="manual")
    sc.add_argument("--quiet", action="store_true")
    sh = sub.add_parser("schedule")
    sh.add_argument("action", choices=["install", "remove", "status"])
    args = ap.parse_args(argv)
    if args.cmd in (None, "serve"):
        if args.cmd is None:
            args.no_browser = False
            args.no_autoscan = False
        return cmd_serve(args)
    if args.cmd == "scan":
        return cmd_scan(args)
    return cmd_schedule(args)


if __name__ == "__main__":
    sys.exit(main())
