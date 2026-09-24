"""Salvage command-center: stdlib HTTP server + JSON API + the dashboard."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .carver import carve_file
from .drives import list_drives
from .engine import open_image, recover_deleted
from .exfat import free_ranges
from .inspect import inspect


def _pick_path(token: str) -> str:
    return os.path.join(tempfile.gettempdir(), f"salvage_pick_{token}.txt")


def _dialog_script(kind: str, tmp: str) -> str:
    if kind == "file":
        return (
            "Add-Type -AssemblyName System.Windows.Forms; "
            "$d = New-Object System.Windows.Forms.OpenFileDialog; "
            "$d.Filter = 'Disk images (*.dd;*.img;*.raw;*.iso)|*.dd;*.img;*.raw;*.iso|All files (*.*)|*.*'; "
            "if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { "
            f"Set-Content -LiteralPath '{tmp}' -Value $d.FileName -Encoding UTF8 }}"
        )
    return (
        "Add-Type -AssemblyName System.Windows.Forms; "
        "$d = New-Object System.Windows.Forms.FolderBrowserDialog; "
        "$d.Description = 'Select output folder'; "
        "if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { "
        f"Set-Content -LiteralPath '{tmp}' -Value $d.SelectedPath -Encoding UTF8 }}"
    )


def _start_pick(kind: str, token: str) -> None:
    """Launch a native dialog (folder or file) in a DETACHED process (non-blocking).
    It writes its result to a temp file; the server never waits on it."""
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-Command", _dialog_script(kind, _pick_path(token))],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        pass


def _pick_result(token: str) -> str:
    tmp = _pick_path(token)
    if not os.path.exists(tmp):
        return ""
    try:
        with open(tmp, encoding="utf-8") as fh:
            return fh.read().strip()
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass


def _resource_root() -> Path:
    # PyInstaller onefile extracts bundled files to sys._MEIPASS at runtime.
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


ROOT = _resource_root()
DASH = ROOT / "dashboard"

# Background-scan state: recover runs in a thread and reports progress here, so
# the dashboard can poll /api/progress instead of blocking for 20+ minutes.
SCAN_STATE = {
    "running": False, "deep": False, "scanned": 0, "total": None, "pct": None,
    "found": 0, "done": False, "files": [], "out": "", "error": None,
    "started_at": None, "elapsed": 0, "rate": None, "remaining": None,
    "cancel": False, "stalled": False, "last_progress_at": None,
}
_SCAN_LOCK = threading.Lock()

STALL_SECONDS = 300            # no byte progress for this long => mark stalled + auto-cancel
MAX_SCAN_SECONDS = 12 * 3600   # hard cap — abort any scan that runs past this


def _cancel_requested() -> bool:
    with _SCAN_LOCK:
        return bool(SCAN_STATE.get("cancel"))

# Targeted-scan type map: UI key -> set of sniffed extensions to keep.
TYPE_EXTENSIONS = {
    "png": {".png"},
    "jpg": {".jpg"},
    "gif": {".gif"},
    "pdf": {".pdf"},
    "doc": {".doc"},
    "office": {".zip"},      # docx/xlsx/pptx are zip containers
    "zip": {".zip"},
    "mp3": {".mp3", ".ogg"},
    "wav": {".wav"},
    "mp4": {".mp4"},
    "exe": {".exe"},
}


def _run_recover(image: str, out: str, offset: int, deep: bool, types) -> None:
    with _SCAN_LOCK:
        SCAN_STATE.update(running=True, deep=deep, scanned=0, total=None, pct=None,
                          found=0, done=False, files=[], out=out, error=None,
                          started_at=time.time(), cancel=False, stalled=False,
                          last_progress_at=time.time())

    def walk_progress(dirs: int, found: int) -> None:
        # Enumeration pass: we know how many dirs we've walked, but not yet how
        # many bytes are coming, so the bar stays indeterminate here.
        with _SCAN_LOCK:
            SCAN_STATE["scanned"] = dirs
            SCAN_STATE["found"] = found
            SCAN_STATE["total"] = None
            SCAN_STATE["pct"] = None
            SCAN_STATE["last_progress_at"] = time.time()

    def recover_progress(bytes_done: int, total: int, found: int) -> None:
        # Recovery pass: bytes_done/total drives an accurate rate + time-remaining.
        with _SCAN_LOCK:
            SCAN_STATE["scanned"] = bytes_done
            SCAN_STATE["total"] = total
            SCAN_STATE["found"] = found
            SCAN_STATE["pct"] = round(100.0 * bytes_done / total, 1) if total else None
            SCAN_STATE["last_progress_at"] = time.time()

    try:
        img = open_image(image)
        found = recover_deleted(img, out, fs_offset=offset, deep=deep,
                                progress=walk_progress,
                                recover_progress=recover_progress, types=types,
                                cancel=_cancel_requested,
                                deadline=time.time() + MAX_SCAN_SECONDS)
        with _SCAN_LOCK:
            SCAN_STATE.update(running=False, done=True, files=found, found=len(found))
    except Exception as exc:
        with _SCAN_LOCK:
            SCAN_STATE.update(running=False, done=True, error=str(exc))


def _run_carve(image: str, out: str, deleted_only: bool = False) -> None:
    with _SCAN_LOCK:
        SCAN_STATE.update(running=True, deep=False, scanned=0, total=0, pct=0,
                          found=0, done=False, files=[], out=out, error=None,
                          started_at=time.time(), cancel=False, stalled=False,
                          last_progress_at=time.time())

    def progress(bytes_done: int, total: int, found_count: int) -> None:
        with _SCAN_LOCK:
            SCAN_STATE["scanned"] = bytes_done
            SCAN_STATE["total"] = total
            SCAN_STATE["found"] = found_count
            SCAN_STATE["pct"] = round(100.0 * bytes_done / total, 1) if total else 0
            SCAN_STATE["last_progress_at"] = time.time()

    # Deleted-only carve: restrict the scan to unallocated (free) space on exFAT,
    # which is where deleted files' data lives. Fall back to a full carve if the
    # source isn't exFAT or the free-space map can't be read.
    ranges = None
    if deleted_only:
        try:
            ranges = free_ranges(open_image(image))
        except Exception:
            ranges = None

    try:
        found = carve_file(image, out, progress=progress, cancel=_cancel_requested,
                           ranges=ranges, deadline=time.time() + MAX_SCAN_SECONDS)
        with _SCAN_LOCK:
            SCAN_STATE.update(running=False, done=True, files=found, found=len(found))
    except Exception as exc:
        with _SCAN_LOCK:
            SCAN_STATE.update(running=False, done=True, error=str(exc))


def _watchdog() -> None:
    """Daemon that auto-cancels a scan that has stopped making progress, so a
    wedged raw-device read can't run forever."""
    while True:
        time.sleep(15)
        with _SCAN_LOCK:
            if SCAN_STATE["running"] and SCAN_STATE.get("last_progress_at"):
                if time.time() - SCAN_STATE["last_progress_at"] > STALL_SECONDS:
                    SCAN_STATE["stalled"] = True
                    SCAN_STATE["cancel"] = True


def _json(handler, code, obj):
    body = json.dumps(obj).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self._serve_file(DASH / "index.html", "text/html")
        if self.path == "/api/status":
            return _json(self, 200, {"ok": True, "app": "salvage", "version": "0.1.0"})
        if self.path == "/api/drives":
            return _json(self, 200, {"ok": True, "drives": list_drives()})
        if self.path == "/api/progress":
            with _SCAN_LOCK:
                s = dict(SCAN_STATE)
            # Time elapsed + estimated time remaining, from the byte rate so far.
            s["elapsed"] = 0
            s["rate"] = None
            s["remaining"] = None
            if s.get("started_at"):
                s["elapsed"] = time.time() - s["started_at"]
                if s["elapsed"] > 0 and s.get("scanned") and s.get("total"):
                    s["rate"] = s["scanned"] / s["elapsed"]
                    left = s["total"] - s["scanned"]
                    if s["rate"] > 0:
                        s["remaining"] = left / s["rate"]
            return _json(self, 200, {"ok": True, **s})
        if self.path.startswith("/api/pick-folder-result/"):
            token = self.path.rsplit("/", 1)[-1]
            path = _pick_result(token)
            return _json(self, 200, {"ok": True, "path": path, "ready": bool(path)})
        if self.path.startswith("/api/pick-file-result/"):
            token = self.path.rsplit("/", 1)[-1]
            path = _pick_result(token)
            return _json(self, 200, {"ok": True, "path": path, "ready": bool(path)})
        return _json(self, 404, {"ok": False, "error": "not found"})

    def do_POST(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        except Exception:
            return _json(self, 400, {"ok": False, "error": "bad json"})

        if self.path == "/api/carve":
            return self._carve(body)
        if self.path == "/api/recover":
            return self._recover(body)
        if self.path == "/api/inspect":
            return self._inspect(body)
        if self.path == "/api/scan":
            return self._scan(body)
        if self.path == "/api/cancel":
            with _SCAN_LOCK:
                if SCAN_STATE["running"]:
                    SCAN_STATE["cancel"] = True
            return _json(self, 200, {"ok": True})
        if self.path == "/api/pick-folder":
            token = uuid.uuid4().hex
            _start_pick("folder", token)
            return _json(self, 200, {"ok": True, "token": token})
        if self.path == "/api/pick-file":
            token = uuid.uuid4().hex
            _start_pick("file", token)
            return _json(self, 200, {"ok": True, "token": token})
        return _json(self, 404, {"ok": False, "error": "not found"})

    def _carve(self, body):
        image = body.get("image", "")
        out = body.get("out", "")
        deleted_only = bool(body.get("deleted_only", False))
        if not image or not out:
            return _json(self, 400, {"ok": False, "error": "image and out are required"})
        if not os.path.exists(image):
            return _json(self, 404, {"ok": False, "error": f"image not found: {image}"})
        with _SCAN_LOCK:
            if SCAN_STATE["running"]:
                return _json(self, 409, {"ok": False, "error": "a scan is already running"})
        threading.Thread(target=_run_carve, args=(image, out, deleted_only), daemon=True).start()
        return _json(self, 200, {"ok": True, "started": True})

    def _recover(self, body):
        image = body.get("image", "")
        out = body.get("out", "")
        offset = int(body.get("offset", 0) or 0)
        scanmode = body.get("scanmode", "quick")
        deep = scanmode in ("full", "targeted")
        # Targeted scan: map selected type keys to the sniffed extensions to keep.
        extensions = None
        if scanmode == "targeted":
            ext = set()
            for k in (body.get("types", []) or []):
                ext |= TYPE_EXTENSIONS.get(k, set())
            extensions = ext or None
        if not image or not out:
            return _json(self, 400, {"ok": False, "error": "image and out are required"})
        if not os.path.exists(image):
            return _json(self, 404, {"ok": False, "error": f"image not found: {image}"})
        with _SCAN_LOCK:
            if SCAN_STATE["running"]:
                return _json(self, 409, {"ok": False, "error": "a scan is already running"})
        threading.Thread(target=_run_recover, args=(image, out, offset, deep, extensions), daemon=True).start()
        return _json(self, 200, {"ok": True, "started": True})

    def _inspect(self, body):
        path = body.get("path", "")
        if not path:
            return _json(self, 400, {"ok": False, "error": "path is required"})
        if not os.path.exists(path):
            return _json(self, 404, {"ok": False, "error": f"not found: {path}"})
        try:
            return _json(self, 200, {"ok": True, "info": inspect(path)})
        except Exception as exc:
            return _json(self, 500, {"ok": False, "error": str(exc)})

    def _scan(self, body):
        path = body.get("path", "")
        if not path:
            return _json(self, 400, {"ok": False, "error": "path is required"})
        path = os.path.abspath(path)
        if not os.path.exists(path):
            return _json(self, 404, {"ok": False, "error": f"not found: {path}"})
        mp = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
        if not os.path.exists(mp):
            return _json(self, 400, {"ok": False, "error": "Windows Defender MpCmdRun.exe not found"})
        # Report-only scan (-DisableRemediation): identify, never delete/quarantine.
        cmd = ["powershell", "-NoProfile", "-Command",
               f"& '{mp}' -Scan -ScanType 3 -File '{path}' -DisableRemediation"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            return _json(self, 200, {"ok": True, "clean": None,
                                     "output": "scan still running (timed out waiting)"})
        except Exception as exc:
            return _json(self, 500, {"ok": False, "error": str(exc)})
        out = (r.stdout or "") + (r.stderr or "")
        low = out.lower()
        rc = r.returncode
        if rc == 0:
            status = "clean"                       # MpCmdRun exit 0 = no threats
        elif rc == 2 or ("threat" in low and "no threats detected" not in low):
            status = "threats"                     # MpCmdRun exit 2 = threat found
        else:
            status = "error"                       # scan failed — NOT the same as a threat
        return _json(self, 200, {"ok": True, "status": status, "output": out.strip()[:4000]})

    def _serve_file(self, path, ctype):
        if not path.exists():
            return _json(self, 404, {"ok": False, "error": "not found"})
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(host="127.0.0.1", port=8900):
    # Bind the first free port in 8900..8909 so a stale copy can't wedge us.
    srv = None
    for p in range(port, port + 10):
        try:
            srv = ThreadingHTTPServer((host, p), Handler)
            port = p
            break
        except OSError:
            continue
    if srv is None:
        print("ERROR: ports 8900-8909 are all in use.")
        print("Close other Salvage windows and try again.")
        input("Press Enter to close this window...")
        return
    url = f"http://{host}:{port}"
    print(f"Salvage is running — your browser should open {url}")
    print("If it doesn't, open that address manually. Keep this window open.")
    try:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    except Exception:
        pass
    threading.Thread(target=_watchdog, daemon=True, name="salvage-watchdog").start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
