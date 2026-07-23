#!/usr/bin/env python3
"""
Lab C2 Beacon
===============
A self-contained Command-and-Control beacon + listener for the operator's
own authorized lab range. Real socket I/O over HTTP/HTTPS/DNS/TCP channels,
beacon registration, and task polling.

AUTHORIZED LAB USE ONLY.

Scope: real network I/O for beaconing and task polling. Steganographic
data hiding in third-party traffic, domain fronting against real CDNs, and
anti-forensics (timestomping/log clearing) are NOT implemented and NOT
simulated here — they appear only as ``kind=="info"`` plan text from the
orchestrator.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Old compiled-in default; used only to detect an unrotated secret and refuse
# it.  There is no safe default secret — each engagement must set its own.
_KNOWN_INSECURE_DEFAULT = "lab-secret-change-me"


def _generate_secret() -> str:
    return secrets.token_urlsafe(32)


def _require_secret(secret: str) -> str:
    """Validate that the beacon HMAC secret was explicitly set."""
    if not secret or secret == _KNOWN_INSECURE_DEFAULT:
        raise ValueError(
            "LabBeacon secret must be set to a strong, per-engagement value; "
            "the compiled-in placeholder is not allowed."
        )
    return secret


class LabBeacon:
    """Client-side beacon. Connects to a LabBeaconServer, polls for tasks."""

    def __init__(self, server: str, port: int = 8443, protocol: str = "http",
                 secret: str = "", interval: int = 5, jitter: int = 2,
                 confirm_fn: Optional[Callable] = None):
        self.server = server
        self.port = port
        self.protocol = protocol  # http | https | tcp | dns(http-tunnel)
        self.secret = _require_secret(secret)
        self.interval = interval
        self.jitter = jitter
        self.confirm_fn = confirm_fn or (lambda *_a, **_k: False)
        self.beacon_id = hashlib.sha1(
            f"{socket.gethostname()}-{os.getpid()}-{time.time()}".encode()
        ).hexdigest()[:12]
        self._stop = threading.Event()

    def _hmac(self, body: bytes) -> str:
        return hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()

    def _http_request(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        scheme = "https" if self.protocol == "https" else "http"
        url = f"{scheme}://{self.server}:{self.port}{path}"
        data = json.dumps(body).encode()
        headers = {"X-Beacon": self.beacon_id, "X-Sig": self._hmac(data)}
        r = requests.post(url, data=data, headers=headers, timeout=10,
                          verify=False)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        return r.json()

    def register(self) -> Dict[str, Any]:
        """Register the beacon with the lab C2 server. Gated by confirm_fn —
        the operator must ACCEPT before any network I/O to the server."""
        if not self.confirm_fn(
            f"Register C2 beacon with {self.server}:{self.port} ({self.protocol})?"
        ):
            return {"status": "blocked by confirm_fn"}
        body = {
            "id": self.beacon_id,
            "host": socket.gethostname(),
            "user": os.getenv("USER", "?"),
            "proto": self.protocol,
        }
        if self.protocol in ("http", "https"):
            return self._http_request("/register", body)
        # TCP fallback: send one JSON line, read one line back.
        return self._tcp_round("/register", body)

    def _tcp_round(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        try:
            with socket.create_connection((self.server, self.port), timeout=10) as s:
                payload = json.dumps({"path": path, **body}).encode()
                s.sendall(payload + b"\n")
                data = s.makefile().readline()
                return json.loads(data) if data else {"error": "empty reply"}
        except Exception as e:
            return {"error": str(e)}

    def poll_once(self) -> Dict[str, Any]:
        """Poll the server for a task. Returns the task dict or {task: none}."""
        if not self.confirm_fn(f"Beacon {self.beacon_id} poll {self.server}:{self.port}?"):
            return {"status": "blocked by confirm_fn"}
        if self.protocol in ("http", "https"):
            return self._http_request("/task", {"id": self.beacon_id})
        return self._tcp_round("/task", {"id": self.beacon_id})

    def run(self, on_task: Optional[Callable[[Dict[str, Any]], None]] = None):
        """Background poll loop until stop()."""
        while not self._stop.is_set():
            try:
                res = self.poll_once()
                if on_task and res.get("task"):
                    on_task(res)
            except Exception as e:
                logger.debug(f"beacon poll error: {e}")
            # jitter
            self._stop.wait(self.interval + (hash(self.beacon_id) % (self.jitter + 1)))

    def stop(self):
        self._stop.set()


class LabBeaconServer:
    """Minimal C2 listener for authorized lab use. HTTP + TCP.

    Registers beacons, queues tasks, and serves them on poll.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8443,
                 secret: str = ""):
        self.host = host
        self.port = port
        self.secret = _require_secret(secret)
        self.beacons: Dict[str, Dict[str, Any]] = {}
        self.task_queue: Dict[str, List[Dict[str, Any]]] = {}
        self._httpd: Optional[HTTPServer] = None
        self._tcp_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def _verify(self, body: bytes, sig: str) -> bool:
        return hmac.compare_digest(self._hmac(body), sig)

    def _hmac(self, body: bytes) -> str:
        return hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()

    def register(self, beacon: Dict[str, Any]) -> Dict[str, Any]:
        bid = beacon.get("id", "")
        self.beacons[bid] = {**beacon, "last_seen": time.time()}
        self.task_queue.setdefault(bid, [])
        logger.info("beacon registered: %s (%s)", bid, beacon.get("host"))
        return {"ok": True, "id": bid}

    def enqueue_task(self, beacon_id: str, task: Dict[str, Any]) -> bool:
        if beacon_id not in self.beacons:
            return False
        self.task_queue.setdefault(beacon_id, []).append(task)
        return True

    def next_task(self, beacon_id: str) -> Dict[str, Any]:
        q = self.task_queue.get(beacon_id, [])
        if q:
            return {"task": q.pop(0)}
        return {"task": None}

    # -- HTTP listener ----------------------------------------------------
    def _handler(self):
        server = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b"{}"
                sig = self.headers.get("X-Sig", "")
                bid = self.headers.get("X-Beacon", "")
                if not server._verify(body, sig):
                    self.send_response(401); self.end_headers(); return
                try:
                    data = json.loads(body)
                except Exception:
                    data = {}
                if self.path == "/register":
                    out = server.register(data)
                elif self.path == "/task":
                    out = server.next_task(bid)
                else:
                    out = {"error": "unknown path"}
                payload = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        return H

    def serve_http(self):
        self._httpd = HTTPServer((self.host, self.port), self._handler())
        logger.info("LabBeaconServer HTTP on %s:%d", self.host, self.port)
        self._httpd.serve_forever()

    def start(self, background: bool = True):
        if background:
            threading.Thread(target=self.serve_http, daemon=True).start()
        else:
            self.serve_http()

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
        self._stop.set()


if __name__ == "__main__":  # pragma: no cover
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    ap = argparse.ArgumentParser(description="Authorized-lab C2 beacon server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument(
        "--secret",
        default="",
        help="Per-engagement HMAC secret. If omitted a random secret is generated.",
    )
    a = ap.parse_args()
    secret = a.secret if a.secret and a.secret != _KNOWN_INSECURE_DEFAULT else _generate_secret()
    srv = LabBeaconServer(host=a.host, port=a.port, secret=secret)
    print(f"[+] LabBeaconServer on {a.host}:{a.port} (AUTHORIZED LAB USE ONLY)")
    print(f"[+] beacon secret: {secret}")
    try:
        srv.start(background=False)
    except KeyboardInterrupt:
        srv.stop()