"""core.post_access_tui.rat_ext.auth — Phase 2.4 §B.1.

Bearer-cookie auth for the RAT-like dashboard. When the dashboard
binds to ``0.0.0.0`` the operator MUST set ``RAT_DASHBOARD_TOKEN``;
the server refuses to start without it. When bound to
``127.0.0.1`` the dashboard runs without auth (the operator's
local box only).

The auth path uses a bearer cookie. The first request without
the cookie is redirected to ``/login``; the operator pastes
the token, the server validates against
``RAT_DASHBOARD_TOKEN`` env, and on success the server
sets a ``rat_dash`` cookie. Subsequent requests present
the cookie.

Brute-force protection: after 5 failed attempts in a 60s
window the server adds a 30s cooldown; attempts during the
cooldown are logged + rejected.

The token is read from env only; never inlined in source.
"""
from __future__ import annotations

import hmac
import os
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, Optional, Tuple


# Cookie name + max age (seconds)
COOKIE_NAME = "rat_dash"
COOKIE_MAX_AGE = 60 * 60 * 4  # 4 hours

# Brute-force lockout
MAX_FAILED = 5
WINDOW_S = 60
COOLDOWN_S = 30


def get_required_token() -> Optional[str]:
    """Return the bearer token from env, or None if not set."""
    return os.environ.get("RAT_DASHBOARD_TOKEN")


def is_token_required(host: str) -> bool:
    """Token is REQUIRED when the dashboard binds to a non-loopback
    address. Refuse to start without one — the operator's contract."""
    if not host:
        return False
    return host not in ("127.0.0.1", "::1", "localhost", "")


def constant_time_eq(a: Optional[str], b: Optional[str]) -> bool:
    """Constant-time string equality (avoids timing leaks)."""
    if a is None or b is None:
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class AuthState:
    """Per-server auth state. Tracks failed attempts and cooldowns."""

    def __init__(self):
        self._failed: Deque[float] = deque()
        self._cooldown_until: float = 0.0

    def is_in_cooldown(self) -> bool:
        return time.time() < self._cooldown_until

    def cooldown_remaining_s(self) -> float:
        return max(0.0, self._cooldown_until - time.time())

    def record_failure(self) -> None:
        now = time.time()
        # Drop entries outside the window
        while self._failed and now - self._failed[0] > WINDOW_S:
            self._failed.popleft()
        self._failed.append(now)
        if len(self._failed) >= MAX_FAILED:
            self._cooldown_until = now + COOLDOWN_S
            # Reset the window so the lockout doesn't keep firing
            self._failed.clear()

    def record_success(self) -> None:
        self._failed.clear()
        self._cooldown_until = 0.0

    def check_token(self, presented: Optional[str]) -> Tuple[bool, str]:
        """Validate ``presented`` against ``RAT_DASHBOARD_TOKEN``.

        Returns ``(ok, reason)``. The reason is one of:
          - "ok"
          - "cooldown" — too many recent failures
          - "missing" — no token provided
          - "mismatch" — wrong token
          - "no_server_token" — server has no RAT_DASHBOARD_TOKEN set
        """
        if self.is_in_cooldown():
            return False, "cooldown"
        server_token = get_required_token()
        if not server_token:
            return False, "no_server_token"
        if not presented:
            return False, "missing"
        if not constant_time_eq(presented, server_token):
            self.record_failure()
            return False, "mismatch"
        self.record_success()
        return True, "ok"


def parse_cookie(cookie_header: Optional[str], name: str = COOKIE_NAME
                 ) -> Optional[str]:
    """Parse a Cookie header and return the value of ``name``, or
    None if missing. Does not raise on malformed input."""
    if not cookie_header:
        return None
    for piece in cookie_header.split(";"):
        piece = piece.strip()
        if "=" not in piece:
            continue
        k, v = piece.split("=", 1)
        if k == name:
            return v
    return None


def build_login_html(error: str = "") -> bytes:
    """Render a minimal login page. No JS, no CSS framework — just
    a single form. The operator pastes their token; the server
    sets the cookie on POST /login."""
    msg = ""
    if error == "mismatch":
        msg = '<div class="err">wrong token — try again</div>'
    elif error == "cooldown":
        msg = '<div class="err">too many attempts; wait 30s</div>'
    elif error == "no_server_token":
        msg = ('<div class="err">server has no RAT_DASHBOARD_TOKEN '
               'set; refusing to authenticate</div>')
    body = (
        '<!doctype html><html><head><meta charset="utf-8"><title>'
        'KFIOSA dashboard login</title>'
        '<style>body{font-family:monospace;background:#0a0a0a;'
        'color:#e0e0e0;padding:2em;}input{background:#1a1a1a;'
        'color:#e0e0e0;border:1px solid #444;padding:0.5em;'
        'width:30em;}button{background:#3a86ff;color:#fff;'
        'border:none;padding:0.5em 1em;cursor:pointer;}'
        '.err{color:#ff6b6b;margin-top:1em;}</style></head>'
        '<body><h2>KFIOSA RAT dashboard</h2>'
        '<p>paste the bearer token from RAT_DASHBOARD_TOKEN:</p>'
        f'<form method="POST" action="/login">'
        f'<input type="password" name="token" autofocus>'
        f'<button type="submit">log in</button></form>'
        f'{msg}</body></html>'
    )
    return body.encode("utf-8")


def build_set_cookie(value: str, max_age: int = COOKIE_MAX_AGE) -> str:
    """Build a Set-Cookie header value for the rat_dash cookie."""
    return (f"{COOKIE_NAME}={value}; HttpOnly; Path=/; SameSite=Strict; "
            f"Max-Age={max_age}")


__all__ = [
    "COOKIE_NAME",
    "COOKIE_MAX_AGE",
    "MAX_FAILED",
    "WINDOW_S",
    "COOLDOWN_S",
    "get_required_token",
    "is_token_required",
    "AuthState",
    "parse_cookie",
    "build_login_html",
    "build_set_cookie",
]
