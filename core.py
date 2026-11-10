"""Shared helpers: configuration, Malaysian phone numbers, rate limits, SMS."""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections import defaultdict, deque

from flask import request

log = logging.getLogger("debtsms")
logging.basicConfig(level=logging.INFO)

SMS_PROVIDER = os.environ.get("SMS_PROVIDER", "console").lower()
APP_NAME = os.environ.get("APP_NAME", "DebtSMS")

# --- Phone numbers -----------------------------------------------------------

# Malaysian mobile numbers: 011-xxxx xxxx (8 digits after 11), or
# 010/012-019-xxx xxxx (7 digits after the prefix). Stored as E.164.
_MY_MOBILE = re.compile(r"^\+60(11\d{8}|1[02-9]\d{7})$")


def normalize_my_phone(raw: str) -> str | None:
    """Return the number in E.164 (+601...) form, or None if not a MY mobile."""
    digits = re.sub(r"[\s\-().]", "", raw or "")
    if digits.startswith("+60"):
        e164 = digits
    elif digits.startswith("60"):
        e164 = "+" + digits
    elif digits.startswith("0"):
        e164 = "+6" + digits
    else:
        return None
    return e164 if _MY_MOBILE.match(e164) else None


def mask_phone(e164: str) -> str:
    return e164[:5] + "*" * (len(e164) - 8) + e164[-3:]


# --- Rate limiting -----------------------------------------------------------


class RateStore:
    """Thread-safe sliding-window counters keyed by arbitrary strings."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, window: float, now: float) -> deque[float]:
        q = self._events[key]
        while q and now - q[0] > window:
            q.popleft()
        return q

    def check(self, key: str, limit: int, window: float) -> tuple[bool, int]:
        """Return (allowed, seconds_until_allowed) without recording."""
        now = time.time()
        with self._lock:
            q = self._prune(key, window, now)
            if len(q) < limit:
                return True, 0
            return False, int(window - (now - q[0])) + 1

    def hit(self, key: str) -> None:
        with self._lock:
            self._events[key].append(time.time())


rates = RateStore()


def client_ip() -> str:
    # Only trust X-Forwarded-For if you deploy behind a proxy you control
    # (then wrap the app with werkzeug.middleware.proxy_fix.ProxyFix instead).
    return request.remote_addr or "unknown"


# --- SMS providers -----------------------------------------------------------


def send_sms(to_e164: str, body: str) -> None:
    if SMS_PROVIDER == "console":
        # Development only: prints the message instead of sending it.
        log.warning("[console SMS] to=%s body=%r", to_e164, body)
        return
    if SMS_PROVIDER == "twilio":
        from twilio.rest import Client  # imported lazily; optional dependency

        client = Client(os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"])
        client.messages.create(to=to_e164, from_=os.environ["TWILIO_FROM"], body=body)
        return
    raise RuntimeError(f"Unknown SMS_PROVIDER: {SMS_PROVIDER!r}")
