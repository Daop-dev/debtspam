"""Malaysian phone number OTP verification (Flask).

One OTP flow per browser session: the user enters a Malaysian mobile number,
confirms consent, receives a one-time code by SMS and enters it to verify.

Abuse protections (so the /send endpoint cannot be used to flood a number):
  * consent checkbox and CSRF token required on every POST
  * resend cooldown per phone number
  * hourly cap per phone number and per client IP
  * limited verification attempts per code, codes expire
  * codes are stored only as salted HMACs, compared in constant time

Rate-limit state is kept in process memory, so run a single worker process
(or swap ``RateStore`` for Redis) when deploying.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect

log = logging.getLogger("otp")
logging.basicConfig(level=logging.INFO)

# --- Configuration -----------------------------------------------------------

OTP_LENGTH = int(os.environ.get("OTP_LENGTH", 6))
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 300))
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", 5))
RESEND_COOLDOWN_SECONDS = int(os.environ.get("RESEND_COOLDOWN_SECONDS", 60))
MAX_SENDS_PER_PHONE_PER_HOUR = int(os.environ.get("MAX_SENDS_PER_PHONE_PER_HOUR", 3))
MAX_SENDS_PER_IP_PER_HOUR = int(os.environ.get("MAX_SENDS_PER_IP_PER_HOUR", 5))
SMS_PROVIDER = os.environ.get("SMS_PROVIDER", "console").lower()
APP_NAME = os.environ.get("APP_NAME", "DebtSMS")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") == "1",
)
csrf = CSRFProtect(app)

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


# --- OTP codes ---------------------------------------------------------------


def generate_code() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(OTP_LENGTH))


def hash_code(code: str, salt: str) -> str:
    key = app.config["SECRET_KEY"].encode()
    return hmac.new(key, f"{salt}:{code}".encode(), hashlib.sha256).hexdigest()


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


# --- Routes ------------------------------------------------------------------


def _pending() -> dict | None:
    otp = session.get("otp")
    if otp and time.time() < otp["expires"]:
        return otp
    return None


@app.get("/")
def index():
    pending = _pending()
    return render_template(
        "index.html",
        pending=bool(pending),
        phone=session.get("phone_input", ""),
    )


@app.post("/send")
def send():
    raw = request.form.get("phone", "").strip()
    session["phone_input"] = raw[:20]

    if request.form.get("consent") != "yes":
        flash("Please confirm you own or are authorized to use this number.", "error")
        return redirect(url_for("index"))

    phone = normalize_my_phone(raw)
    if not phone:
        flash("Enter a valid Malaysian mobile number (e.g. 0123456789).", "error")
        return redirect(url_for("index"))

    checks = [
        (f"cooldown:{phone}", 1, RESEND_COOLDOWN_SECONDS),
        (f"phone:{phone}", MAX_SENDS_PER_PHONE_PER_HOUR, 3600),
        (f"ip:{client_ip()}", MAX_SENDS_PER_IP_PER_HOUR, 3600),
    ]
    for key, limit, window in checks:
        allowed, wait = rates.check(key, limit, window)
        if not allowed:
            flash(f"Too many requests. Please try again in {wait} seconds.", "error")
            return redirect(url_for("index"))

    code = generate_code()
    salt = secrets.token_hex(8)
    minutes = max(1, OTP_TTL_SECONDS // 60)
    try:
        send_sms(
            phone,
            f"{APP_NAME}: your verification code is {code}. "
            f"It expires in {minutes} min. Do not share this code.",
        )
    except Exception:
        log.exception("SMS send failed for %s", mask_phone(phone))
        flash("Could not send the SMS right now. Please try again later.", "error")
        return redirect(url_for("index"))

    for key, _, _ in checks:
        rates.hit(key)

    session["otp"] = {
        "phone": phone,
        "salt": salt,
        "hash": hash_code(code, salt),
        "expires": time.time() + OTP_TTL_SECONDS,
        "attempts": 0,
    }
    session.pop("verified", None)
    flash(f"OTP sent to {mask_phone(phone)}.", "info")
    return redirect(url_for("index"))


@app.post("/verify")
def verify():
    otp = _pending()
    if not otp:
        session.pop("otp", None)
        flash("Your code has expired. Please request a new one.", "error")
        return redirect(url_for("index"))

    code = re.sub(r"\D", "", request.form.get("code", ""))
    otp["attempts"] += 1
    session["otp"] = otp  # persist attempt count

    if hmac.compare_digest(hash_code(code, otp["salt"]), otp["hash"]):
        session.pop("otp", None)
        session.pop("phone_input", None)
        session["verified"] = otp["phone"]
        log.info("Verified %s", mask_phone(otp["phone"]))
        return redirect(url_for("index"))

    remaining = OTP_MAX_ATTEMPTS - otp["attempts"]
    if remaining <= 0:
        session.pop("otp", None)
        flash("Too many incorrect attempts. Please request a new code.", "error")
    else:
        flash(f"Incorrect code. {remaining} attempt(s) left.", "error")
    return redirect(url_for("index"))


@app.post("/reset")
def reset():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.config["SESSION_COOKIE_SECURE"] = False  # allow http://localhost in dev
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
