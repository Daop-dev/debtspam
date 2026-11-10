"""DebtSMS: phone OTP verification plus a staff debt-reminder tool (Flask).

The reminder tool lives in reminders.py and is served under /admin.

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
import os
import re
import secrets
import time

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect

from core import APP_NAME, client_ip, log, mask_phone, normalize_my_phone, rates, send_sms

# --- Configuration -----------------------------------------------------------

OTP_LENGTH = int(os.environ.get("OTP_LENGTH", 6))
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 300))
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", 5))
RESEND_COOLDOWN_SECONDS = int(os.environ.get("RESEND_COOLDOWN_SECONDS", 60))
MAX_SENDS_PER_PHONE_PER_HOUR = int(os.environ.get("MAX_SENDS_PER_PHONE_PER_HOUR", 3))
MAX_SENDS_PER_IP_PER_HOUR = int(os.environ.get("MAX_SENDS_PER_IP_PER_HOUR", 5))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") == "1",
)
csrf = CSRFProtect(app)

import reminders  # noqa: E402  (staff debt-reminder tool, under /admin)

app.register_blueprint(reminders.bp)
csrf.exempt(reminders.inbound_sms)
reminders.init_db()

# --- OTP codes ---------------------------------------------------------------


def generate_code() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(OTP_LENGTH))


def hash_code(code: str, salt: str) -> str:
    key = app.config["SECRET_KEY"].encode()
    return hmac.new(key, f"{salt}:{code}".encode(), hashlib.sha256).hexdigest()


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
