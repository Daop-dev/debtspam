"""Staff tool for sending debt payment reminders by SMS (served under /admin).

Safeguards, so this can only be used for legitimate reminders to your own
customers:
  * staff login (ADMIN_USERNAME / ADMIN_PASSWORD), with login rate limiting
  * a customer is only messaged if staff recorded their consent to SMS
  * opt-out: every message ends with "Reply STOP to opt out"; STOP replies
    (Twilio inbound webhook) or the Opt-out button stop all further messages
  * per-customer frequency caps (min hours between reminders, max per 30 days)
  * sending only during allowed hours, Malaysia time (default 08:00-20:00)
  * capped batch size; every attempt is written to the message log
"""

from __future__ import annotations

import functools
import hmac
import os
import re
import sqlite3
from datetime import date, datetime, timedelta, timezone

from flask import (Blueprint, abort, flash, g, redirect,
                   render_template, request, session, url_for)

from core import APP_NAME, client_ip, log, mask_phone, normalize_my_phone, rates, send_sms

bp = Blueprint("admin", __name__)

MYT = timezone(timedelta(hours=8))  # Malaysia has no daylight saving

DATABASE_PATH = os.environ.get(
    "DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "debtsms.db")
)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
MIN_HOURS_BETWEEN = int(os.environ.get("REMINDER_MIN_HOURS_BETWEEN", 24))
MAX_PER_30_DAYS = int(os.environ.get("REMINDER_MAX_PER_30_DAYS", 4))
SEND_HOUR_START = int(os.environ.get("REMINDER_SEND_HOUR_START", 8))
SEND_HOUR_END = int(os.environ.get("REMINDER_SEND_HOUR_END", 20))
MAX_BATCH = int(os.environ.get("REMINDER_MAX_BATCH", 50))
MAX_TEMPLATE_LEN = 300
OPT_OUT_TEXT = "Reply STOP to opt out."

TEMPLATES = {
    "upcoming": "{brand}: Hi {name}, a friendly reminder that your payment of "
                "RM{amount} is due on {due_date}. Thank you.",
    "due_today": "{brand}: Hi {name}, your payment of RM{amount} is due today "
                 "({due_date}). Please ignore if already paid.",
    "overdue": "{brand}: Hi {name}, our records show RM{amount} was due on "
               "{due_date} and is still outstanding. Please contact us to arrange "
               "payment. Ignore if already paid.",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL UNIQUE,
    amount TEXT NOT NULL,
    due_date TEXT NOT NULL,
    consent INTEGER NOT NULL DEFAULT 0,
    opted_out INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER,
    phone TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL,          -- sent | failed | skipped
    detail TEXT,
    staff TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_customer ON messages(customer_id, created_at);
"""


# --- Database ----------------------------------------------------------------


def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@bp.teardown_app_request
def _close_db(_exc) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.executescript(SCHEMA)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


@bp.app_template_filter("myt")
def to_myt(value: str) -> str:
    """Format a stored UTC timestamp in Malaysia time."""
    return datetime.fromisoformat(value).astimezone(MYT).strftime("%d/%m/%Y %H:%M")


# --- Auth --------------------------------------------------------------------


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("staff"):
            return redirect(url_for("admin.login"))
        return view(*args, **kwargs)
    return wrapped


@bp.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not ADMIN_PASSWORD:
            flash("Staff login is disabled: set ADMIN_PASSWORD when starting the app.")
            return redirect(url_for("admin.login"))
        key = f"login:{client_ip()}"
        allowed, wait = rates.check(key, 5, 900)
        if not allowed:
            flash(f"Too many login attempts. Try again in {wait} seconds.")
            return redirect(url_for("admin.login"))
        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        ok_user = hmac.compare_digest(user.encode(), ADMIN_USERNAME.encode())
        ok_pw = hmac.compare_digest(pw.encode(), ADMIN_PASSWORD.encode())
        if ok_user and ok_pw:
            session.clear()
            session["staff"] = user
            return redirect(url_for("admin.dashboard"))
        rates.hit(key)
        flash("Wrong username or password.")
    return render_template("admin_login.html", disabled=not ADMIN_PASSWORD)


@bp.post("/admin/logout")
def logout():
    session.pop("staff", None)
    return redirect(url_for("admin.login"))


# --- Customers ---------------------------------------------------------------


def _parse_amount(raw: str) -> str | None:
    raw = (raw or "").replace(",", "").replace("RM", "").strip()
    if not re.fullmatch(r"\d{1,9}(\.\d{1,2})?", raw):
        return None
    return f"{float(raw):,.2f}"


def _parse_date(raw: str) -> str | None:
    try:
        return date.fromisoformat((raw or "").strip()).isoformat()
    except ValueError:
        return None


@bp.get("/admin")
@login_required
def dashboard():
    since = iso(now_utc() - timedelta(days=30))
    customers = db().execute(
        """
        SELECT c.*,
               (SELECT MAX(created_at) FROM messages m
                 WHERE m.customer_id = c.id AND m.status = 'sent') AS last_sent,
               (SELECT COUNT(*) FROM messages m
                 WHERE m.customer_id = c.id AND m.status = 'sent'
                   AND m.created_at >= ?) AS sent_30d
          FROM customers c ORDER BY c.due_date, c.name
        """,
        (since,),
    ).fetchall()
    return render_template(
        "admin_dashboard.html",
        customers=customers,
        templates=TEMPLATES,
        opt_out_text=OPT_OUT_TEXT,
        limits=dict(hours=MIN_HOURS_BETWEEN, per30=MAX_PER_30_DAYS,
                    start=SEND_HOUR_START, end=SEND_HOUR_END, batch=MAX_BATCH),
        mask=mask_phone,
        today=datetime.now(MYT).date().isoformat(),
    )


@bp.post("/admin/customers")
@login_required
def add_customer():
    name = request.form.get("name", "").strip()[:80]
    phone = normalize_my_phone(request.form.get("phone", ""))
    amount = _parse_amount(request.form.get("amount", ""))
    due = _parse_date(request.form.get("due_date", ""))
    consent = request.form.get("consent") == "yes"
    errors = []
    if not name:
        errors.append("name")
    if not phone:
        errors.append("a valid Malaysian mobile number")
    if not amount:
        errors.append("an amount like 150.00")
    if not due:
        errors.append("a due date")
    if not consent:
        errors.append("confirmation that the customer agreed to SMS reminders")
    if errors:
        flash("Please provide " + ", ".join(errors) + ".")
        return redirect(url_for("admin.dashboard"))
    try:
        db().execute(
            "INSERT INTO customers (name, phone, amount, due_date, consent, created_at)"
            " VALUES (?, ?, ?, ?, 1, ?)",
            (name, phone, amount, due, iso(now_utc())),
        )
        db().commit()
        flash(f"Added {name}.")
    except sqlite3.IntegrityError:
        flash("A customer with that phone number already exists.")
    return redirect(url_for("admin.dashboard"))


@bp.post("/admin/customers/<int:cid>/update")
@login_required
def update_customer(cid: int):
    amount = _parse_amount(request.form.get("amount", ""))
    due = _parse_date(request.form.get("due_date", ""))
    if not amount or not due:
        flash("Enter a valid amount and due date.")
    else:
        db().execute("UPDATE customers SET amount = ?, due_date = ? WHERE id = ?",
                     (amount, due, cid))
        db().commit()
        flash("Customer updated.")
    return redirect(url_for("admin.dashboard"))


@bp.post("/admin/customers/<int:cid>/optout")
@login_required
def toggle_optout(cid: int):
    row = db().execute("SELECT opted_out FROM customers WHERE id = ?", (cid,)).fetchone()
    if not row:
        abort(404)
    db().execute("UPDATE customers SET opted_out = ? WHERE id = ?",
                 (0 if row["opted_out"] else 1, cid))
    db().commit()
    return redirect(url_for("admin.dashboard"))


@bp.post("/admin/customers/<int:cid>/delete")
@login_required
def delete_customer(cid: int):
    db().execute("DELETE FROM customers WHERE id = ?", (cid,))
    db().commit()
    flash("Customer deleted.")
    return redirect(url_for("admin.dashboard"))


# --- Sending -----------------------------------------------------------------

_PLACEHOLDER = re.compile(r"\{(name|amount|due_date|brand)\}")


def render_message(template: str, customer: sqlite3.Row) -> str:
    due = date.fromisoformat(customer["due_date"]).strftime("%d/%m/%Y")
    values = {"name": customer["name"], "amount": customer["amount"],
              "due_date": due, "brand": APP_NAME}
    body = _PLACEHOLDER.sub(lambda m: values[m.group(1)], template).strip()
    if "STOP" not in body.upper():
        body = f"{body} {OPT_OUT_TEXT}"
    return body


def skip_reason(customer: sqlite3.Row) -> str | None:
    if not customer["consent"]:
        return "no consent recorded"
    if customer["opted_out"]:
        return "customer opted out"
    sent = db().execute(
        "SELECT created_at FROM messages WHERE customer_id = ? AND status = 'sent'"
        " AND created_at >= ? ORDER BY created_at DESC",
        (customer["id"], iso(now_utc() - timedelta(days=30))),
    ).fetchall()
    if len(sent) >= MAX_PER_30_DAYS:
        return f"already sent {MAX_PER_30_DAYS} reminders in the last 30 days"
    if sent:
        last = datetime.fromisoformat(sent[0]["created_at"])
        if now_utc() - last < timedelta(hours=MIN_HOURS_BETWEEN):
            return f"already reminded in the last {MIN_HOURS_BETWEEN} hours"
    return None


def _log(customer, body, status, detail):
    db().execute(
        "INSERT INTO messages (customer_id, phone, body, status, detail, staff, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (customer["id"], customer["phone"], body, status, detail,
         session.get("staff"), iso(now_utc())),
    )
    db().commit()


@bp.post("/admin/send")
@login_required
def send_reminders():
    hour = datetime.now(MYT).hour
    if not (SEND_HOUR_START <= hour < SEND_HOUR_END):
        flash(f"Reminders can only be sent between {SEND_HOUR_START:02d}:00 and "
              f"{SEND_HOUR_END:02d}:00 Malaysia time.")
        return redirect(url_for("admin.dashboard"))

    template = request.form.get("template", "").strip()
    if not template or len(template) > MAX_TEMPLATE_LEN:
        flash(f"The message must be 1-{MAX_TEMPLATE_LEN} characters.")
        return redirect(url_for("admin.dashboard"))

    ids = sorted({int(i) for i in request.form.getlist("customer_ids") if i.isdigit()})
    if not ids:
        flash("Select at least one customer.")
        return redirect(url_for("admin.dashboard"))
    if len(ids) > MAX_BATCH:
        flash(f"Select at most {MAX_BATCH} customers at a time.")
        return redirect(url_for("admin.dashboard"))

    counts = {"sent": 0, "skipped": 0, "failed": 0}
    for cid in ids:
        customer = db().execute("SELECT * FROM customers WHERE id = ?", (cid,)).fetchone()
        if not customer:
            continue
        body = render_message(template, customer)
        reason = skip_reason(customer)
        if reason:
            _log(customer, body, "skipped", reason)
            counts["skipped"] += 1
            continue
        try:
            send_sms(customer["phone"], body)
        except Exception as exc:  # provider error: log it, carry on with the batch
            log.exception("Reminder to %s failed", mask_phone(customer["phone"]))
            _log(customer, body, "failed", type(exc).__name__)
            counts["failed"] += 1
            continue
        _log(customer, body, "sent", None)
        counts["sent"] += 1

    flash(f"Sent {counts['sent']}, skipped {counts['skipped']}, failed {counts['failed']}."
          " See the message log for details.")
    return redirect(url_for("admin.dashboard"))


@bp.get("/admin/log")
@login_required
def message_log():
    rows = db().execute(
        "SELECT m.*, c.name FROM messages m LEFT JOIN customers c ON c.id = m.customer_id"
        " ORDER BY m.id DESC LIMIT 200"
    ).fetchall()
    return render_template("admin_log.html", rows=rows, mask=mask_phone)


# --- Inbound SMS (opt-out) ---------------------------------------------------

_STOP_WORDS = {"STOP", "UNSUBSCRIBE", "CANCEL", "END", "QUIT", "BERHENTI"}


@bp.post("/sms/inbound")
def inbound_sms():
    """Twilio inbound-message webhook: a STOP reply opts the customer out."""
    token = os.environ.get("TWILIO_AUTH_TOKEN")
    if not token:
        abort(404)
    from twilio.request_validator import RequestValidator

    signature = request.headers.get("X-Twilio-Signature", "")
    if not RequestValidator(token).validate(request.url, request.form.to_dict(), signature):
        abort(403)
    phone = normalize_my_phone(request.form.get("From", ""))
    word = request.form.get("Body", "").strip().upper()
    if phone and word in _STOP_WORDS:
        db().execute("UPDATE customers SET opted_out = 1 WHERE phone = ?", (phone,))
        db().commit()
        log.info("Opt-out received from %s", mask_phone(phone))
    return ("<Response></Response>", 200, {"Content-Type": "text/xml"})
