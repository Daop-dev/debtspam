# debtspam
DebtSMS Spammer is an SMS messaging tool designed to automate debt payment reminders and notifications. It allows authorized users to send customized SMS messages to notify customers about outstanding balances, overdue payments, payment deadlines, and account updates.

## Phone number OTP verification

A small Flask app (`app.py` + `templates/index.html`) that verifies a user owns a Malaysian mobile number before they're allowed to use the tool.

```bash
pip install -r requirements.txt
SESSION_COOKIE_SECURE=0 python app.py   # dev: SMS_PROVIDER=console prints the code to the log
```

Set `SMS_PROVIDER=twilio` plus the `TWILIO_*` variables (see `.env.example`) to send real SMS.

Abuse protections: CSRF + consent required, 60s resend cooldown per number, 3 sends/hour per number, 5 sends/hour per IP, 5 attempts per code, 5-minute expiry, codes stored only as HMACs. Rate limits are in-memory, so run a single worker process (or move them to Redis).

## Debt payment reminders (staff tool)

Open `/admin` (e.g. http://localhost:5000/admin) and log in with `ADMIN_USERNAME` / `ADMIN_PASSWORD`:

```bash
ADMIN_PASSWORD=choose-a-password SESSION_COOKIE_SECURE=0 python app.py
```

- **Customers**: name, Malaysian mobile number, amount owed, due date, stored in SQLite (`debtsms.db`). A customer can only be added once staff confirm the customer agreed to SMS reminders.
- **Send reminder**: choose *Upcoming*, *Due today* or *Overdue* (or edit the text), tick customers and send. Placeholders: `{name}` `{amount}` `{due_date}` `{brand}`. "Reply STOP to opt out." is added to every message.
- **Opt-out**: the *Opt out* button, or a STOP reply when Twilio's inbound webhook points to `/sms/inbound` (requests are verified with your Twilio signature).
- **Limits**: 08:00–20:00 Malaysia time only, at most once per 24 h and 4 times per 30 days per customer, 50 customers per send. Skipped and failed sends are recorded in the **Message log**.
