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
