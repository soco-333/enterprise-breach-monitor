"""
notifier.py — sends breach alerts over Email, Telegram, and WhatsApp.

All credentials are read from environment variables so nothing sensitive
lives in source control. See .env.example for the full list.

WhatsApp uses Twilio's WhatsApp API (works with the sandbox number for
testing, or a Twilio-approved WhatsApp Business sender for production).
"""

import os
import smtplib
from email.mime.text import MIMEText
import requests

# ── Email (SMTP) ────────────────────────────────────────────────────────────
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
ALERT_FROM_EMAIL = os.environ.get("ALERT_FROM_EMAIL", SMTP_USER)

# ── Telegram ─────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")

# ── WhatsApp (Twilio) ────────────────────────────────────────────────────
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_FROM = os.environ.get("TWILIO_WHATSAPP_FROM")  # e.g. "whatsapp:+14155238886"


def send_email_alert(to_address, subject, body):
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        print("[notifier] Email not configured, skipping alert.")
        return False
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = ALERT_FROM_EMAIL
        msg["To"] = to_address

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(ALERT_FROM_EMAIL, [to_address], msg.as_string())
        return True
    except Exception as e:
        print(f"[notifier] Email alert failed: {e}")
        return False


def send_telegram_alert(chat_id, text):
    if not TELEGRAM_BOT_TOKEN:
        print("[notifier] Telegram not configured, skipping alert.")
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        resp = requests.post(url, json={"chat_id": chat_id, "text": text}, timeout=10)
        return resp.status_code == 200
    except Exception as e:
        print(f"[notifier] Telegram alert failed: {e}")
        return False


def send_whatsapp_alert(to_number, body):
    """to_number should be a plain phone number in E.164 format, e.g. +919876543210."""
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_WHATSAPP_FROM):
        print("[notifier] WhatsApp not configured, skipping alert.")
        return False
    try:
        from twilio.rest import Client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(
            from_=TWILIO_WHATSAPP_FROM,
            body=body,
            to=f"whatsapp:{to_number}",
        )
        return True
    except Exception as e:
        print(f"[notifier] WhatsApp alert failed: {e}")
        return False


def dispatch_alert(channels, message, subject="Breach Monitor Alert",
                    notify_email=None, telegram_chat_id=None, whatsapp_number=None):
    """channels: list of strings from {'email', 'telegram', 'whatsapp'}."""
    results = {}
    if "email" in channels and notify_email:
        results["email"] = send_email_alert(notify_email, subject, message)
    if "telegram" in channels and telegram_chat_id:
        results["telegram"] = send_telegram_alert(telegram_chat_id, message)
    if "whatsapp" in channels and whatsapp_number:
        results["whatsapp"] = send_whatsapp_alert(whatsapp_number, message)
    return results
