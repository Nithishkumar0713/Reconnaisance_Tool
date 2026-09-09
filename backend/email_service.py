"""
email_service.py — OTP generation, storage, verification, and SMTP email delivery.
"""

import smtplib
import os
import secrets
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "") or SMTP_USER

OTP_EXPIRE_SECONDS = 600
OTP_RESEND_COOLDOWN = 60
MAX_ATTEMPTS = 5

_otp_store: dict[str, dict] = {}


def _generate_otp() -> str:
    """Generate a cryptographically secure 6-digit OTP (100000–999999)."""
    return str(secrets.randbelow(900000) + 100000)


def store_otp(email: str) -> str:
    """
    Create and store a new OTP for the given email.
    Enforces resend cooldown to prevent spam.
    Returns the OTP string.
    """
    key = email.strip().lower()
    existing = _otp_store.get(key)
    if existing:
        elapsed = time.time() - existing.get("sent_at", 0)
        if elapsed < OTP_RESEND_COOLDOWN:
            wait = int(OTP_RESEND_COOLDOWN - elapsed)
            raise ValueError(f"Please wait {wait}s before requesting another code.")

    otp = _generate_otp()
    _otp_store[key] = {
        "otp": otp,
        "expires_at": time.time() + OTP_EXPIRE_SECONDS,
        "attempts": 0,
        "sent_at": time.time(),
    }
    return otp


def verify_otp(email: str, otp_input: str) -> bool:
    """
    Verify an OTP for the given email.
    Returns True on success. Raises ValueError on failure.
    Clears the OTP after success or too many failed attempts.
    """
    key = email.strip().lower()
    record = _otp_store.get(key)

    if not record:
        raise ValueError("No verification code was sent to this email. Please request a new one.")

    if time.time() > record["expires_at"]:
        _otp_store.pop(key, None)
        raise ValueError("Your verification code has expired. Please request a new one.")

    record["attempts"] += 1
    if record["attempts"] > MAX_ATTEMPTS:
        _otp_store.pop(key, None)
        raise ValueError("Too many incorrect attempts. Please request a new verification code.")

    if record["otp"] != otp_input.strip():
        remaining = MAX_ATTEMPTS - record["attempts"]
        raise ValueError(f"Incorrect code. {remaining} attempt(s) remaining.")

    _otp_store.pop(key, None)
    return True


def send_otp_email(to_email: str, otp: str, full_name: str = "User") -> None:
    """
    Send an HTML OTP verification email via SMTP with STARTTLS.
    Raises ValueError if SMTP is not configured.
    Raises RuntimeError if sending fails.
    """
    if not SMTP_USER or not SMTP_PASS:
        raise ValueError(
            "Email service not configured. "
            "Set SMTP_USER and SMTP_PASS in your backend/.env file. "
            "For Gmail, create an App Password at: "
            "Google Account → Security → 2-Step Verification → App Passwords."
        )

    year = time.strftime("%Y")

    html_body = f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f8fafc;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:480px;margin:40px auto;padding:32px;">

    <div style="text-align:center;margin-bottom:24px;">
      <div style="background:linear-gradient(135deg,#ea580c,#f59e0b);width:60px;height:60px;border-radius:50%;margin:0 auto 14px;line-height:60px;text-align:center;font-size:28px;">
        🔍
      </div>
      <h1 style="color:#1e293b;font-size:22px;margin:0;font-weight:900;letter-spacing:-0.5px;">Reconnaissance Tool</h1>
      <p style="color:#94a3b8;font-size:11px;margin:6px 0 0;text-transform:uppercase;letter-spacing:3px;">Email Verification</p>
    </div>

    <div style="background:white;border-radius:14px;padding:30px;border:1px solid #e2e8f0;box-shadow:0 2px 12px rgba(0,0,0,0.05);">
      <p style="color:#374151;font-size:15px;margin:0 0 6px;">Hello, <strong>{full_name}</strong>!</p>
      <p style="color:#6b7280;font-size:14px;margin:0 0 26px;line-height:1.6;">
        Enter the code below to verify your email address and complete your registration.
      </p>

      <div style="background:#fff7ed;border:2px dashed #fed7aa;border-radius:12px;padding:26px;text-align:center;margin-bottom:26px;">
        <div style="font-size:46px;font-weight:900;letter-spacing:16px;color:#ea580c;font-family:monospace;">
          {otp}
        </div>
      </div>

      <div style="background:#f1f5f9;border-radius:8px;padding:14px 16px;">
        <p style="color:#64748b;font-size:12px;margin:0;line-height:1.8;">
          ⏱ <strong>Expires in 10 minutes</strong><br>
          🔒 If you didn't request this, you can safely ignore this email.
        </p>
      </div>
    </div>

    <p style="color:#cbd5e1;font-size:11px;text-align:center;margin-top:22px;">
      Reconnaissance Tool © {year} — Host Diagnostics Platform
    </p>
  </div>
</body>
</html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🔍 Your Verification Code — Reconnaissance Tool"
    msg["From"] = SMTP_FROM or SMTP_USER
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(msg["From"], to_email, msg.as_string())
    except smtplib.SMTPAuthenticationError:
        raise RuntimeError(
            "SMTP login failed. Check SMTP_USER and SMTP_PASS in .env. "
            "For Gmail, use a 16-character App Password, not your account password."
        )
    except smtplib.SMTPRecipientsRefused:
        raise RuntimeError(f"Email address '{to_email}' was rejected by the mail server.")
    except Exception as e:
        raise RuntimeError(f"Failed to send verification email: {type(e).__name__}: {str(e)}")


def send_password_reset_otp_email(to_email: str, otp: str, full_name: str = "User") -> None:
    """
    Send an HTML password-reset OTP email via SMTP with STARTTLS.
    Same delivery mechanics as send_otp_email, distinct copy so a reset
    code doesn't read as "complete your registration".
    Raises ValueError if SMTP is not configured.
    Raises RuntimeError if sending fails.
    """
    if not SMTP_USER or not SMTP_PASS:
        raise ValueError(
            "Email service not configured. "
            "Set SMTP_USER and SMTP_PASS in your backend/.env file. "
            "For Gmail, create an App Password at: "
            "Google Account → Security → 2-Step Verification → App Passwords."
        )

    year = time.strftime("%Y")

    html_body = f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f8fafc;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:480px;margin:40px auto;padding:32px;">

    <div style="text-align:center;margin-bottom:24px;">
      <div style="background:linear-gradient(135deg,#ea580c,#f59e0b);width:60px;height:60px;border-radius:50%;margin:0 auto 14px;line-height:60px;text-align:center;font-size:28px;">
        🔑
      </div>
      <h1 style="color:#1e293b;font-size:22px;margin:0;font-weight:900;letter-spacing:-0.5px;">Reconnaissance Tool</h1>
      <p style="color:#94a3b8;font-size:11px;margin:6px 0 0;text-transform:uppercase;letter-spacing:3px;">Password Reset</p>
    </div>

    <div style="background:white;border-radius:14px;padding:30px;border:1px solid #e2e8f0;box-shadow:0 2px 12px rgba(0,0,0,0.05);">
      <p style="color:#374151;font-size:15px;margin:0 0 6px;">Hello, <strong>{full_name}</strong>!</p>
      <p style="color:#6b7280;font-size:14px;margin:0 0 26px;line-height:1.6;">
        We received a request to reset your password. Enter the code below to continue.
      </p>

      <div style="background:#fff7ed;border:2px dashed #fed7aa;border-radius:12px;padding:26px;text-align:center;margin-bottom:26px;">
        <div style="font-size:46px;font-weight:900;letter-spacing:16px;color:#ea580c;font-family:monospace;">
          {otp}
        </div>
      </div>

      <div style="background:#f1f5f9;border-radius:8px;padding:14px 16px;">
        <p style="color:#64748b;font-size:12px;margin:0;line-height:1.8;">
          ⏱ <strong>Expires in 10 minutes</strong><br>
          🔒 If you didn't request this, you can safely ignore this email — your password won't be changed.
        </p>
      </div>
    </div>

    <p style="color:#cbd5e1;font-size:11px;text-align:center;margin-top:22px;">
      Reconnaissance Tool © {year} — Host Diagnostics Platform
    </p>
  </div>
</body>
</html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🔑 Reset Your Password — Reconnaissance Tool"
    msg["From"] = SMTP_FROM or SMTP_USER
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(msg["From"], to_email, msg.as_string())
    except smtplib.SMTPAuthenticationError:
        raise RuntimeError(
            "SMTP login failed. Check SMTP_USER and SMTP_PASS in .env. "
            "For Gmail, use a 16-character App Password, not your account password."
        )
    except smtplib.SMTPRecipientsRefused:
        raise RuntimeError(f"Email address '{to_email}' was rejected by the mail server.")
    except Exception as e:
        raise RuntimeError(f"Failed to send password reset email: {type(e).__name__}: {str(e)}")
