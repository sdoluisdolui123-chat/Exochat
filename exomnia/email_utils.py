"""
Password-reset email delivery via Brevo (formerly Sendinblue).

Uses Brevo's HTTPS REST API rather than SMTP, since many free hosts
(including Render's free tier) block outbound SMTP ports but always
allow outbound HTTPS.

Setup (do this once):
  1. Create a free account at https://www.brevo.com
  2. Verify a "sender" email address/domain (Brevo requires this before
     you can send — see Senders & IP in their dashboard)
  3. Get an API key: Settings -> SMTP & API -> API Keys -> Generate a new key
  4. Set these environment variables (locally and on Render):
       BREVO_API_KEY=xkeysib-xxxxxxxxxxxx
       BREVO_SENDER_EMAIL=you@yourdomain.com   (the verified sender)
       BREVO_SENDER_NAME=Exomnia               (optional, display name)

Without BREVO_API_KEY set, send_reset_code_email() logs the code to the
console instead of emailing it — handy for local development so you're
never blocked from testing the flow.
"""
import os
import json
import urllib.request
import urllib.error

BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "Exomnia")
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


def send_reset_code_email(to_email, display_name, code):
    """
    Send the password-reset verification code by email.
    Returns True if the email was handed off successfully (or, in local
    dev without an API key, printed to the console). Returns False if a
    real send was attempted and failed.
    """
    if not BREVO_API_KEY or not BREVO_SENDER_EMAIL:
        # Local/dev fallback: no email service configured, so just log it.
        print(f"[DEV MODE — no BREVO_API_KEY set] Password reset code for "
              f"{to_email}: {code}")
        return True

    # Clean HTML without extra whitespace
    html_content = f"""<html><body style="font-family: Arial, sans-serif; background-color: #f8f9fa; padding: 20px;"><div style="max-width: 480px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);"><h2 style="color: #0E4950; margin-bottom: 10px;">Reset your password</h2><p style="color: #333; font-size: 14px; line-height: 1.6;">Hi {display_name or 'there'},</p><p style="color: #333; font-size: 14px; line-height: 1.6;">Use this code to reset your Exomnia password. It expires in 15 minutes.</p><div style="font-size: 28px; font-weight: bold; letter-spacing: 4px; background: #f0f4f4; padding: 16px 24px; border-radius: 8px; text-align: center; color: #0E4950; margin: 25px 0; border: 2px solid #0E4950;">{code}</div><p style="color: #666; font-size: 13px;">If you didn't request this, you can safely ignore this email.</p><hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;"><p style="color: #999; font-size: 12px; text-align: center;">© 2026 Exomnia. All rights reserved.</p></div></body></html>"""

    payload = {
        "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
        "to": [{"email": to_email, "name": display_name or to_email}],
        "subject": "Your Exomnia password reset code",
        "htmlContent": html_content,
    }

    req = urllib.request.Request(
        BREVO_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "accept": "application/json",
            "api-key": BREVO_API_KEY,
            "content-type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"✅ Brevo API response: {resp.status}")
            print(f"📧 Email sent to: {to_email} | Reset code: {code}")
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        error_msg = e.read().decode(errors='ignore')
        print(f"❌ Brevo API error {e.code}: {error_msg}")
        return False
    except Exception as e:
        print(f"❌ Error sending reset email: {e}")
        return False
