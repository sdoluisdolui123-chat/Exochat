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

    payload = {
        "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
        "to": [{"email": to_email, "name": display_name or to_email}],
        "subject": "Your Exomnia password reset code",
        "htmlContent": f"""
            <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
                <h2 style="color:#0E4950;">Reset your password</h2>
                <p>Hi {display_name or ''},</p>
                <p>Use this code to reset your Exomnia password. It expires in 15 minutes.</p>
                <div style="font-size: 32px; font-weight: bold; letter-spacing: 6px;
                            background:#f0f4f4; padding: 16px 24px; border-radius: 8px;
                            text-align: center; color:#0E4950; margin: 20px 0;">
                    {code}
                </div>
                <p>If you didn't request this, you can safely ignore this email.</p>
            </div>
        """,
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
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        print(f"Brevo API error {e.code}: {e.read().decode(errors='ignore')}")
        return False
    except Exception as e:
        print(f"Error sending reset email: {e}")
        return False
