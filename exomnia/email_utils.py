"""
Password-reset email delivery via Gmail SMTP.

This uses Gmail's SMTP server which has better deliverability than Brevo
for transactional emails, especially from free email domains.

Setup (do this once):
  1. Go to https://myaccount.google.com/apppasswords
  2. You will see a dropdown for "Select the app and device you're using"
  3. Select "Mail" in the app dropdown
  4. For Device, select "Windows Computer" (or any device - it will work for all)
  5. Click Generate
  6. Copy the 16-character app password that appears
  7. Set these environment variables (locally and on Render):
       GMAIL_EMAIL=your-email@gmail.com
       GMAIL_PASSWORD=xxxx-xxxx-xxxx-xxxx  (the app password, NOT your account password)

Note: The app password works for ALL devices (mobile, computer, etc.) once generated.
You only need to generate it once, not for each device.

Without GMAIL_EMAIL and GMAIL_PASSWORD set, send_reset_code_email() logs the code to the
console instead of emailing it — handy for local development so you're
never blocked from testing the flow.
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

GMAIL_EMAIL = os.environ.get("GMAIL_EMAIL", "")
GMAIL_PASSWORD = os.environ.get("GMAIL_PASSWORD", "")


def send_reset_code_email(to_email, display_name, code):
    """
    Send the password-reset verification code by email via Gmail SMTP.
    Returns True if the email was sent successfully (or, in local
    dev without credentials, printed to the console). Returns False if a
    real send was attempted and failed.
    """
    if not GMAIL_EMAIL or not GMAIL_PASSWORD:
        # Local/dev fallback: no email service configured, so just log it.
        print(f"[DEV MODE — no GMAIL credentials set] Password reset code for "
              f"{to_email}: {code}")
        return True

    # Clean HTML with proper styling
    html_content = f"""<html><body style="font-family: Arial, sans-serif; background-color: #f8f9fa; padding: 20px; margin: 0;"><div style="max-width: 480px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);"><h2 style="color: #0E4950; margin-top: 0; margin-bottom: 15px;">Reset your password</h2><p style="color: #333; font-size: 14px; line-height: 1.6; margin: 0 0 10px 0;">Hi {display_name or 'there'},</p><p style="color: #333; font-size: 14px; line-height: 1.6; margin: 0 0 20px 0;">Use this code to reset your Exomnia password. It expires in 15 minutes.</p><div style="font-size: 32px; font-weight: bold; letter-spacing: 6px; background: #f0f4f4; padding: 16px 24px; border-radius: 8px; text-align: center; color: #0E4950; margin: 25px 0; border: 2px solid #0E4950; font-family: 'Courier New', monospace;">{code}</div><p style="color: #666; font-size: 13px; line-height: 1.6; margin: 20px 0 0 0;">If you didn't request this, you can safely ignore this email.</p><hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;"><p style="color: #999; font-size: 12px; text-align: center; margin: 0;">© 2026 Exomnia. All rights reserved.</p></div></body></html>"""

    try:
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Your Exomnia password reset code"
        msg["From"] = GMAIL_EMAIL
        msg["To"] = to_email
        
        # Attach HTML content
        msg.attach(MIMEText(html_content, "html"))
        
        # Send via Gmail SMTP
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_EMAIL, GMAIL_PASSWORD)
            server.sendmail(GMAIL_EMAIL, to_email, msg.as_string())
        
        print(f"✅ Email sent to {to_email} | Reset code: {code}")
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ Gmail authentication failed: {e}")
        print("   Check your GMAIL_EMAIL and GMAIL_PASSWORD environment variables")
        return False
    except smtplib.SMTPException as e:
        print(f"❌ SMTP error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error sending reset email: {e}")
        return False
