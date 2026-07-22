"""
Signup / sign-in routes.
"""
from datetime import datetime, timedelta

from flask import render_template, request, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from ..extensions import app
from ..db import get_db_connection, return_db_connection
from ..utils import validate_phone, validate_email, generate_reset_code
from ..email_utils import send_reset_code_email


# ----------------- Routes -----------------
@app.route("/", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        display_name  = request.form.get("display_name", "").strip()
        country_code  = request.form.get("country_code", "").strip()
        phone_number  = request.form.get("phone_number", "").strip()
        phone         = request.form.get("phone", "").strip()
        email         = request.form.get("email", "").strip().lower()
        password      = request.form.get("password", "").strip()
        password_conf = request.form.get("password_confirm", "").strip()

        if not phone and country_code and phone_number:
            phone = country_code + phone_number

        if not display_name:
            return render_template('signup.html', error="Please enter your name")
        if not phone:
            return render_template('signup.html', error="Please enter your phone number")
        if not validate_phone(phone):
            return render_template('signup.html', error="Please use correct phone number format with country code")
        if not email or not validate_email(email):
            return render_template('signup.html', error="Please enter a valid email address")
        if not password or len(password) < 6:
            return render_template('signup.html', error="Password must be at least 6 characters")
        if password != password_conf:
            return render_template('signup.html', error="Passwords do not match")

        try:
            now_iso   = datetime.now().isoformat()
            pwd_hash  = generate_password_hash(password)
            conn = get_db_connection()
            try:
                c = conn.cursor()
                # Check if phone already registered with a password
                c.execute("SELECT password_hash FROM users WHERE phone=?", (phone,))
                row = c.fetchone()
                if row and row[0]:
                    return render_template('signup.html', error="An account with this number already exists. Please sign in.")
                c.execute("INSERT OR IGNORE INTO users(phone,last_online) VALUES(?,?)", (phone, now_iso))
                c.execute("UPDATE users SET last_online=?, username=?, password_hash=?, email=? WHERE phone=?",
                          (now_iso, display_name, pwd_hash, email, phone))
                c.execute("UPDATE users SET display_name=? WHERE phone=? AND (display_name IS NULL OR display_name='')",
                          (display_name, phone))
                conn.commit()
            finally:
                return_db_connection(conn)
            return redirect(url_for('main_app', logged_in_phone=phone))
        except Exception as e:
            print(f"Error in signup: {e}")
            return render_template('signup.html', error="An error occurred. Please try again.")

    return render_template('signup.html')

@app.route("/signin", methods=["GET","POST"])
def signin():
    if request.method == "POST":
        country_code = request.form.get("country_code", "").strip()
        phone_number = request.form.get("phone_number", "").strip()
        phone        = request.form.get("phone", "").strip()
        password     = request.form.get("password", "").strip()

        if not phone and country_code and phone_number:
            phone = country_code + phone_number

        if not phone:
            return render_template('signin.html', error="Please enter your phone number")
        if not validate_phone(phone):
            return render_template('signin.html', error="Please use correct phone number format with country code")
        if not password:
            return render_template('signin.html', error="Please enter your password")

        try:
            now_iso = datetime.now().isoformat()
            conn = get_db_connection()
            try:
                c = conn.cursor()
                c.execute("SELECT password_hash FROM users WHERE phone=?", (phone,))
                row = c.fetchone()
                if not row:
                    return render_template('signin.html', error="No account found with this number. Please create an account first.")
                stored_hash = row[0] or ""
                # Allow sign-in without password for old accounts that predate password system
                if stored_hash and not check_password_hash(stored_hash, password):
                    return render_template('signin.html', error="Incorrect password. Please try again.")
                c.execute("UPDATE users SET last_online=? WHERE phone=?", (now_iso, phone))
                conn.commit()
            finally:
                return_db_connection(conn)
            return redirect(url_for('main_app', logged_in_phone=phone))
        except Exception as e:
            print(f"Error in signin: {e}")
            return render_template('signin.html', error="An error occurred. Please try again.")

    return render_template('signin.html')


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email or not validate_email(email):
            return render_template('forgot_password.html', error="Please enter a valid email address")

        # Always show the same generic message regardless of whether this
        # email is on file — this avoids leaking which emails are registered.
        generic_msg = ("If this email is on an account, we've sent a "
                        "6-digit reset code to it. Enter it on the next screen.")
        try:
            conn = get_db_connection()
            try:
                c = conn.cursor()
                c.execute("SELECT phone, display_name, username FROM users WHERE email=?", (email,))
                row = c.fetchone()
                if row and row[0]:
                    phone, display_name, username = row
                    code = generate_reset_code()
                    expires_at = (datetime.now() + timedelta(minutes=15)).isoformat()
                    c.execute(
                        "INSERT INTO password_resets(phone, code, expires_at) VALUES(?,?,?)",
                        (phone, code, expires_at)
                    )
                    conn.commit()
                    send_reset_code_email(email, display_name or username, code)
            finally:
                return_db_connection(conn)
        except Exception as e:
            print(f"Error in forgot_password: {e}")
            # Still show the generic message — don't reveal internal errors either

        return render_template('reset_password.html', email=email, info=generic_msg)

    return render_template('forgot_password.html')


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email         = request.form.get("email", "").strip().lower()
        code          = request.form.get("code", "").strip()
        password      = request.form.get("password", "").strip()
        password_conf = request.form.get("password_confirm", "").strip()

        if not email or not validate_email(email):
            return render_template('forgot_password.html', error="Something went wrong — please start over")
        if not code:
            return render_template('reset_password.html', email=email, error="Please enter the code from your email")
        if not password or len(password) < 6:
            return render_template('reset_password.html', email=email, error="Password must be at least 6 characters")
        if password != password_conf:
            return render_template('reset_password.html', email=email, error="Passwords do not match")

        try:
            conn = get_db_connection()
            try:
                c = conn.cursor()
                c.execute("SELECT phone FROM users WHERE email=?", (email,))
                user_row = c.fetchone()
                if not user_row:
                    return render_template('reset_password.html', email=email, error="Invalid or already-used code")
                phone = user_row[0]

                c.execute(
                    "SELECT id, expires_at FROM password_resets "
                    "WHERE phone=? AND code=? AND used=0 ORDER BY id DESC LIMIT 1",
                    (phone, code)
                )
                row = c.fetchone()
                if not row:
                    return render_template('reset_password.html', email=email, error="Invalid or already-used code")
                reset_id, expires_at = row
                if datetime.now() > datetime.fromisoformat(expires_at):
                    return render_template('reset_password.html', email=email, error="This code has expired — please request a new one")

                pwd_hash = generate_password_hash(password)
                c.execute("UPDATE users SET password_hash=? WHERE phone=?", (pwd_hash, phone))
                c.execute("UPDATE password_resets SET used=1 WHERE id=?", (reset_id,))
                conn.commit()
            finally:
                return_db_connection(conn)
            return redirect(url_for('signin', reset='success'))
        except Exception as e:
            print(f"Error in reset_password: {e}")
            return render_template('reset_password.html', email=email, error="An error occurred. Please try again.")

    email = request.args.get('email', '')
    return render_template('reset_password.html', email=email)

