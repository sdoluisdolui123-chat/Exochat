"""
Signup / sign-in routes.
"""
from datetime import datetime

from flask import render_template, request, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from ..extensions import app
from ..db import get_db_connection, return_db_connection
from ..utils import validate_phone


# ----------------- Routes -----------------
@app.route("/", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        display_name  = request.form.get("display_name", "").strip()
        country_code  = request.form.get("country_code", "").strip()
        phone_number  = request.form.get("phone_number", "").strip()
        phone         = request.form.get("phone", "").strip()
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
                c.execute("UPDATE users SET last_online=?, username=?, password_hash=? WHERE phone=?",
                          (now_iso, display_name, pwd_hash, phone))
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

