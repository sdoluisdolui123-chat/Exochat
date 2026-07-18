"""
Contacts list API + adding a new contact.
"""
from datetime import datetime

from flask import request, jsonify

from ..extensions import app
from ..db import get_db_connection, return_db_connection
from ..cache import cache
from ..utils import validate_phone


# ----------------- Contacts API -----------------
@app.route("/api/contacts")
def api_contacts():
    phone = request.args.get("phone")
    if not phone:
        return jsonify([]), 400
    
    # Check cache first
    cache_key = f"contacts_{phone}"
    cached_contacts = cache.get(cache_key)
    if cached_contacts:
        return jsonify(cached_contacts)
    
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("""
                SELECT c.contact_phone, c.contact_name,
                       substr(COALESCE(c.last_message,''), 1, 50) ||
                       CASE WHEN length(c.last_message) > 50 THEN '...' ELSE '' END as last_message,
                       c.last_sender,
                       COALESCE(u.avatar_photo, '') as avatar_photo,
                       COALESCE(u.avatar_color, '#0E4950') as avatar_color,
                       COALESCE(u.avatar_emoji, '') as avatar_emoji,
                       c.timestamp as last_message_time,
                       (SELECT COUNT(*) FROM messages m
                        WHERE m.sender = c.contact_phone
                          AND m.receiver = ?
                          AND m.status != 'seen') as unread_count
                FROM contacts c
                LEFT JOIN users u ON u.phone = c.contact_phone
                WHERE c.user_phone=?
                ORDER BY c.timestamp DESC
            """,(phone, phone))
            rows = c.fetchall()
        finally:
            return_db_connection(conn)
        contacts = [{"contact_phone": r[0], "contact_name": r[1], "last_message": r[2],
                     "last_sender": r[3], "avatar_photo": r[4], "avatar_color": r[5],
                     "avatar_emoji": r[6], "last_message_time": r[7], "unread_count": r[8] or 0}
                    for r in rows]
        
        # Cache the results
        cache.set(cache_key, contacts)
        
        return jsonify(contacts)
    except Exception as e:
        print(f" Error in api_contacts: {e}")
        return jsonify([]), 500

@app.route("/add_contact", methods=["POST"])
def add_contact():
    try:
        user = request.form.get("user")
        country_code = request.form.get("country_code","")
        contact_phone = request.form.get("contact_phone","").strip()
        contact_name = request.form.get("contact_name","").strip()
        if not all([user, contact_phone, contact_name]):
            return jsonify({"success": False, "error": "Please fill all information"}), 400

        full_contact_phone = contact_phone
        if country_code and not contact_phone.startswith(country_code):
            full_contact_phone = country_code + contact_phone

        if not validate_phone(full_contact_phone):
            return jsonify({"success": False, "error": "Please enter valid phone number"}), 400

        now_iso = datetime.now().isoformat()
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO users(phone,last_online) VALUES(?,?)",(full_contact_phone, now_iso))
            c.execute("""
                INSERT OR REPLACE INTO contacts(user_phone,contact_phone,contact_name,last_message)
                VALUES(?,?,?,COALESCE((SELECT last_message FROM contacts WHERE user_phone=? AND contact_phone=?), ''))
            """,(user, full_contact_phone, contact_name, user, full_contact_phone))
            conn.commit()
        finally:
            return_db_connection(conn)

        # Clear cache for this user's contacts
        cache.delete(f"contacts_{user}")

        return jsonify({"success": True})

    except Exception as e:
        print(f" Error in add_contact: {e}")
        return jsonify({"success": False, "error": "An error occurred"}), 500
