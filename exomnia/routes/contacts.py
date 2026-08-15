"""
Contacts list API + adding a new contact.
"""
from datetime import datetime

from flask import request, jsonify

from ..extensions import app
from ..db import get_db_connection, return_db_connection
from ..cache import cache
from ..utils import validate_phone, utc_now_iso


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

        now_iso = utc_now_iso()
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


# ----------------- Block / Unblock -----------------
@app.route("/api/block_contact", methods=["POST"])
def api_block_contact():
    data = request.get_json() or {}
    phone = str(data.get("phone", "")).strip()
    contact_phone = str(data.get("contact_phone", "")).strip()
    if not phone or not contact_phone:
        return jsonify({"success": False, "error": "Phone and contact_phone required"}), 400
    if phone == contact_phone:
        return jsonify({"success": False, "error": "Can't block yourself"}), 400
    now_iso = datetime.now().isoformat()
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO blocked_contacts(blocker_phone, blocked_phone, created_at) VALUES(?,?,?)",
            (phone, contact_phone, now_iso),
        )
        conn.commit()
    finally:
        return_db_connection(conn)
    return jsonify({"success": True})


@app.route("/api/unblock_contact", methods=["POST"])
def api_unblock_contact():
    data = request.get_json() or {}
    phone = str(data.get("phone", "")).strip()
    contact_phone = str(data.get("contact_phone", "")).strip()
    if not phone or not contact_phone:
        return jsonify({"success": False, "error": "Phone and contact_phone required"}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute(
            "DELETE FROM blocked_contacts WHERE blocker_phone=? AND blocked_phone=?",
            (phone, contact_phone),
        )
        conn.commit()
    finally:
        return_db_connection(conn)
    return jsonify({"success": True})


@app.route("/api/blocked_contacts")
def api_blocked_contacts():
    phone = request.args.get("phone", "").strip()
    if not phone:
        return jsonify([]), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT b.blocked_phone, b.created_at,
                   COALESCE(ct.contact_name, ''),
                   COALESCE(u.avatar_photo, ''), COALESCE(u.avatar_color, '#0E4950'),
                   COALESCE(u.avatar_emoji, '')
            FROM blocked_contacts b
            LEFT JOIN contacts ct ON ct.user_phone = b.blocker_phone AND ct.contact_phone = b.blocked_phone
            LEFT JOIN users u ON u.phone = b.blocked_phone
            WHERE b.blocker_phone = ?
            ORDER BY b.created_at DESC
        """, (phone,))
        rows = c.fetchall()
    finally:
        return_db_connection(conn)
    blocked = [{
        "phone": r[0], "blocked_at": r[1],
        "name": r[2] or r[0],
        "avatar_photo": r[3], "avatar_color": r[4], "avatar_emoji": r[5],
    } for r in rows]
    return jsonify(blocked)


@app.route("/api/is_blocked")
def api_is_blocked():
    """Whether `phone` has blocked `contact_phone`, and vice versa — the
    chat page needs both directions to decide what UI/state to show."""
    phone = request.args.get("phone", "").strip()
    contact_phone = request.args.get("contact_phone", "").strip()
    if not phone or not contact_phone:
        return jsonify({"error": "Both phone and contact_phone required"}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT 1 FROM blocked_contacts WHERE blocker_phone=? AND blocked_phone=?",
            (phone, contact_phone),
        )
        i_blocked_them = c.fetchone() is not None
        c.execute(
            "SELECT 1 FROM blocked_contacts WHERE blocker_phone=? AND blocked_phone=?",
            (contact_phone, phone),
        )
        they_blocked_me = c.fetchone() is not None
    finally:
        return_db_connection(conn)
    return jsonify({"i_blocked_them": i_blocked_them, "they_blocked_me": they_blocked_me})
