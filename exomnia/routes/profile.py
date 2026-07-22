"""
Profile read/update + avatar & banner photo upload.
"""
import os

from flask import request, jsonify, send_from_directory

from ..extensions import app
from ..db import get_db_connection, return_db_connection
from ..cache import cache
from ..utils import validate_email


# ----------------- Profile API -----------------
@app.route("/api/profile")
def api_get_profile():
    phone = request.args.get("phone", "").strip()
    if not phone:
        return jsonify({"error": "Phone required"}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT phone, display_name, bio, avatar_color, avatar_emoji, last_online, avatar_photo, banner_photo, email FROM users WHERE phone=?", (phone,))
        row = c.fetchone()
    finally:
        return_db_connection(conn)
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "phone": row[0],
        "display_name": row[1] or "",
        "bio": row[2] or "",
        "avatar_color": row[3] or "#0E4950",
        "avatar_emoji": row[4] or "",
        "last_online": row[5] or "",
        "avatar_photo": row[6] or "",
        "banner_photo": row[7] or "",
        "email": row[8] or "",
    })

@app.route("/api/profile/update", methods=["POST"])
def api_update_profile():
    data = request.get_json() or {}
    phone = data.get("phone", "").strip()
    display_name = data.get("display_name", "").strip()[:40]
    bio = data.get("bio", "").strip()[:120]
    avatar_color = data.get("avatar_color", "#0E4950").strip()
    avatar_emoji = data.get("avatar_emoji", "").strip()
    email = data.get("email", "").strip().lower()
    if not phone:
        return jsonify({"success": False, "error": "Phone required"}), 400
    if email and not validate_email(email):
        return jsonify({"success": False, "error": "Please enter a valid email address"}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        if email:
            c.execute("""
                UPDATE users SET display_name=?, bio=?, avatar_color=?, avatar_emoji=?, email=?
                WHERE phone=?
            """, (display_name, bio, avatar_color, avatar_emoji, email, phone))
        else:
            # Don't overwrite an existing email with a blank one — only
            # update it when the person actually provided a new value.
            c.execute("""
                UPDATE users SET display_name=?, bio=?, avatar_color=?, avatar_emoji=?
                WHERE phone=?
            """, (display_name, bio, avatar_color, avatar_emoji, phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    cache.delete(f"profile_{phone}")
    return jsonify({"success": True})

# ----------------- Profile Photo Upload -----------------
AVATAR_UPLOAD_FOLDER = os.path.join(app.config['UPLOAD_FOLDER'], 'avatars')
os.makedirs(AVATAR_UPLOAD_FOLDER, exist_ok=True)
ALLOWED_AVATAR_EXTS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}

@app.route("/api/profile/upload_photo", methods=["POST"])
def api_upload_profile_photo():
    phone = request.form.get("phone", "").strip()
    if not phone:
        return jsonify({"success": False, "error": "Phone required"}), 400
    if 'photo' not in request.files:
        return jsonify({"success": False, "error": "No file"}), 400
    f = request.files['photo']
    if not f or f.filename == '':
        return jsonify({"success": False, "error": "Empty file"}), 400
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ALLOWED_AVATAR_EXTS:
        return jsonify({"success": False, "error": "Invalid file type"}), 400
    # Limit to 5 MB
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > 5 * 1024 * 1024:
        return jsonify({"success": False, "error": "File too large (max 5 MB)"}), 400
    filename = f"avatar_{phone.replace('+','')}.{ext}"
    path = os.path.join(AVATAR_UPLOAD_FOLDER, filename)
    f.save(path)
    photo_url = f"/uploads/avatars/{filename}"
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE users SET avatar_photo=? WHERE phone=?", (photo_url, phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    cache.delete(f"profile_{phone}")
    return jsonify({"success": True, "photo_url": photo_url})

@app.route("/uploads/avatars/<path:filename>")
def serve_avatar(filename):
    from flask import send_from_directory as sfd, make_response
    resp = make_response(sfd(AVATAR_UPLOAD_FOLDER, filename))
    # Avatars/covers get overwritten in place (same filename each time a
    # user updates their photo). Without this, browsers/mobile devices can
    # keep showing the old cached image after an update. 'no-cache' still
    # allows caching, it just forces a revalidation (conditional GET) with
    # the server every time, so a genuinely new file is always picked up.
    resp.headers['Cache-Control'] = 'no-cache, must-revalidate'
    return resp

@app.route("/api/profile/upload_banner", methods=["POST"])
def api_upload_banner_photo():
    phone = request.form.get("phone", "").strip()
    if not phone:
        return jsonify({"success": False, "error": "Phone required"}), 400
    if 'photo' not in request.files:
        return jsonify({"success": False, "error": "No file"}), 400
    f = request.files['photo']
    if not f or f.filename == '':
        return jsonify({"success": False, "error": "Empty file"}), 400
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ALLOWED_AVATAR_EXTS:
        return jsonify({"success": False, "error": "Invalid file type"}), 400
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > 8 * 1024 * 1024:
        return jsonify({"success": False, "error": "File too large (max 8 MB)"}), 400
    filename = f"banner_{phone.replace('+','')}.{ext}"
    path = os.path.join(AVATAR_UPLOAD_FOLDER, filename)
    f.save(path)
    photo_url = f"/uploads/avatars/{filename}"
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE users SET banner_photo=? WHERE phone=?", (photo_url, phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    cache.delete(f"profile_{phone}")
    return jsonify({"success": True, "banner_url": photo_url})
