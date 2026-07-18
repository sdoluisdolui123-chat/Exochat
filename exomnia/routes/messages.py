"""
Message history API (paginated, decrypts on read).
"""
from flask import request, jsonify

from ..extensions import app
from ..db import get_db_connection, return_db_connection
from ..cache import cache
from ..crypto import encryptor


@app.route("/api/get_messages")
def api_get_messages():
    user_phone    = request.args.get("user_phone")
    contact_phone = request.args.get("contact_phone")
    page          = request.args.get("page", 1, type=int)
    limit         = request.args.get("limit", 50, type=int)
    offset        = (page - 1) * limit

    if not all([user_phone, contact_phone]):
        return jsonify([]), 400

    # Cache page 1 results (invalidated on new message)
    # Skip cache entirely when caller passes a cache-bust timestamp (_=...)
    cache_bust = request.args.get('_')
    cache_key = f"msgs_{min(user_phone,contact_phone)}_{max(user_phone,contact_phone)}_p{page}"
    if not cache_bust:
        cached = cache.get(cache_key)
        if cached is not None:
            return jsonify(cached)
    else:
        cached = None

    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("""
                SELECT m.id, m.sender, m.receiver, m.message, m.encrypted_message,
                       m.status, m.timestamp, m.message_type,
                       m.file_path, m.file_name, m.file_size, m.thumbnail_path
                FROM messages m
                WHERE ((m.sender=? AND m.receiver=?) OR (m.sender=? AND m.receiver=?))
                  AND (m.deleted_for IS NULL OR instr(','||m.deleted_for||',', ','||?||',') = 0)
                ORDER BY m.timestamp ASC
                LIMIT ? OFFSET ?
            """, (user_phone, contact_phone, contact_phone, user_phone, user_phone, limit, offset))
            messages_data = c.fetchall()

            message_ids = [m[0] for m in messages_data]
            reactions_dict = {}
            if message_ids:
                placeholders = ','.join('?' * len(message_ids))
                c.execute(f"""
                    SELECT message_id, user_phone, emoji
                    FROM message_reactions
                    WHERE message_id IN ({placeholders})
                """, message_ids)
                for msg_id, r_phone, r_emoji in c.fetchall():
                    reactions_dict.setdefault(msg_id, []).append(
                        {'user_phone': r_phone, 'emoji': r_emoji}
                    )
        finally:
            return_db_connection(conn)

        messages = []
        for row in messages_data:
            (message_id, sender, receiver, plaintext, encrypted, status, timestamp,
             message_type, file_path, file_name, file_size, thumbnail_path) = row

            mtype = message_type or 'text'
            if mtype == 'text':
                if encrypted:
                    decrypted = encryptor.decrypt_message(encrypted, sender, receiver)
                    content = decrypted if decrypted is not None else (plaintext or '')
                else:
                    content = plaintext or ''
            else:
                content = file_name or mtype

            messages.append({
                "id":             message_id,
                "sender":         sender,
                "receiver":       receiver,
                "message":        content,
                "status":         status,
                "timestamp":      timestamp,
                "reactions":      reactions_dict.get(message_id, []),
                "message_type":   mtype,
                "file_path":      file_path,
                "file_name":      file_name,
                "file_size":      file_size,
                "thumbnail_path": thumbnail_path,
            })

        cache.set(cache_key, messages)
        return jsonify(messages)

    except Exception as e:
        print(f"Error in api_get_messages: {e}")
        return jsonify([]), 500
