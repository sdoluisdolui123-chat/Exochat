"""
1:1 chat page (loads recent history + renders the chat UI shell).
"""
from flask import render_template, request, redirect, url_for

from ..extensions import app
from ..db import get_db_connection, return_db_connection
from ..cache import cache
from ..crypto import encryptor


@app.route("/chat/<contact_phone>")
def chat_page(contact_phone):
    phone = request.args.get("phone")
    if not phone:
        return redirect(url_for('signin'))
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT contact_name FROM contacts WHERE user_phone=? AND contact_phone=?", (phone, contact_phone))
            row = c.fetchone()
            c.execute("""
                SELECT id, sender, receiver, message, encrypted_message, status, timestamp,
                       message_type, file_path, file_name, file_size, thumbnail_path
                FROM messages
                WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
                ORDER BY timestamp ASC
                LIMIT 100
            """, (phone, contact_phone, contact_phone, phone))
            messages_data = c.fetchall()

            # Process messages
            messages = []
            for m in messages_data:
                message_id, sender, receiver, plaintext, encrypted, status, timestamp, message_type, file_path, file_name, file_size, thumbnail_path = m

                if message_type == 'text':
                    if encrypted:
                        decrypted = encryptor.decrypt_message(encrypted, sender, receiver)
                        msg_text = decrypted if decrypted is not None else plaintext
                    else:
                        msg_text = plaintext
                    messages.append({
                        "id": message_id, "sender": sender, "receiver": receiver,
                        "message": msg_text, "status": status, "timestamp": timestamp,
                        "message_type": "text"
                    })
                else:
                    messages.append({
                        "id": message_id,
                        "sender": sender,
                        "receiver": receiver,
                        "message": f"Sent a {message_type}",
                        "status": status,
                        "timestamp": timestamp,
                        "message_type": message_type,
                        "file_path": file_path,
                        "file_name": file_name,
                        "file_size": file_size,
                        "thumbnail_path": thumbnail_path
                    })

            c.execute("UPDATE messages SET status='seen' WHERE receiver=? AND sender=? AND status!='seen'", (phone, contact_phone))
            # Ensure a contacts row exists so the chat is accessible from both sides
            c.execute("""INSERT OR IGNORE INTO contacts(user_phone,contact_phone,contact_name,last_message,last_sender)
                         VALUES(?,?,'',(SELECT message FROM messages WHERE ((sender=? AND receiver=?) OR (sender=? AND receiver=?)) ORDER BY timestamp DESC LIMIT 1),'')""",
                      (phone, contact_phone, phone, contact_phone, contact_phone, phone))
            conn.commit()
        finally:
            return_db_connection(conn)
        # Bust contacts cache so unread badge clears immediately when returning to the list
        cache.delete(f"contacts_{phone}")
        contact_name = row[0] if row and row[0] else contact_phone
        return render_template("chat.html", phone=phone, contact_phone=contact_phone, contact_name=contact_name, messages=messages)
    except Exception as e:
        print(f" Error in chat_page: {e}")
        return "An error occurred", 500
