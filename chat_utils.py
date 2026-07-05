"""
Shared helpers for real-time chat: room naming, presence tracking,
and notification-preview text. Used by both sockets.py and the
voice/presence HTTP routes.
"""
from .extensions import socketio
from .db import get_db_connection, return_db_connection


# ----------------- Chat helpers -----------------
def get_room(user, contact):
    """Create consistent room name for two users"""
    try:
        user = str(user).strip()
        contact = str(contact).strip()
        
        users = [user, contact]
        users.sort(key=str.lower)
        
        room = f"room_{users[0]}_{users[1]}"
        
        print(f"Room created: {room} for users {user} and {contact}")
        return room
    except Exception as e:
        print(f"Error in get_room: {e}, user={user}, contact={contact}")
        return f"room_{user}_{contact}"

def _file_preview_text(message_type, file_name=None):
    """Friendly one-line preview for non-text messages, used in notifications."""
    icons = {'image': '📷 Photo', 'video': '🎥 Video', 'audio': '🎵 Audio', 'voice': '🎤 Voice message'}
    return icons.get(message_type, '📎 ' + (file_name or 'File'))

def _resolve_display_name(viewer_phone, target_phone):
    """Best-effort friendly name for target_phone, as seen by viewer_phone.
    Falls back to the target's own profile display_name, then their phone."""
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT contact_name FROM contacts WHERE user_phone=? AND contact_phone=?",
                  (viewer_phone, target_phone))
        row = c.fetchone()
        if row and row[0]:
            return row[0]
        c.execute("SELECT display_name FROM users WHERE phone=?", (target_phone,))
        row = c.fetchone()
        if row and row[0]:
            return row[0]
    except Exception as e:
        print(f"Error resolving display name: {e}")
    finally:
        return_db_connection(conn)
    return target_phone

connected_users = {}      # sid -> {phone, room, contact}
online_users   = {}      # phone -> set of sids  (multiple tabs)

def _user_online(phone):
    return bool(online_users.get(phone))

def _broadcast_presence(phone, contact, status, last_online=None):
    """Emit a presence update to the room shared by phone and contact."""
    room = get_room(phone, contact)
    socketio.emit('presence_update', {
        'phone':       phone,
        'status':      status,          # 'online' | 'offline'
        'last_online': last_online,
    }, room=room)

