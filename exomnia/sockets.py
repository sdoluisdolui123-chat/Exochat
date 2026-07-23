"""
Real-time Socket.IO event handlers for 1:1 chat, presence, typing and groups.
"""
from datetime import datetime

from flask import request
from flask_socketio import emit, join_room

from .extensions import socketio
from .db import get_db_connection, return_db_connection
from .cache import cache
from .crypto import encryptor
from .chat_utils import (
    get_room, _file_preview_text, _resolve_display_name,
    _user_online, _broadcast_presence, connected_users, online_users,
    _add_watcher, _notify_watchers,
)

typing_status = {}


@socketio.on('register_user')
def on_register_user(data):
    """Join this socket to the user's personal room so they receive
    new-message notifications no matter which page they're on
    (dashboard, a different 1:1 chat, or a different group).

    Also marks the user as online immediately, so contacts see an
    accurate status even when this user is just browsing the
    dashboard/contact list rather than inside a specific chat."""
    try:
        phone = str(data.get('phone', '')).strip()
        if phone:
            join_room(f'user_{phone}')

            sid = request.sid
            existing = connected_users.get(sid, {})
            connected_users[sid] = {'phone': phone, 'room': existing.get('room'), 'contact': existing.get('contact')}

            was_offline = phone not in online_users or not online_users[phone]
            if phone not in online_users:
                online_users[phone] = set()
            online_users[phone].add(sid)

            # Let anyone already watching this user (e.g. they have this
            # user's chat open) know right away that they're online, even
            # though this user hasn't opened a specific chat themselves yet.
            if was_offline:
                _notify_watchers(phone, 'online')
    except Exception as e:
        print(f"Error in register_user: {e}")

@socketio.on('join')
def on_join(data):
    try:
        user    = str(data['user'])
        contact = str(data['contact'])
        room    = get_room(user, contact)

        join_room(room)
        join_room(f'user_{user}')
        connected_users[request.sid] = {'phone': user, 'room': room, 'contact': contact}

        # Track online sids for this user
        if user not in online_users:
            online_users[user] = set()
        online_users[user].add(request.sid)

        # Update last_online in DB
        now_iso = datetime.now().isoformat()
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("UPDATE users SET last_online=? WHERE phone=?", (now_iso, user))
            conn.commit()
        finally:
            return_db_connection(conn)

        # Remember that `user` wants to know about `contact`'s presence from
        # now on, no matter what page `contact` is on when it changes.
        _add_watcher(contact, user)

        # Tell everyone watching this user (not just `contact`, in case this
        # user has other open chats too) that they're online
        _notify_watchers(user, 'online')

        # Tell this user whether their contact is currently online
        contact_online = _user_online(contact)
        if contact_online:
            emit('presence_update', {'phone': contact, 'status': 'online', 'last_online': None})
        else:
            # Fetch contact's last_online from DB
            conn2 = get_db_connection()
            try:
                c2 = conn2.cursor()
                c2.execute("SELECT last_online FROM users WHERE phone=?", (contact,))
                row = c2.fetchone()
                last_seen = row[0] if row else None
            finally:
                return_db_connection(conn2)
            emit('presence_update', {'phone': contact, 'status': 'offline', 'last_online': last_seen})

        if typing_status.get((user, contact)):
            emit('typing', {'actor': contact}, room=request.sid)

        emit('join_success', {'room': room, 'success': True}, room=request.sid)
    except Exception as e:
        print(f"Error in join: {e}")
        emit('error', {'message': 'Failed to join room'})

@socketio.on('disconnect')
def on_disconnect(reason=None):
    try:
        sid  = request.sid
        info = connected_users.pop(sid, None)
        if info:
            phone   = info['phone']
            contact = info.get('contact')

            # Remove this sid from online set
            if phone in online_users:
                online_users[phone].discard(sid)
                if not online_users[phone]:          # last tab closed
                    del online_users[phone]
                    # Stamp last_online in DB
                    now_iso = datetime.now().isoformat()
                    conn = get_db_connection()
                    try:
                        c = conn.cursor()
                        c.execute("UPDATE users SET last_online=? WHERE phone=?", (now_iso, phone))
                        conn.commit()
                    finally:
                        return_db_connection(conn)
                    # Notify everyone watching this user (every open chat
                    # that has this user as the contact), not just the one
                    # chat window this particular socket happened to be in.
                    _notify_watchers(phone, 'offline', now_iso)

        # Clean up stale typing statuses
        for key in list(typing_status.keys()):
            if typing_status.get(key):
                del typing_status[key]
    except Exception as e:
        print(f"Error in disconnect: {e}")


@socketio.on('send_message')
def handle_message(data):
    try:
        sender = str(data.get('sender', ''))
        receiver = str(data.get('receiver', ''))
        message = data.get('message', '').strip()
        if not all([sender, receiver, message]):
            emit('error', {'message': 'Invalid message data'})
            return
        if len(message) > 5000:
            emit('error', {'message': 'Message too long'})
            return

        encrypted_message = encryptor.encrypt_message(message, sender, receiver)
        if not encrypted_message:
            emit('error', {'message': 'Failed to encrypt message'})
            return

        now_iso = datetime.now().isoformat()
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("INSERT INTO messages(sender,receiver,message,encrypted_message,message_type,status,timestamp) VALUES(?,?,?,?,?,?,?)",
                      (sender, receiver, message, encrypted_message, "text", "sent", now_iso))
            message_id = c.lastrowid
            c.execute("INSERT OR IGNORE INTO users(phone,last_online) VALUES(?,?)", (receiver, now_iso))
            c.execute("INSERT OR IGNORE INTO contacts(user_phone,contact_phone,contact_name,last_message,last_sender) VALUES(?,?,?,?,?)",
                      (sender, receiver, "", message, sender))
            c.execute("UPDATE contacts SET last_message=?, last_sender=?, timestamp=CURRENT_TIMESTAMP WHERE user_phone=? AND contact_phone=?",
                      (message, sender, sender, receiver))
            c.execute("INSERT OR IGNORE INTO contacts(user_phone,contact_phone,contact_name,last_message,last_sender) VALUES(?,?,?,?,?)",
                      (receiver, sender, "", message, sender))
            c.execute("UPDATE contacts SET last_message=?, last_sender=?, timestamp=CURRENT_TIMESTAMP WHERE user_phone=? AND contact_phone=?",
                      (message, sender, receiver, sender))
            conn.commit()
        finally:
            return_db_connection(conn)
        temp_id = data.get('temp_id', None)
        room = get_room(sender, receiver)
        # Invalidate message cache so next page load fetches fresh messages
        cache.clear_pattern(f"msgs_{min(sender,receiver)}_{max(sender,receiver)}")
        emit('receive_message', {'id': message_id, 'sender': sender, 'receiver': receiver, 'message': message, 'temp_id': temp_id, 'timestamp': now_iso, 'status': 'sent'}, room=room)

        # Fallback delivery: also send the full message to the receiver's
        # personal room (joined reliably via register_user on every
        # connect/reconnect). If the receiver's specific chat-room join was
        # missed or delayed (flaky network, reconnect race, etc.), this
        # ensures the message still shows up in their open chat window
        # instead of only updating the contacts-list preview. The client
        # already dedupes by message id so receiving it twice is harmless.
        emit('receive_message', {'id': message_id, 'sender': sender, 'receiver': receiver, 'message': message, 'timestamp': now_iso, 'status': 'sent'}, room=f'user_{receiver}')

        # Also send to the sender's personal room so the dashboard can
        # update the contact row in real time when they're on Contacts page
        emit('receive_message', {'id': message_id, 'sender': sender, 'receiver': receiver, 'message': message, 'timestamp': now_iso, 'status': 'sent'}, room=f'user_{sender}')

        # Notify the receiver everywhere they're connected (dashboard, other open chats, etc.)
        try:
            sender_name = _resolve_display_name(receiver, sender)
            emit('new_message_notification', {
                'id': 'dm-' + str(message_id), 'type': 'dm', 'sender': sender, 'sender_name': sender_name,
                'preview': message[:120], 'timestamp': now_iso, 'last_sender': sender
            }, room=f'user_{receiver}')
        except Exception as ne:
            print(f"Error emitting message notification: {ne}")
        
    except Exception as e:
        print(f" Error in send_message: {e}")
        emit('error', {'message': 'Failed to send message'})

@socketio.on('send_file_message')
def handle_file_message(data):
    try:
        sender = str(data.get('sender', ''))
        receiver = str(data.get('receiver', ''))
        message_type = data.get('message_type', '')
        file_path = data.get('file_path', '')
        file_name = data.get('file_name', '')
        file_size = data.get('file_size', 0)
        message_id = data.get('message_id', '')

        if not all([sender, receiver, message_type, file_path]):
            emit('error', {'message': 'Invalid file message data'})
            return

        room = get_room(sender, receiver)
        emit('receive_file_message', {
            'id': message_id,
            'sender': sender,
            'receiver': receiver,
            'message_type': message_type,
            'file_path': file_path,
            'file_name': file_name,
            'file_size': file_size
        }, room=room, broadcast=True)

        # Also send to the sender's personal room for dashboard row update
        emit('receive_file_message', {
            'id': message_id,
            'sender': sender,
            'receiver': receiver,
            'message_type': message_type,
            'file_name': file_name
        }, room=f'user_{sender}')

        cache.clear_for_users(sender, receiver)
        cache.clear_pattern(f"msgs_{min(sender,receiver)}_{max(sender,receiver)}")

        # Notify the receiver everywhere they're connected
        try:
            sender_name = _resolve_display_name(receiver, sender)
            emit('new_message_notification', {
                'id': 'dm-' + str(message_id), 'type': 'dm', 'sender': sender, 'sender_name': sender_name,
                'preview': _file_preview_text(message_type, file_name),
                'timestamp': datetime.now().isoformat(), 'last_sender': sender
            }, room=f'user_{receiver}')
        except Exception as ne:
            print(f"Error emitting file notification: {ne}")

    except Exception as e:
        print(f"Error in send_file_message: {e}")
        emit('error', {'message': 'Failed to send file message'})

@socketio.on('add_reaction')
def handle_add_reaction(data):
    try:
        message_id = data.get('message_id')
        emoji = data.get('emoji')
        user_phone = data.get('user_phone')
        is_voice = data.get('is_voice', False)

        if not all([message_id, emoji, user_phone]):
            emit('error', {'message': 'Invalid reaction data'})
            return

        conn = get_db_connection()
        try:
            c = conn.cursor()

            # Check the correct table first based on is_voice flag.
            # Both tables use AUTOINCREMENT so their IDs overlap — always
            # check voice_messages first when the client says it's a voice reaction.
            sender, receiver, group_id = None, None, None
            if is_voice:
                c.execute("SELECT sender, receiver, group_id FROM voice_messages WHERE id=?", (message_id,))
                vmsg = c.fetchone()
                if vmsg:
                    sender, receiver, group_id = vmsg
                else:
                    emit('error', {'message': 'Message not found'})
                    return
            else:
                c.execute("SELECT sender, receiver FROM messages WHERE id=?", (message_id,))
                message = c.fetchone()
                if message:
                    sender, receiver = message
                else:
                    # Fallback: try voice_messages in case is_voice wasn't sent
                    c.execute("SELECT sender, receiver, group_id FROM voice_messages WHERE id=?", (message_id,))
                    vmsg = c.fetchone()
                    if vmsg:
                        sender, receiver, group_id = vmsg
                    else:
                        emit('error', {'message': 'Message not found'})
                        return

            c.execute("SELECT emoji FROM message_reactions WHERE message_id=? AND user_phone=?",
                     (message_id, user_phone))
            existing_reaction = c.fetchone()

            if existing_reaction:
                if existing_reaction[0] == emoji:
                    c.execute("DELETE FROM message_reactions WHERE message_id=? AND user_phone=?",
                             (message_id, user_phone))
                    action = 'removed'
                else:
                    c.execute("UPDATE message_reactions SET emoji=? WHERE message_id=? AND user_phone=?",
                             (emoji, message_id, user_phone))
                    action = 'updated'
            else:
                c.execute("INSERT INTO message_reactions (message_id, user_phone, emoji) VALUES (?, ?, ?)",
                         (message_id, user_phone, emoji))
                action = 'added'

            conn.commit()
            c.execute("SELECT user_phone, emoji FROM message_reactions WHERE message_id=?", (message_id,))
            updated_reactions = c.fetchall()
            reactions_list = [{'user_phone': r[0], 'emoji': r[1]} for r in updated_reactions]

        finally:
            return_db_connection(conn)

        payload = {
            'message_id': message_id,
            'user_phone': user_phone,
            'emoji': emoji,
            'action': action,
            'reactions': reactions_list,
            'is_voice': bool(is_voice)
        }

        if group_id:
            emit('reaction_updated', payload, room=f'group_{group_id}', broadcast=True)
        else:
            room = get_room(sender, receiver)
            emit('reaction_updated', payload, room=room, broadcast=True)

        if sender and receiver:
            cache.clear_for_users(sender, receiver)
        cache.clear_pattern(f"msgs_{min(sender,receiver)}_{max(sender,receiver)}")
        # Also invalidate voice history cache so reactions are fresh on next page load
        if sender and receiver:
            users = sorted([str(sender), str(receiver)], key=str.lower)
            for lim in (30, 50):
                cache.delete(f"voice_history_dm_{'_'.join(users)}_0_{lim}")
        if group_id:
            for lim in (30, 50):
                cache.delete(f"voice_history_group_{group_id}_0_{lim}")

    except Exception as e:
        print(f"Error in add_reaction: {e}")
        emit('error', {'message': 'Failed to add reaction'})

@socketio.on('join_group')
def on_join_group(data):
    try:
        group_id = str(data.get('group_id'))
        user = str(data.get('user'))
        room = f"group_{group_id}"
        join_room(room)
        join_room(f'user_{user}')
        emit('join_group_success', {'room': room, 'success': True}, room=request.sid)
    except Exception as e:
        print(f"Error in join_group: {e}")


@socketio.on('send_group_message')
def handle_group_message(data):
    try:
        group_id = data.get('group_id')
        sender = str(data.get('sender', ''))
        message = data.get('message', '').strip()
        temp_id = data.get('temp_id')
        message_type = data.get('message_type', 'text')
        file_path = data.get('file_path')
        file_name = data.get('file_name')
        file_size = data.get('file_size')

        if not group_id or not sender:
            emit('error', {'message': 'Invalid group message data'})
            return
        # For file messages the text body may be the filename; require either message or file_path
        if not message and not file_path:
            emit('error', {'message': 'Invalid group message data'})
            return

        # Verify membership
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_phone=?", (group_id, sender))
            if not c.fetchone():
                emit('error', {'message': 'Not a group member'})
                return

            now_iso = datetime.now().isoformat()
            c.execute("""
                INSERT INTO group_messages (group_id, sender, message, message_type, file_path, file_name, file_size, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (group_id, sender, message, message_type, file_path, file_name, file_size, now_iso))
            message_id = c.lastrowid

            # Resolve sender display name for recipients
            c.execute("SELECT name FROM groups WHERE id=?", (group_id,))
            group_row = c.fetchone()
            c.execute("SELECT user_phone FROM group_members WHERE group_id=? AND user_phone!=?", (group_id, sender))
            other_members = [r[0] for r in c.fetchall()]
            conn.commit()
        finally:
            return_db_connection(conn)

        room = f"group_{group_id}"
        emit('receive_group_message', {
            'id': message_id,
            'group_id': group_id,
            'sender': sender,
            'message': message,
            'message_type': message_type,
            'file_path': file_path,
            'file_name': file_name,
            'file_size': file_size,
            'temp_id': temp_id,
            'timestamp': now_iso
        }, room=room, broadcast=True)

        # Also send to the sender's personal room so the dashboard can
        # update the group row in real time when they're on the Contacts page
        emit('receive_group_message', {
            'id': message_id,
            'group_id': group_id,
            'sender': sender,
            'message': message,
            'message_type': message_type,
            'timestamp': now_iso
        }, room=f'user_{sender}')

        cache.clear_pattern(f"group_{group_id}")
        cache.clear_pattern(f"groups_")

        # Notify every other group member, regardless of which page they're on
        try:
            group_name = group_row[0] if group_row else 'Group'
            sender_name = _resolve_display_name(sender, sender)
            preview = message[:120] if message else _file_preview_text(message_type, file_name)
            for member in other_members:
                emit('new_message_notification', {
                    'id': 'grp-' + str(message_id), 'type': 'group', 'group_id': group_id, 'group_name': group_name,
                    'sender': sender, 'sender_name': sender_name,
                    'preview': preview, 'timestamp': now_iso
                }, room=f'user_{member}')
        except Exception as ne:
            print(f"Error emitting group notification: {ne}")

    except Exception as e:
        print(f"Error in send_group_message: {e}")
        emit('error', {'message': 'Failed to send group message'})


@socketio.on('group_typing')
def handle_group_typing(data):
    try:
        group_id = str(data.get('group_id'))
        user = str(data.get('user'))
        room = f"group_{group_id}"
        emit('group_typing', {'group_id': group_id, 'user': user}, room=room, broadcast=True)
    except Exception as e:
        print(f"Error in group_typing: {e}")


@socketio.on('group_stop_typing')
def handle_group_stop_typing(data):
    try:
        group_id = str(data.get('group_id'))
        user = str(data.get('user'))
        room = f"group_{group_id}"
        emit('group_stop_typing', {'group_id': group_id, 'user': user}, room=room, broadcast=True)
    except Exception as e:
        print(f"Error in group_stop_typing: {e}")


@socketio.on('add_group_reaction')
def handle_add_group_reaction(data):
    try:
        message_id = data.get('message_id')
        emoji = data.get('emoji')
        user_phone = data.get('user_phone')
        group_id = data.get('group_id')

        if not all([message_id, emoji, user_phone, group_id]):
            emit('error', {'message': 'Invalid group reaction data'})
            return

        conn = get_db_connection()
        try:
            c = conn.cursor()
            # Check group_messages first, then voice_messages
            c.execute("SELECT id FROM group_messages WHERE id=? AND group_id=?", (message_id, group_id))
            is_voice = False
            if not c.fetchone():
                c.execute("SELECT id FROM voice_messages WHERE id=? AND group_id=?", (message_id, group_id))
                if not c.fetchone():
                    emit('error', {'message': 'Message not found in group'})
                    return
                is_voice = True

            c.execute("SELECT emoji FROM message_reactions WHERE message_id=? AND user_phone=?",
                      (message_id, user_phone))
            existing = c.fetchone()

            if existing:
                if existing[0] == emoji:
                    c.execute("DELETE FROM message_reactions WHERE message_id=? AND user_phone=?",
                              (message_id, user_phone))
                    action = 'removed'
                else:
                    c.execute("UPDATE message_reactions SET emoji=? WHERE message_id=? AND user_phone=?",
                              (emoji, message_id, user_phone))
                    action = 'updated'
            else:
                c.execute("INSERT INTO message_reactions (message_id, user_phone, emoji) VALUES (?,?,?)",
                          (message_id, user_phone, emoji))
                action = 'added'
            conn.commit()

            c.execute("SELECT user_phone, emoji FROM message_reactions WHERE message_id=?", (message_id,))
            reactions_list = [{'user_phone': r[0], 'emoji': r[1]} for r in c.fetchall()]
        finally:
            return_db_connection(conn)

        room = f"group_{group_id}"
        emit('group_reaction_updated', {
            'message_id': message_id,
            'group_id': group_id,
            'user_phone': user_phone,
            'emoji': emoji,
            'action': action,
            'reactions': reactions_list,
            'is_voice': is_voice
        }, room=room, broadcast=True)

        # Invalidate voice history cache so reactions are fresh on next page load
        for lim in (30, 50):
            cache.delete(f"voice_history_group_{group_id}_0_{lim}")

    except Exception as e:
        print(f"Error in add_group_reaction: {e}")
        emit('error', {'message': 'Failed to add group reaction'})


@socketio.on('mark_seen')
def handle_mark_seen(data):
    try:
        sender = str(data.get('sender', ''))
        receiver = str(data.get('receiver', ''))

        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("UPDATE messages SET status='seen' WHERE sender=? AND receiver=? AND status!='seen'",
                     (sender, receiver))
            conn.commit()
        finally:
            return_db_connection(conn)
        # Bust receiver's contacts cache so badge clears immediately
        cache.delete(f"contacts_{receiver}")

        room = get_room(sender, receiver)
        emit('message_seen_confirmation', {
            'receiver': sender,
            'status': 'seen'
        }, room=room)

    except Exception as e:
        print(f"Error in mark_seen: {e}")

@socketio.on('typing')
def handle_typing(data):
    try:
        actor = str(data.get('actor', ''))
        target = str(data.get('target', ''))
        if not all([actor, target]):
            return
        typing_status[(target, actor)] = True
        room = get_room(actor, target)
        emit('typing', {'actor': actor}, room=room, broadcast=True)
    except Exception as e:
        print(f" Error in typing: {e}")

@socketio.on('stop_typing')
def handle_stop_typing(data):
    try:
        actor = str(data.get('actor', ''))
        target = str(data.get('target', ''))
        if not all([actor, target]):
            return
        typing_status[(target, actor)] = False
        room = get_room(actor, target)
        emit('stop_typing', {'actor': actor}, room=room, broadcast=True)
    except Exception as e:
        print(f"Error in stop_typing: {e}")

@socketio.on('set_presence')
def handle_set_presence(data):
    try:
        phone   = str(data.get('phone', ''))
        contact = str(data.get('contact', ''))
        status  = data.get('status', 'online')
        if not phone or not contact:
            return
        now_iso = datetime.now().isoformat()
        if status == 'away':
            # Treat away as offline for the contact's view
            _broadcast_presence(phone, contact, 'offline', now_iso)
        else:
            _broadcast_presence(phone, contact, 'online')
    except Exception as e:
        print(f"Error in set_presence: {e}")

@socketio.on('heartbeat')
def handle_heartbeat(data):
    try:
        phone = str(data.get('phone', ''))
        if phone:
            now_iso = datetime.now().isoformat()
            conn = get_db_connection()
            try:
                c = conn.cursor()
                c.execute("UPDATE users SET last_online=? WHERE phone=?", (now_iso, phone))
                conn.commit()
            finally:
                return_db_connection(conn)
    except Exception as e:
        print(f"Error in heartbeat: {e}")

@socketio.on_error_default
def default_error_handler(e):
    print(f"SocketIO Error: {e}")
    emit('error', {'message': 'An error occurred'})
