"""
Voice-message upload/history/delete + generic message delete + presence API.
"""
import os
import json
import uuid
import hashlib
from datetime import datetime

from flask import request, jsonify, send_from_directory

from ..extensions import app, socketio, VOICE_UPLOAD_FOLDER, ALLOWED_AUDIO_EXTENSIONS, MAX_VOICE_FILE_SIZE
from ..db import get_db_connection, return_db_connection
from ..cache import cache
from ..chat_utils import _resolve_display_name, _user_online


def _voice_waveform(seed, bars=40):
    import random
    rng = random.Random(hashlib.md5(seed.encode()).hexdigest())
    return [round(rng.uniform(0.15, 1.0), 3) for _ in range(bars)]

@app.route('/api/voice/upload', methods=['POST'])
def voice_upload():
    if 'audio' not in request.files:
        return jsonify({'success': False, 'error': 'No audio file'}), 400
    audio_file  = request.files['audio']
    sender      = request.form.get('sender', '').strip()
    receiver    = request.form.get('receiver', '').strip()
    group_id    = request.form.get('group_id', type=int)
    duration_ms = request.form.get('duration_ms', 0, type=int)
    waveform    = request.form.get('waveform')
    if not sender:
        return jsonify({'success': False, 'error': 'Missing sender'}), 400
    if not receiver and not group_id:
        return jsonify({'success': False, 'error': 'Missing receiver or group_id'}), 400
    ext = (audio_file.filename.rsplit('.', 1)[-1].lower()
           if '.' in (audio_file.filename or '') else 'webm')
    if ext not in ALLOWED_AUDIO_EXTENSIONS:
        ext = 'webm'
    audio_data = audio_file.read()
    if len(audio_data) > MAX_VOICE_FILE_SIZE:
        return jsonify({'success': False, 'error': 'File too large (max 10 MB)'}), 413
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    file_path   = os.path.join(VOICE_UPLOAD_FOLDER, unique_name)

    # Parse/validate waveform first — cheap, no I/O
    if waveform:
        try:
            bars = json.loads(waveform)
            assert isinstance(bars, list) and len(bars) > 0
            waveform_json = json.dumps([max(0.0, min(1.0, float(b))) for b in bars[:60]])
        except Exception:
            waveform_json = json.dumps(_voice_waveform(unique_name))
    else:
        waveform_json = json.dumps(_voice_waveform(unique_name))

    timestamp = datetime.now().isoformat()
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO voice_messages
                (sender,receiver,group_id,file_path,file_name,file_size,
                 duration_ms,waveform_data,status,timestamp)
            VALUES (?,?,?,?,?,?,?,?,'sent',?)
        """, (sender, receiver or None, group_id, file_path, unique_name,
              len(audio_data), duration_ms, waveform_json, timestamp))
        conn.commit()
        voice_id = c.lastrowid
    finally:
        return_db_connection(conn)

    # Update contacts last_message for DM voice messages
    if not group_id and receiver:
        try:
            conn2 = get_db_connection()
            try:
                c2 = conn2.cursor()
                c2.execute("INSERT OR IGNORE INTO contacts(user_phone,contact_phone,contact_name,last_message,last_sender) VALUES(?,?,?,?,?)",
                           (sender, receiver, "", "🎤 Voice message", sender))
                c2.execute("UPDATE contacts SET last_message='🎤 Voice message', last_sender=?, timestamp=? WHERE user_phone=? AND contact_phone=?",
                           (sender, timestamp, sender, receiver))
                c2.execute("INSERT OR IGNORE INTO contacts(user_phone,contact_phone,contact_name,last_message,last_sender) VALUES(?,?,?,?,?)",
                           (receiver, sender, "", "🎤 Voice message", sender))
                c2.execute("UPDATE contacts SET last_message='🎤 Voice message', last_sender=?, timestamp=? WHERE user_phone=? AND contact_phone=?",
                           (sender, timestamp, receiver, sender))
                conn2.commit()
                # Invalidate contacts cache for both users
                cache.delete(f"contacts_{sender}")
                cache.delete(f"contacts_{receiver}")
            finally:
                return_db_connection(conn2)
        except Exception:
            pass

    payload = {
        'success': True, 'id': voice_id, 'sender': sender,
        'receiver': receiver or None, 'group_id': group_id,
        'file_name': unique_name, 'file_size': len(audio_data),
        'duration_ms': duration_ms, 'waveform': json.loads(waveform_json),
        'timestamp': timestamp, 'status': 'sent', 'message_type': 'voice',
    }

    # Emit to room BEFORE writing file to disk — receivers get notified immediately
    if group_id:
        socketio.emit('voice_message', payload, room=f'group_{group_id}')
        # Invalidate voice history cache for this group
        cache.delete(f"voice_history_group_{group_id}_0_30")
        cache.delete(f"voice_history_group_{group_id}_0_50")
    else:
        users = sorted([sender, receiver], key=str.lower)
        socketio.emit('voice_message', payload, room=f'room_{users[0]}_{users[1]}')
        cache.delete(f"voice_history_dm_{'_'.join(users)}_0_30")
        cache.delete(f"voice_history_dm_{'_'.join(users)}_0_50")

    # Write file after emitting — client already has the response, disk I/O doesn't block UX
    with open(file_path, 'wb') as f:
        f.write(audio_data)

    # Notify recipients everywhere they're connected, regardless of which page they're on
    try:
        if group_id:
            conn3 = get_db_connection()
            try:
                c3 = conn3.cursor()
                c3.execute("SELECT name FROM groups WHERE id=?", (group_id,))
                grow = c3.fetchone()
                group_name = grow[0] if grow else 'Group'
                c3.execute("SELECT user_phone FROM group_members WHERE group_id=? AND user_phone!=?", (group_id, sender))
                other_members = [r[0] for r in c3.fetchall()]
            finally:
                return_db_connection(conn3)
            sender_name = _resolve_display_name(sender, sender)
            for member in other_members:
                socketio.emit('new_message_notification', {
                    'id': 'voice-' + str(voice_id), 'type': 'group', 'group_id': group_id, 'group_name': group_name,
                    'sender': sender, 'sender_name': sender_name,
                    'preview': '🎤 Voice message', 'timestamp': timestamp
                }, room=f'user_{member}')
        elif receiver:
            sender_name = _resolve_display_name(receiver, sender)
            socketio.emit('new_message_notification', {
                'id': 'voice-' + str(voice_id), 'type': 'dm', 'sender': sender, 'sender_name': sender_name,
                'preview': '🎤 Voice message', 'timestamp': timestamp
            }, room=f'user_{receiver}')
    except Exception as ne:
        print(f"Error emitting voice notification: {ne}")

    return jsonify(payload)

@app.route('/api/voice/file/<filename>')
def serve_voice_file(filename):
    try:
        from flask import make_response
        safe = os.path.basename(filename)
        ext = safe.rsplit('.', 1)[-1].lower() if '.' in safe else 'webm'
        mime_map = {'webm': 'audio/webm', 'ogg': 'audio/ogg', 'm4a': 'audio/mp4', 'mp4': 'audio/mp4', 'aac': 'audio/aac'}
        content_type = mime_map.get(ext, 'audio/webm')
        resp = make_response(send_from_directory(VOICE_UPLOAD_FOLDER, safe))
        resp.headers['Content-Type'] = content_type
        resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        resp.headers['Accept-Ranges'] = 'bytes'
        return resp
    except FileNotFoundError:
        return "File not found", 404

@app.route('/api/voice/history')
def voice_history():
    sender     = request.args.get('sender', '').strip()
    receiver   = request.args.get('receiver', '').strip()
    group_id   = request.args.get('group_id', type=int)
    user_phone = request.args.get('user_phone', '').strip()
    limit      = request.args.get('limit', 30, type=int)
    offset     = request.args.get('offset', 0, type=int)

    # Serve from cache when possible
    if group_id:
        cache_key = f"voice_history_group_{group_id}_{offset}_{limit}"
    else:
        users = sorted([sender, receiver], key=str.lower)
        cache_key = f"voice_history_dm_{'_'.join(users)}_{offset}_{limit}"
    cached = cache.get(cache_key)
    if cached:
        return jsonify(cached)

    conn = get_db_connection()
    try:
        c = conn.cursor()
        if group_id:
            c.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_phone=?", (group_id, user_phone))
            if not c.fetchone():
                return jsonify([]), 403
            c.execute("""SELECT id,sender,receiver,group_id,file_name,file_size,
                                duration_ms,waveform_data,status,timestamp,listened_at
                         FROM voice_messages WHERE group_id=?
                         ORDER BY timestamp ASC LIMIT ? OFFSET ?""", (group_id, limit, offset))
        else:
            if not sender or not receiver:
                return jsonify([]), 400
            c.execute("""SELECT id,sender,receiver,group_id,file_name,file_size,
                                duration_ms,waveform_data,status,timestamp,listened_at
                         FROM voice_messages
                         WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
                         ORDER BY timestamp ASC LIMIT ? OFFSET ?""",
                      (sender, receiver, receiver, sender, limit, offset))
        rows = c.fetchall()
    finally:
        return_db_connection(conn)
    result = [{
        'id': r[0], 'sender': r[1], 'receiver': r[2], 'group_id': r[3],
        'file_name': r[4], 'file_size': r[5], 'duration_ms': r[6],
        'waveform': json.loads(r[7]) if r[7] else [],
        'status': r[8], 'timestamp': r[9], 'listened_at': r[10],
        'message_type': 'voice',
    } for r in rows]

    # Attach reactions for each voice message
    if result:
        ids = [m['id'] for m in result]
        conn2 = get_db_connection()
        try:
            c2 = conn2.cursor()
            placeholders = ','.join('?' * len(ids))
            c2.execute(f"SELECT message_id, user_phone, emoji FROM message_reactions WHERE message_id IN ({placeholders})", ids)
            react_dict = {}
            for msg_id, r_phone, r_emoji in c2.fetchall():
                react_dict.setdefault(msg_id, []).append({'user_phone': r_phone, 'emoji': r_emoji})
        finally:
            return_db_connection(conn2)
        for m in result:
            m['reactions'] = react_dict.get(m['id'], [])

    cache.set(cache_key, result)
    return jsonify(result)

@app.route('/api/voice/listened', methods=['POST'])
def voice_listened():
    data       = request.get_json() or {}
    voice_id   = data.get('id')
    user_phone = data.get('user_phone', '').strip()
    if not voice_id or not user_phone:
        return jsonify({'success': False}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE voice_messages SET status='listened',listened_at=? WHERE id=? AND receiver=?",
                  (datetime.now().isoformat(), voice_id, user_phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    socketio.emit('voice_listened', {'id': voice_id, 'listener': user_phone})
    return jsonify({'success': True})


@app.route('/api/message/delete', methods=['POST'])
def message_delete():
    data       = request.get_json() or {}
    message_id = data.get('id')
    user_phone = data.get('user_phone', '').strip()
    scope      = data.get('scope', 'me')  # 'me' or 'everyone'
    if not message_id or not user_phone:
        return jsonify({'success': False}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT sender, receiver, message_type FROM messages WHERE id=?", (message_id,))
        row = c.fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'Not found'}), 404
        sender, receiver, message_type = row
        if sender != user_phone:
            return jsonify({'success': False, 'error': 'Forbidden'}), 403

        if scope == 'everyone':
            # Delete file from disk if media
            if message_type in ('image', 'video', 'audio', 'file'):
                c.execute("SELECT file_path FROM messages WHERE id=?", (message_id,))
                fp = c.fetchone()
                if fp and fp[0]:
                    try: os.remove(fp[0])
                    except OSError: pass
            c.execute("DELETE FROM message_reactions WHERE message_id=?", (message_id,))
            c.execute("DELETE FROM messages WHERE id=?", (message_id,))
        else:
            # Delete only for me — mark deleted
            c.execute("UPDATE messages SET deleted_for=COALESCE(deleted_for||',','')||? WHERE id=?",
                      (user_phone, message_id))
        conn.commit()
    finally:
        return_db_connection(conn)

    # Invalidate message cache
    users = sorted([str(sender), str(receiver)], key=str.lower)
    cache.clear_pattern(f"msgs_{users[0]}_{users[1]}")

    # Real-time notification
    room = f"room_{users[0]}_{users[1]}"
    socketio.emit('message_deleted', {
        'id': message_id, 'sender': sender, 'receiver': receiver, 'scope': scope
    }, room=room)

    return jsonify({'success': True})

@app.route('/api/voice/delete', methods=['POST'])
def voice_delete():
    data       = request.get_json() or {}
    voice_id   = data.get('id')
    user_phone = data.get('user_phone', '').strip()
    if not voice_id or not user_phone:
        return jsonify({'success': False}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT file_path,sender,receiver,group_id FROM voice_messages WHERE id=?", (voice_id,))
        row = c.fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'Not found'}), 404
        file_path, sender, receiver, group_id = row
        if sender != user_phone:
            return jsonify({'success': False, 'error': 'Forbidden'}), 403
        try:
            os.remove(file_path)
        except OSError:
            pass
        # Delete associated reactions first
        c.execute("DELETE FROM message_reactions WHERE message_id=?", (voice_id,))
        c.execute("DELETE FROM voice_messages WHERE id=?", (voice_id,))
        conn.commit()
    finally:
        return_db_connection(conn)

    # Invalidate all voice history cache entries for this conversation
    if group_id:
        for lim in (30, 50):
            cache.delete(f"voice_history_group_{group_id}_0_{lim}")
        cache.clear_pattern(f"voice_history_group_{group_id}_")
    else:
        if sender and receiver:
            users = sorted([str(sender), str(receiver)], key=str.lower)
            key_prefix = f"voice_history_dm_{'_'.join(users)}_"
            cache.clear_pattern(key_prefix)

    # Notify all participants so the bubble is removed from their screen in real time
    payload = {'id': voice_id, 'sender': sender, 'receiver': receiver, 'group_id': group_id}
    if group_id:
        socketio.emit('voice_deleted', payload, room=f'group_{group_id}')
    else:
        users = sorted([str(sender), str(receiver)], key=str.lower)
        socketio.emit('voice_deleted', payload, room=f'room_{users[0]}_{users[1]}')

    return jsonify({'success': True})

@app.route('/api/presence/<phone>')
def api_presence(phone):
    if _user_online(phone):
        return jsonify({'phone': phone, 'status': 'online', 'last_online': None})
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT last_online FROM users WHERE phone=?", (phone,))
        row = c.fetchone()
        last_online = row[0] if row else None
    finally:
        return_db_connection(conn)
    return jsonify({'phone': phone, 'status': 'offline', 'last_online': last_online})
