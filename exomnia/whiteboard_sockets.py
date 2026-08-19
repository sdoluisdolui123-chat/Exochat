"""
Real-time Socket.IO handlers for the collaborative whiteboard.

Kept separate from sockets.py (which already covers 1:1/group chat)
so the two features stay easy to review independently. Registered the
same way: import this module once from app.py and every @socketio.on
decorator below fires.

State is kept in memory per room (a list of finished strokes/images).
That's enough for "reconnect / open the board on another device and
see what's already there" without adding a DB table; a server
restart clears boards, which is an acceptable trade-off for an
in-session collaboration tool. Swap `_wb_state` for a DB-backed store
later if boards need to outlive a restart.
"""
from flask import request
from flask_socketio import emit, join_room, leave_room

from .extensions import socketio

# room -> list of finished shapes: {id, type: 'stroke'|'image', ...}
_wb_state = {}
# room -> {sid: {'phone': str, 'name': str}}  (who's currently on the board)
_wb_presence = {}

MAX_SHAPES_PER_ROOM = 3000  # keep memory bounded for long-running boards


def _presence_list(room):
    return [
        {"phone": v["phone"], "name": v["name"]}
        for v in _wb_presence.get(room, {}).values()
    ]


@socketio.on('wb_join')
def on_wb_join(data):
    try:
        room = str(data.get('room', '')).strip()
        phone = str(data.get('phone', '')).strip()
        name = str(data.get('name') or phone).strip()
        if not room or not phone:
            return

        join_room(room)
        _wb_presence.setdefault(room, {})[request.sid] = {'phone': phone, 'name': name}

        # Send the new joiner everything drawn so far, and who else is here.
        emit('wb_history', {
            'shapes': _wb_state.get(room, []),
            'participants': _presence_list(room),
        }, room=request.sid)

        # Let everyone already on the board know someone joined.
        emit('wb_presence', {'participants': _presence_list(room)}, room=room)
    except Exception as e:
        print(f"Error in wb_join: {e}")


@socketio.on('wb_leave')
def on_wb_leave(data):
    try:
        room = str(data.get('room', '')).strip()
        if not room:
            return
        _wb_presence.get(room, {}).pop(request.sid, None)
        leave_room(room)
        emit('wb_presence', {'participants': _presence_list(room)}, room=room)
    except Exception as e:
        print(f"Error in wb_leave: {e}")


def handle_disconnect(sid):
    """Called from sockets.py's single shared on_disconnect handler
    (Flask-SocketIO only keeps one handler per event, so whiteboard
    cleanup can't register its own @socketio.on('disconnect') without
    silently replacing the chat one — see app.py wiring notes)."""
    try:
        for room, members in list(_wb_presence.items()):
            if sid in members:
                members.pop(sid, None)
                emit('wb_presence', {'participants': _presence_list(room)}, room=room)
                if not members:
                    _wb_presence.pop(room, None)
    except Exception as e:
        print(f"Error in wb disconnect cleanup: {e}")


@socketio.on('wb_draw_move')
def on_wb_draw_move(data):
    """Live in-progress stroke segment — broadcast only, not stored.
    Lets collaborators watch each other draw in real time; the final,
    complete stroke arrives separately via wb_stroke and IS stored."""
    try:
        room = str(data.get('room', '')).strip()
        if not room:
            return
        emit('wb_draw_move', {
            'stroke_id': data.get('stroke_id'),
            'points': data.get('points', []),
            'color': data.get('color'),
            'size': data.get('size'),
            'tool': data.get('tool'),
            'phone': data.get('phone'),
        }, room=room, include_self=False)
    except Exception as e:
        print(f"Error in wb_draw_move: {e}")


@socketio.on('wb_stroke')
def on_wb_stroke(data):
    """A finished pen/eraser stroke — persisted for late joiners."""
    try:
        room = str(data.get('room', '')).strip()
        stroke = data.get('stroke')
        if not room or not isinstance(stroke, dict) or not stroke.get('points'):
            return

        shape = {
            'id': stroke.get('id'),
            'type': 'stroke',
            'tool': stroke.get('tool', 'pen'),
            'color': stroke.get('color', '#1a2e2f'),
            'size': stroke.get('size', 4),
            'points': stroke.get('points', []),
            'phone': data.get('phone'),
        }
        shapes = _wb_state.setdefault(room, [])
        shapes.append(shape)
        if len(shapes) > MAX_SHAPES_PER_ROOM:
            del shapes[: len(shapes) - MAX_SHAPES_PER_ROOM]

        emit('wb_stroke', {'shape': shape}, room=room, include_self=False)
    except Exception as e:
        print(f"Error in wb_stroke: {e}")


@socketio.on('wb_image')
def on_wb_image(data):
    """A dropped-in image (already resized/compressed client-side)."""
    try:
        room = str(data.get('room', '')).strip()
        img = data.get('image')
        if not room or not isinstance(img, dict) or not img.get('src'):
            return

        shape = {
            'id': img.get('id'),
            'type': 'image',
            'src': img.get('src'),
            'x': img.get('x', 40), 'y': img.get('y', 40),
            'w': img.get('w', 240), 'h': img.get('h', 180),
            'phone': data.get('phone'),
        }
        shapes = _wb_state.setdefault(room, [])
        shapes.append(shape)
        if len(shapes) > MAX_SHAPES_PER_ROOM:
            del shapes[: len(shapes) - MAX_SHAPES_PER_ROOM]

        emit('wb_image', {'shape': shape}, room=room, include_self=False)
    except Exception as e:
        print(f"Error in wb_image: {e}")


@socketio.on('wb_shape')
def on_wb_shape(data):
    """A placed shape object: rectangle, ellipse, line, arrow, text, or
    sticky note. Structurally these are all just dicts with a 'type'
    field, so one generic handler covers every kind (mirrors wb_image)."""
    try:
        room = str(data.get('room', '')).strip()
        shape = data.get('shape')
        if not room or not isinstance(shape, dict) or not shape.get('id') or not shape.get('type'):
            return
        shape = dict(shape)
        shape['phone'] = data.get('phone')

        shapes = _wb_state.setdefault(room, [])
        shapes.append(shape)
        if len(shapes) > MAX_SHAPES_PER_ROOM:
            del shapes[: len(shapes) - MAX_SHAPES_PER_ROOM]

        emit('wb_shape', {'shape': shape}, room=room, include_self=False)
    except Exception as e:
        print(f"Error in wb_shape: {e}")


@socketio.on('wb_shape_update')
def on_wb_shape_update(data):
    """An existing shape was moved or edited (select-tool drag, or
    sticky/text content edit). Replaces the stored shape by id so late
    joiners see the latest version."""
    try:
        room = str(data.get('room', '')).strip()
        shape = data.get('shape')
        if not room or not isinstance(shape, dict) or not shape.get('id'):
            return
        shape = dict(shape)
        shape['phone'] = data.get('phone')

        shapes = _wb_state.setdefault(room, [])
        for i, s in enumerate(shapes):
            if s.get('id') == shape['id']:
                shapes[i] = shape
                break
        else:
            shapes.append(shape)

        emit('wb_shape_update', {'shape': shape}, room=room, include_self=False)
    except Exception as e:
        print(f"Error in wb_shape_update: {e}")


@socketio.on('wb_delete')
def on_wb_delete(data):
    """Remove a single shape/stroke/image by id (used by the select
    tool's delete action and by undo)."""
    try:
        room = str(data.get('room', '')).strip()
        shape_id = data.get('id')
        if not room or not shape_id:
            return
        shapes = _wb_state.get(room, [])
        _wb_state[room] = [s for s in shapes if s.get('id') != shape_id]
        emit('wb_delete', {'id': shape_id, 'phone': data.get('phone')}, room=room, include_self=False)
    except Exception as e:
        print(f"Error in wb_delete: {e}")


@socketio.on('wb_clear')
def on_wb_clear(data):
    try:
        room = str(data.get('room', '')).strip()
        if not room:
            return
        _wb_state[room] = []
        emit('wb_clear', {'phone': data.get('phone')}, room=room)
    except Exception as e:
        print(f"Error in wb_clear: {e}")


@socketio.on('wb_cursor')
def on_wb_cursor(data):
    """Lightweight cursor-position broadcast so collaborators can see
    where everyone else is pointing (not stored, fire-and-forget)."""
    try:
        room = str(data.get('room', '')).strip()
        if not room:
            return
        emit('wb_cursor', {
            'phone': data.get('phone'),
            'name': data.get('name'),
            'x': data.get('x'),
            'y': data.get('y'),
        }, room=room, include_self=False)
    except Exception as e:
        print(f"Error in wb_cursor: {e}")
