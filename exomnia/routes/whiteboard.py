"""
Interactive whiteboard pages: one for a group, one for a 1:1 chat.
Reuses the same access checks as group_chat_page()/chat_page() so a
user can only open a board for a group they belong to.
"""
from flask import render_template, request, redirect, url_for

from ..extensions import app
from ..db import get_db_connection, return_db_connection
from ..chat_utils import get_room, _resolve_display_name


@app.route("/whiteboard/group/<int:group_id>")
def group_whiteboard_page(group_id):
    phone = request.args.get("phone")
    if not phone:
        return redirect(url_for('signin'))
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_phone=?", (group_id, phone))
            if not c.fetchone():
                return "Access denied", 403
            c.execute("SELECT name FROM groups WHERE id=?", (group_id,))
            g = c.fetchone()
            if not g:
                return "Group not found", 404
            group_name = g[0]
        finally:
            return_db_connection(conn)

        room = f"wb_group_{group_id}"
        my_name = _resolve_display_name(phone, phone) or phone
        return render_template(
            "whiteboard.html",
            phone=phone,
            room=room,
            board_title=group_name,
            my_name=my_name,
            back_url=url_for('group_chat_page', group_id=group_id, phone=phone),
        )
    except Exception as e:
        print(f"Error in group_whiteboard_page: {e}")
        return "An error occurred", 500


@app.route("/whiteboard/dm/<contact_phone>")
def dm_whiteboard_page(contact_phone):
    phone = request.args.get("phone")
    if not phone:
        return redirect(url_for('signin'))
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT contact_name FROM contacts WHERE user_phone=? AND contact_phone=?", (phone, contact_phone))
            row = c.fetchone()
        finally:
            return_db_connection(conn)

        board_title = row[0] if row and row[0] else contact_phone
        room = f"wb_dm_{get_room(phone, contact_phone)}"
        my_name = _resolve_display_name(phone, phone) or phone
        return render_template(
            "whiteboard.html",
            phone=phone,
            room=room,
            board_title=board_title,
            my_name=my_name,
            back_url=url_for('chat_page', contact_phone=contact_phone, phone=phone),
        )
    except Exception as e:
        print(f"Error in dm_whiteboard_page: {e}")
        return "An error occurred", 500
