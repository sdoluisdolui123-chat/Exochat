"""
Group creation/membership APIs + the group chat page.
"""
from datetime import datetime

from flask import render_template, request, jsonify, redirect, url_for

from ..extensions import app, socketio
from ..db import get_db_connection, return_db_connection
from ..cache import cache


# ----------------- Group API Routes -----------------

@app.route("/api/groups")
def api_groups():
    phone = request.args.get("phone")
    if not phone:
        return jsonify([]), 400
    cache_key = f"groups_{phone}"
    cached = cache.get(cache_key)
    if cached is not None:
        return jsonify(cached)
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("""
                SELECT g.id, g.name, g.avatar_letter, g.created_by,
                       COUNT(gm2.user_phone) as member_count,
                       (SELECT gm3.message FROM group_messages gm3
                        WHERE gm3.group_id = g.id ORDER BY gm3.timestamp DESC LIMIT 1) as last_message,
                       (SELECT gm3.timestamp FROM group_messages gm3
                        WHERE gm3.group_id = g.id ORDER BY gm3.timestamp DESC LIMIT 1) as last_message_time,
                       (SELECT COUNT(*) FROM group_messages gm4
                        WHERE gm4.group_id = g.id
                          AND gm4.sender != ?) as unread_count,
                       CASE WHEN gm.user_phone IS NOT NULL THEN 0 ELSE 1 END as left_group
                FROM groups g
                LEFT JOIN group_members gm ON g.id = gm.group_id AND gm.user_phone = ?
                LEFT JOIN group_members gm2 ON g.id = gm2.group_id
                WHERE gm.user_phone IS NOT NULL OR g.created_by = ?
                GROUP BY g.id
                ORDER BY last_message_time DESC, g.created_at DESC
            """, (phone, phone, phone))
            rows = c.fetchall()
        finally:
            return_db_connection(conn)
        groups = [{"id": r[0], "name": r[1], "avatar_letter": r[2],
                   "created_by": r[3], "member_count": r[4], "last_message": r[5],
                   "last_message_time": r[6], "unread_count": r[7] or 0,
                   "left_group": bool(r[8])} for r in rows]
        cache.set(cache_key, groups)
        return jsonify(groups)
    except Exception as e:
        print(f"Error in api_groups: {e}")
        return jsonify([]), 500


@app.route("/api/delete_contact", methods=["POST"])
def api_delete_contact():
    try:
        data = request.get_json() or {}
        user_phone = str(data.get("user_phone", "")).strip()
        contact_phone = str(data.get("contact_phone", "")).strip()
        if not user_phone or not contact_phone:
            return jsonify({"success": False, "error": "Missing data"}), 400
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("DELETE FROM contacts WHERE user_phone=? AND contact_phone=?",
                      (user_phone, contact_phone))
            conn.commit()
        finally:
            return_db_connection(conn)
        cache.delete(f"contacts_{user_phone}")
        return jsonify({"success": True})
    except Exception as e:
        print(f"Error in delete_contact: {e}")
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/api/delete_group", methods=["POST"])
def api_delete_group():
    try:
        data = request.get_json() or {}
        group_id = data.get("group_id")
        user_phone = str(data.get("user_phone", "")).strip()
        if not group_id or not user_phone:
            return jsonify({"success": False, "error": "Missing data"}), 400
        conn = get_db_connection()
        action = None
        affected_members = []
        try:
            c = conn.cursor()
            # Only the group creator (admin) can delete the group entirely
            c.execute("SELECT created_by FROM groups WHERE id=?", (group_id,))
            row = c.fetchone()
            if not row:
                return jsonify({"success": False, "error": "Group not found"}), 404
            is_creator = str(row[0]) == user_phone
            if not is_creator:
                # Non-creators just leave the group instead
                c.execute("DELETE FROM group_members WHERE group_id=? AND user_phone=?",
                          (group_id, user_phone))
                conn.commit()
                action = "left"
                affected_members = [user_phone]
            else:
                # Creator deletes the group entirely (even if they already left)
                c.execute("SELECT user_phone FROM group_members WHERE group_id=?", (group_id,))
                affected_members = [r[0] for r in c.fetchall()]
                if user_phone not in affected_members:
                    affected_members.append(user_phone)
                c.execute("DELETE FROM message_reactions WHERE message_id IN "
                          "(SELECT id FROM group_messages WHERE group_id=?)", (group_id,))
                c.execute("DELETE FROM group_messages WHERE group_id=?", (group_id,))
                c.execute("DELETE FROM group_members WHERE group_id=?", (group_id,))
                c.execute("DELETE FROM groups WHERE id=?", (group_id,))
                conn.commit()
                action = "deleted"
        finally:
            return_db_connection(conn)
        # Invalidate groups cache for every affected member
        for member in affected_members:
            cache.delete(f"groups_{member}")
        if action == "deleted":
            for lim in (30, 50):
                cache.delete(f"voice_history_group_{group_id}_0_{lim}")
        return jsonify({"success": True, "action": action})
    except Exception as e:
        print(f"Error in delete_group: {e}")
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/api/create_group", methods=["POST"])
def api_create_group():
    try:
        data = request.get_json()
        name = data.get("name", "").strip()
        created_by = data.get("created_by", "").strip()
        members = data.get("members", [])

        if not name or not created_by:
            return jsonify({"success": False, "error": "Missing name or creator"}), 400
        if len(name) > 50:
            return jsonify({"success": False, "error": "Group name too long"}), 400

        avatar_letter = name[0].upper()
        members_sorted = sorted([str(m).strip() for m in members if str(m).strip() and str(m).strip() != created_by])
        members_key = ','.join(members_sorted)

        conn = get_db_connection()
        group_id = None
        try:
            c = conn.cursor()
            # Duplicate prevention: check if same group (name+creator+members) was created in last 10 seconds
            c.execute("""
                SELECT g.id FROM groups g
                WHERE g.name=? AND g.created_by=?
                AND g.created_at >= datetime('now', '-10 seconds')
            """, (name, created_by))
            existing = c.fetchone()
            if existing:
                group_id = existing[0]
            else:
                c.execute("INSERT INTO groups (name, created_by, avatar_letter) VALUES (?, ?, ?)",
                          (name, created_by, avatar_letter))
                group_id = c.lastrowid

                # Add creator as admin
                c.execute("INSERT INTO group_members (group_id, user_phone, role) VALUES (?, ?, 'admin')",
                          (group_id, created_by))
                # Add members
                for m in members:
                    m = str(m).strip()
                    if m and m != created_by:
                        c.execute("INSERT OR IGNORE INTO users(phone, last_online) VALUES(?, ?)",
                                  (m, datetime.now().isoformat()))
                        c.execute("INSERT OR IGNORE INTO group_members (group_id, user_phone) VALUES (?, ?)",
                                  (group_id, m))
                conn.commit()
        finally:
            return_db_connection(conn)

        # Invalidate groups cache for creator and all members so the new group appears immediately
        cache.delete(f"groups_{created_by}")
        for m in members:
            m = str(m).strip()
            if m and m != created_by:
                cache.delete(f"groups_{m}")

        return jsonify({"success": True, "group_id": group_id})
    except Exception as e:
        print(f"Error in create_group: {e}")
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/api/group_messages")
def api_group_messages():
    group_id = request.args.get("group_id", type=int)
    user_phone = request.args.get("user_phone")
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 50, type=int)
    offset = (page - 1) * limit

    if not group_id or not user_phone:
        return jsonify([]), 400

    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            # Verify membership
            c.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_phone=?", (group_id, user_phone))
            if not c.fetchone():
                return jsonify([]), 403

            c.execute("""
                SELECT gm.id, gm.sender, gm.message, gm.message_type,
                       gm.file_path, gm.file_name, gm.file_size, gm.timestamp,
                       COALESCE(con.contact_name, gm.sender) as sender_name
                FROM group_messages gm
                LEFT JOIN contacts con ON con.user_phone=? AND con.contact_phone=gm.sender
                WHERE gm.group_id=?
                ORDER BY gm.timestamp ASC
                LIMIT ? OFFSET ?
            """, (user_phone, group_id, limit, offset))
            rows = c.fetchall()

            # Fetch reactions for all returned messages in one query
            msg_ids = [r[0] for r in rows]
            reactions_by_msg = {}
            if msg_ids:
                placeholders = ','.join('?' * len(msg_ids))
                c.execute(f"""
                    SELECT message_id, user_phone, emoji
                    FROM message_reactions
                    WHERE message_id IN ({placeholders})
                """, msg_ids)
                for rxn in c.fetchall():
                    reactions_by_msg.setdefault(rxn[0], []).append(
                        {'user_phone': rxn[1], 'emoji': rxn[2]}
                    )
        finally:
            return_db_connection(conn)

        messages = []
        for r in rows:
            messages.append({
                "id": r[0], "sender": r[1], "message": r[2],
                "message_type": r[3], "file_path": r[4],
                "file_name": r[5], "file_size": r[6],
                "timestamp": r[7], "sender_name": r[8],
                "reactions": reactions_by_msg.get(r[0], [])
            })
        return jsonify(messages)
    except Exception as e:
        print(f"Error in group_messages: {e}")
        return jsonify([]), 500


@app.route("/api/group_info")
def api_group_info():
    group_id = request.args.get("group_id", type=int)
    user_phone = request.args.get("user_phone")
    if not group_id or not user_phone:
        return jsonify({}), 400
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT id, name, avatar_letter, created_by FROM groups WHERE id=?", (group_id,))
            g = c.fetchone()
            if not g:
                return jsonify({}), 404
            c.execute("""
                SELECT gm.user_phone, COALESCE(con.contact_name, gm.user_phone) as display_name, gm.role
                FROM group_members gm
                LEFT JOIN contacts con ON con.user_phone=? AND con.contact_phone=gm.user_phone
                WHERE gm.group_id=?
            """, (user_phone, group_id))
            members = [{"phone": r[0], "name": r[1], "role": r[2]} for r in c.fetchall()]
        finally:
            return_db_connection(conn)
        return jsonify({"id": g[0], "name": g[1], "avatar_letter": g[2],
                        "created_by": g[3], "members": members})
    except Exception as e:
        print(f"Error in group_info: {e}")
        return jsonify({}), 500


@app.route("/api/remove_group_member", methods=["POST"])
def api_remove_group_member():
    try:
        data = request.get_json() or {}
        group_id   = data.get("group_id")
        removed_by = str(data.get("removed_by", "")).strip()
        target     = str(data.get("target_phone", "")).strip()
        if not group_id or not removed_by or not target:
            return jsonify({"success": False, "error": "Missing data"}), 400
        conn = get_db_connection()
        try:
            c = conn.cursor()
            # Only the group creator (admin) can remove members
            c.execute("SELECT role FROM group_members WHERE group_id=? AND user_phone=?",
                      (group_id, removed_by))
            row = c.fetchone()
            if not row or row[0] != 'admin':
                return jsonify({"success": False, "error": "Only the group admin can remove members"}), 403
            # Cannot remove yourself through this endpoint (use leave/delete instead)
            if removed_by == target:
                return jsonify({"success": False, "error": "Cannot remove yourself"}), 400
            c.execute("DELETE FROM group_members WHERE group_id=? AND user_phone=?",
                      (group_id, target))
            if c.rowcount == 0:
                return jsonify({"success": False, "error": "Member not found"}), 404
            conn.commit()
        finally:
            return_db_connection(conn)
        # Notify everyone in the group that the member list changed
        socketio.emit('group_member_removed', {
            'group_id': group_id,
            'removed_phone': target,
            'removed_by': removed_by
        }, room=f'group_{group_id}')
        return jsonify({"success": True})
    except Exception as e:
        print(f"Error in remove_group_member: {e}")
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/api/add_group_members", methods=["POST"])
def api_add_group_members():
    try:
        data = request.get_json()
        group_id = data.get("group_id")
        added_by = str(data.get("added_by", "")).strip()
        members = data.get("members", [])

        if not group_id or not added_by or not members:
            return jsonify({"success": False, "error": "Missing data"}), 400

        conn = get_db_connection()
        try:
            c = conn.cursor()
            # Only admins can add members
            c.execute("SELECT role FROM group_members WHERE group_id=? AND user_phone=?", (group_id, added_by))
            row = c.fetchone()
            if not row or row[0] != 'admin':
                return jsonify({"success": False, "error": "Only admins can add members"}), 403

            now_iso = datetime.now().isoformat()
            added = 0
            for phone in members:
                phone = str(phone).strip()
                if not phone:
                    continue
                c.execute("INSERT OR IGNORE INTO users(phone, last_online) VALUES(?,?)", (phone, now_iso))
                result = c.execute(
                    "INSERT OR IGNORE INTO group_members (group_id, user_phone, role) VALUES (?,?,'member')",
                    (group_id, phone)
                )
                if result.rowcount:
                    added += 1
            conn.commit()
        finally:
            return_db_connection(conn)

        return jsonify({"success": True, "added": added})
    except Exception as e:
        print(f"Error in add_group_members: {e}")
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/group/<int:group_id>")
def group_chat_page(group_id):
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
            c.execute("SELECT name, avatar_letter FROM groups WHERE id=?", (group_id,))
            g = c.fetchone()
            if not g:
                return "Group not found", 404
            group_name = g[0]
            avatar_letter = g[1] or g[0][0].upper()
        finally:
            return_db_connection(conn)
        return render_template("group_chat.html",
                                      phone=phone,
                                      group_id=group_id,
                                      group_name=group_name,
                                      avatar_letter=avatar_letter)
    except Exception as e:
        print(f"Error in group_chat_page: {e}")
        return "An error occurred", 500


# ─────────────────────────────────────────────────────────────────────────────
# VOICE MESSAGING ROUTES
# ─────────────────────────────────────────────────────────────────────────────

