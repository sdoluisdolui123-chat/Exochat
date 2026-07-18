"""
Social network features: feed, posts, likes, comments, follow/connections, search.
"""
import os
import uuid

from flask import request, jsonify, send_from_directory

from ..extensions import app
from ..db import get_db_connection, return_db_connection
from ..cache import cache

SOCIAL_IMAGE_FOLDER = os.path.join(app.config['UPLOAD_FOLDER'], 'social')
os.makedirs(SOCIAL_IMAGE_FOLDER, exist_ok=True)


def _social_user_info(phone, conn):
    """Fetch display info for a user (name, avatar, headline, bio)."""
    c = conn.cursor()
    c.execute("SELECT phone, display_name, avatar_color, avatar_emoji, avatar_photo, bio, headline, location, website, username FROM users WHERE phone=?", (phone,))
    row = c.fetchone()
    if not row:
        return {"phone": phone, "display_name": "NEOX User", "avatar_color": "#0E4950", "avatar_emoji": "", "avatar_photo": "", "bio": "", "headline": "", "location": "", "website": ""}
    resolved_name = (row[1] or "").strip() or (row[9] or "").strip() or "NEOX User"
    return {"phone": row[0], "display_name": resolved_name, "avatar_color": row[2] or "#0E4950", "avatar_emoji": row[3] or "", "avatar_photo": row[4] or "", "bio": row[5] or "", "headline": row[6] or "", "location": row[7] or "", "website": row[8] or ""}

@app.route('/api/social/feed')
def social_feed():
    phone = request.args.get('phone', '').strip()
    if not phone:
        return jsonify([]), 400
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            # Get people the user follows + themselves
            c.execute("SELECT following_phone FROM social_connections WHERE follower_phone=? AND status='accepted'", (phone,))
            following = [r[0] for r in c.fetchall()] + [phone]
            placeholders = ','.join('?' * len(following))
            c.execute(f"""
                SELECT sp.id, sp.author_phone, sp.content, sp.image_path, sp.likes, sp.timestamp
                FROM social_posts sp
                WHERE sp.author_phone IN ({placeholders})
                ORDER BY sp.timestamp DESC LIMIT 50
            """, following)
            posts = c.fetchall()
            result = []
            for row in posts:
                post_id, author, content, image_path, likes, ts = row
                info = _social_user_info(author, conn)
                c.execute("SELECT user_phone FROM social_post_likes WHERE post_id=?", (post_id,))
                liked_by = [r[0] for r in c.fetchall()]
                c.execute("SELECT COUNT(*) FROM social_comments WHERE post_id=?", (post_id,))
                comment_count = c.fetchone()[0]
                result.append({
                    "id": post_id, "author_phone": author, "content": content,
                    "image_path": image_path or "", "likes": likes, "timestamp": ts,
                    "liked_by": liked_by, "comment_count": comment_count,
                    **{k: info[k] for k in ('display_name','avatar_color','avatar_emoji','avatar_photo','headline','bio')}
                })
        finally:
            return_db_connection(conn)
        return jsonify(result)
    except Exception as e:
        print(f"Error in social_feed: {e}")
        return jsonify([]), 500

@app.route('/api/social/post', methods=['POST'])
def social_create_post():
    try:
        phone = request.form.get('phone', '').strip()
        content = request.form.get('content', '').strip()[:1000]
        if not phone:
            return jsonify({'success': False, 'error': 'Phone required'}), 400
        if not content and 'image' not in request.files:
            return jsonify({'success': False, 'error': 'Content required'}), 400

        image_path = ''
        if 'image' in request.files:
            f = request.files['image']
            if f and f.filename:
                ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else 'jpg'
                if ext in {'jpg', 'jpeg', 'png', 'gif', 'webp'}:
                    fname = f"{uuid.uuid4().hex}.{ext}"
                    f.save(os.path.join(SOCIAL_IMAGE_FOLDER, fname))
                    image_path = fname

        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("INSERT INTO social_posts(author_phone, content, image_path) VALUES(?,?,?)",
                      (phone, content, image_path))
            conn.commit()
        finally:
            return_db_connection(conn)
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error in social_create_post: {e}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

@app.route('/api/social/image/<filename>')
def social_serve_image(filename):
    try:
        from flask import make_response
        safe = os.path.basename(filename)
        resp = make_response(send_from_directory(SOCIAL_IMAGE_FOLDER, safe))
        resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        return resp
    except FileNotFoundError:
        return "Not found", 404

@app.route('/social/post/<int:post_id>')
def social_post_page(post_id):
    """Public shareable page for a single social post."""
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT id, author_phone, content, image_path, likes, timestamp FROM social_posts WHERE id=?", (post_id,))
        row = c.fetchone()
        if not row:
            return "Post not found", 404
        _pid, author_phone, content, image_path, _likes, timestamp = row
        info = _social_user_info(author_phone, conn)
    finally:
        return_db_connection(conn)

    author_name = info.get('display_name') or author_phone
    safe_content = (content or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    safe_name = author_name.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    image_html = f'<img src="/api/social/image/{image_path}" style="width:100%;border-radius:12px;margin:12px 0;display:block;" alt="">' if image_path else ''
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{safe_name} on Exomnia</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta property="og:title" content="{safe_name} on Exomnia">
  <meta property="og:description" content="{safe_content[:200]}">
  <link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600;700&display=swap" onload="this.onload=null;this.rel='stylesheet'">
  <style>
    *{{box-sizing:border-box;margin:0;padding:0;}}
    body{{font-family:'DM Sans',-apple-system,BlinkMacSystemFont,sans-serif;background:#eef6f6;display:flex;justify-content:center;align-items:flex-start;min-height:100vh;padding:24px 16px;}}
    .card{{background:#fff;border-radius:20px;max-width:480px;width:100%;padding:24px;box-shadow:0 4px 24px rgba(14,73,80,0.10);margin-top:8px;}}
    .app-header{{font-size:12px;color:#7aabae;font-weight:700;margin-bottom:18px;letter-spacing:0.8px;text-transform:uppercase;}}
    .author{{font-size:17px;font-weight:700;color:#0E4950;margin-bottom:4px;}}
    .meta{{font-size:12px;color:#aac4c5;margin-bottom:14px;}}
    .content{{font-size:16px;color:#1a2e2f;line-height:1.65;word-break:break-word;}}
    .open-btn{{display:block;margin:22px auto 0;padding:13px 28px;background:#0E4950;color:#fff;border-radius:14px;text-decoration:none;font-weight:700;font-size:15px;text-align:center;box-shadow:0 4px 14px rgba(14,73,80,0.25);}}
  </style>
</head>
<body>
  <div class="card">
    <div class="app-header">&#x2022; Exomnia</div>
    <div class="author">{safe_name}</div>
    <div class="meta">{timestamp}</div>
    <div class="content">{safe_content}</div>
    {image_html}
    <a href="/main" class="open-btn">Open in Exomnia</a>
  </div>
</body>
</html>"""

@app.route('/api/social/post/delete', methods=['POST'])
def social_delete_post():
    data = request.get_json() or {}
    post_id = data.get('post_id')
    phone = data.get('phone', '').strip()
    if not post_id or not phone:
        return jsonify({'success': False}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT author_phone, image_path FROM social_posts WHERE id=?", (post_id,))
        row = c.fetchone()
        if not row or row[0] != phone:
            return jsonify({'success': False, 'error': 'Forbidden'}), 403
        if row[1]:
            try: os.remove(os.path.join(SOCIAL_IMAGE_FOLDER, row[1]))
            except OSError: pass
        c.execute("DELETE FROM social_comments WHERE post_id=?", (post_id,))
        c.execute("DELETE FROM social_post_likes WHERE post_id=?", (post_id,))
        c.execute("DELETE FROM social_posts WHERE id=?", (post_id,))
        conn.commit()
    finally:
        return_db_connection(conn)
    return jsonify({'success': True})

@app.route('/api/social/like', methods=['POST'])
def social_like():
    data = request.get_json() or {}
    post_id = data.get('post_id')
    phone = data.get('phone', '').strip()
    if not post_id or not phone:
        return jsonify({'success': False}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT 1 FROM social_post_likes WHERE post_id=? AND user_phone=?", (post_id, phone))
        if c.fetchone():
            c.execute("DELETE FROM social_post_likes WHERE post_id=? AND user_phone=?", (post_id, phone))
            c.execute("UPDATE social_posts SET likes=MAX(0,likes-1) WHERE id=?", (post_id,))
            action = 'unliked'
        else:
            c.execute("INSERT OR IGNORE INTO social_post_likes(post_id, user_phone) VALUES(?,?)", (post_id, phone))
            c.execute("UPDATE social_posts SET likes=likes+1 WHERE id=?", (post_id,))
            action = 'liked'
        conn.commit()
    finally:
        return_db_connection(conn)
    return jsonify({'success': True, 'action': action})

@app.route('/api/social/comments')
def social_comments():
    post_id = request.args.get('post_id', type=int)
    if not post_id:
        return jsonify([]), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT id, author_phone, content, timestamp FROM social_comments WHERE post_id=? ORDER BY timestamp ASC LIMIT 100", (post_id,))
        rows = c.fetchall()
        result = []
        for row in rows:
            info = _social_user_info(row[1], conn)
            result.append({"id": row[0], "author_phone": row[1], "content": row[2], "timestamp": row[3],
                           "display_name": info['display_name'], "avatar_color": info['avatar_color'],
                           "avatar_emoji": info['avatar_emoji'], "avatar_photo": info['avatar_photo']})
    finally:
        return_db_connection(conn)
    return jsonify(result)

@app.route('/api/social/comment', methods=['POST'])
def social_add_comment():
    data = request.get_json() or {}
    post_id = data.get('post_id')
    phone = data.get('phone', '').strip()
    content = data.get('content', '').strip()[:500]
    if not post_id or not phone or not content:
        return jsonify({'success': False}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO social_comments(post_id, author_phone, content) VALUES(?,?,?)", (post_id, phone, content))
        conn.commit()
    finally:
        return_db_connection(conn)
    return jsonify({'success': True})

@app.route('/api/social/connect', methods=['POST'])
def social_connect():
    data = request.get_json() or {}
    from_phone = data.get('from_phone', '').strip()
    to_phone = data.get('to_phone', '').strip()
    if not from_phone or not to_phone or from_phone == to_phone:
        return jsonify({'success': False, 'error': 'Invalid'}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT status FROM social_connections WHERE follower_phone=? AND following_phone=?", (from_phone, to_phone))
        existing = c.fetchone()
        if existing:
            return jsonify({'success': False, 'error': 'Already requested or connected'})
        # Check if the other person already sent a request — auto-accept
        c.execute("SELECT status FROM social_connections WHERE follower_phone=? AND following_phone=?", (to_phone, from_phone))
        reverse = c.fetchone()
        if reverse and reverse[0] == 'pending':
            c.execute("UPDATE social_connections SET status='accepted' WHERE follower_phone=? AND following_phone=?", (to_phone, from_phone))
            c.execute("INSERT OR IGNORE INTO social_connections(follower_phone, following_phone, status) VALUES(?,?,'accepted')", (from_phone, to_phone))
        else:
            c.execute("INSERT OR IGNORE INTO social_connections(follower_phone, following_phone, status) VALUES(?,?,'pending')", (from_phone, to_phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    return jsonify({'success': True})

@app.route('/api/social/respond', methods=['POST'])
def social_respond():
    data = request.get_json() or {}
    from_phone = data.get('from_phone', '').strip()
    to_phone = data.get('to_phone', '').strip()
    action = data.get('action', '').strip()  # 'accept' or 'decline'
    if not from_phone or not to_phone or action not in ('accept', 'decline'):
        return jsonify({'success': False}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        if action == 'accept':
            c.execute("UPDATE social_connections SET status='accepted' WHERE follower_phone=? AND following_phone=? AND status='pending'", (from_phone, to_phone))
            c.execute("INSERT OR IGNORE INTO social_connections(follower_phone, following_phone, status) VALUES(?,?,'accepted')", (to_phone, from_phone))
        else:
            c.execute("DELETE FROM social_connections WHERE follower_phone=? AND following_phone=?", (from_phone, to_phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    return jsonify({'success': True})

@app.route('/api/social/search')
def social_search():
    """Search all app users by name/phone/headline, returning connection status for each."""
    phone = request.args.get('phone', '').strip()
    q = request.args.get('q', '').strip().lower()
    if not phone or not q:
        return jsonify({'people': []}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        # Get all connections (both directions) for this user
        c.execute("SELECT following_phone, status FROM social_connections WHERE follower_phone=?", (phone,))
        outgoing = {r[0]: r[1] for r in c.fetchall()}  # phone -> status
        c.execute("SELECT follower_phone, status FROM social_connections WHERE following_phone=?", (phone,))
        incoming = {r[0]: r[1] for r in c.fetchall()}

        c.execute("""SELECT phone, display_name, avatar_color, avatar_emoji, avatar_photo, bio, headline
                     FROM users
                     WHERE (LOWER(display_name) LIKE ? OR phone LIKE ? OR LOWER(headline) LIKE ? OR LOWER(bio) LIKE ?)
                     ORDER BY last_online DESC LIMIT 40""",
                  (f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%'))
        rows = c.fetchall()
        people = []
        for row in rows:
            p_phone = row[0]
            if p_phone == phone:
                status = 'me'
            elif outgoing.get(p_phone) == 'accepted' or incoming.get(p_phone) == 'accepted':
                status = 'connected'
            elif outgoing.get(p_phone) == 'pending':
                status = 'pending'
            else:
                status = 'none'
            people.append({
                'phone': p_phone,
                'display_name': row[1] or '',
                'avatar_color': row[2] or '#0E4950',
                'avatar_emoji': row[3] or '',
                'avatar_photo': row[4] or '',
                'bio': row[5] or '',
                'headline': row[6] or '',
                'connection_status': status
            })
    finally:
        return_db_connection(conn)
    return jsonify({'people': people})

@app.route('/api/social/disconnect', methods=['POST'])
def social_disconnect():
    data = request.get_json() or {}
    from_phone = data.get('from_phone', '').strip()
    to_phone = data.get('to_phone', '').strip()
    if not from_phone or not to_phone or from_phone == to_phone:
        return jsonify({'success': False, 'error': 'Invalid'}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        # Remove both directions of the connection
        c.execute("DELETE FROM social_connections WHERE (follower_phone=? AND following_phone=?) OR (follower_phone=? AND following_phone=?)",
                  (from_phone, to_phone, to_phone, from_phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    return jsonify({'success': True})

@app.route('/api/social/connections')
def social_connections():
    phone = request.args.get('phone', '').strip()
    if not phone:
        return jsonify({}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT following_phone FROM social_connections WHERE follower_phone=? AND status='accepted'", (phone,))
        following = [r[0] for r in c.fetchall()]
        c.execute("SELECT follower_phone FROM social_connections WHERE following_phone=? AND status='accepted'", (phone,))
        followers = [r[0] for r in c.fetchall()]
        c.execute("SELECT following_phone FROM social_connections WHERE follower_phone=? AND status='pending'", (phone,))
        pending_out = [r[0] for r in c.fetchall()]
    finally:
        return_db_connection(conn)
    return jsonify({'following': following, 'followers': followers, 'pending_out': pending_out})

@app.route('/api/social/requests')
def social_requests():
    phone = request.args.get('phone', '').strip()
    if not phone:
        return jsonify([]), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT follower_phone FROM social_connections WHERE following_phone=? AND status='pending'", (phone,))
        requesters = [r[0] for r in c.fetchall()]
        result = [_social_user_info(p, conn) for p in requesters]
    finally:
        return_db_connection(conn)
    return jsonify(result)

@app.route('/api/social/people')
def social_people():
    """Return users who are NOT yet connected (suggestions)."""
    phone = request.args.get('phone', '').strip()
    if not phone:
        return jsonify([]), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        # Already connected or pending
        c.execute("SELECT following_phone FROM social_connections WHERE follower_phone=?", (phone,))
        already = {r[0] for r in c.fetchall()} | {phone}
        c.execute("SELECT phone, display_name, avatar_color, avatar_emoji, avatar_photo, bio, headline FROM users WHERE phone != ? ORDER BY last_online DESC LIMIT 60", (phone,))
        rows = c.fetchall()
        result = []
        for row in rows:
            p = row[0]
            if p in already:
                continue
            result.append({"phone": p, "display_name": row[1] or "", "avatar_color": row[2] or "#0E4950",
                           "avatar_emoji": row[3] or "", "avatar_photo": row[4] or "",
                           "bio": row[5] or "", "headline": row[6] or ""})
            if len(result) >= 30:
                break
    finally:
        return_db_connection(conn)
    return jsonify(result)

@app.route('/api/social/user_posts')
def social_user_posts():
    phone = request.args.get('phone', '').strip()
    viewer = request.args.get('viewer', '').strip()
    if not phone:
        return jsonify([]), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        info = _social_user_info(phone, conn)
        c.execute("SELECT id, content, image_path, likes, timestamp FROM social_posts WHERE author_phone=? ORDER BY timestamp DESC LIMIT 30", (phone,))
        rows = c.fetchall()
        result = []
        for row in rows:
            post_id, content, image_path, likes, ts = row
            c.execute("SELECT user_phone FROM social_post_likes WHERE post_id=?", (post_id,))
            liked_by = [r[0] for r in c.fetchall()]
            c.execute("SELECT COUNT(*) FROM social_comments WHERE post_id=?", (post_id,))
            comment_count = c.fetchone()[0]
            result.append({"id": post_id, "author_phone": phone, "content": content,
                           "image_path": image_path or "", "likes": likes, "timestamp": ts,
                           "liked_by": liked_by, "comment_count": comment_count,
                           **{k: info[k] for k in ('display_name','avatar_color','avatar_emoji','avatar_photo','headline','bio')}})
    finally:
        return_db_connection(conn)
    return jsonify(result)

@app.route('/api/social/user_stats')
def social_user_stats():
    phone = request.args.get('phone', '').strip()
    if not phone:
        return jsonify({}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM social_posts WHERE author_phone=?", (phone,))
        posts = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM social_connections WHERE following_phone=? AND status='accepted'", (phone,))
        followers = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM social_connections WHERE follower_phone=? AND status='accepted'", (phone,))
        following = c.fetchone()[0]
    finally:
        return_db_connection(conn)
    return jsonify({'posts': posts, 'followers': followers, 'following': following})

@app.route('/api/social/profile/update', methods=['POST'])
def social_update_profile():
    data = request.get_json() or {}
    phone = data.get('phone', '').strip()
    if not phone:
        return jsonify({'success': False}), 400
    headline = data.get('headline', '').strip()[:120]
    location = data.get('location', '').strip()[:80]
    website = data.get('website', '').strip()[:200]
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE users SET headline=?, location=?, website=? WHERE phone=?", (headline, location, website, phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    cache.delete(f"profile_{phone}")
    return jsonify({'success': True})

# ─────────────────────────────────────────────────────────────────────────────
