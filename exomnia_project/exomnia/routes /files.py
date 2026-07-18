"""
Generic file upload + serving for 1:1 chat attachments.
"""
import os
import uuid
from datetime import datetime

from flask import request, jsonify, send_from_directory

from ..extensions import app
from ..db import get_db_connection, return_db_connection
from ..utils import get_file_type


# ----------------- File Upload Route -----------------
@app.route('/upload_file', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        sender = request.form.get('sender')
        receiver = request.form.get('receiver')
        
        if not all([sender, receiver]):
            return jsonify({'success': False, 'error': 'Missing sender or receiver'}), 400

        # Determine file type
        file_type = get_file_type(file.filename)
        
        # Generate unique filename
        if '.' in file.filename:
            file_ext = file.filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid.uuid4()}.{file_ext}"
        else:
            unique_filename = f"{uuid.uuid4()}"
            
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Save file
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        
        # For images and videos, you could generate thumbnails here
        thumbnail_path = None
        if file_type in ['image', 'video']:
            # Thumbnail generation would go here
            # For now, we'll use the same file as thumbnail
            thumbnail_path = unique_filename
        
        # Save to database — only log in messages table for 1:1 chats
        is_group_upload = receiver.startswith('group_')
        now_iso = datetime.now().isoformat()
        conn = get_db_connection()
        try:
            c = conn.cursor()
            if not is_group_upload:
                c.execute("""
                    INSERT INTO messages(sender, receiver, message, message_type, file_path, file_name, file_size, thumbnail_path, status, timestamp)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (sender, receiver, f"Sent a {file_type}", file_type, unique_filename, file.filename, file_size, thumbnail_path, "sent", now_iso))
                message_id = c.lastrowid
                c.execute("INSERT OR IGNORE INTO contacts(user_phone, contact_phone, contact_name, last_message, last_sender) VALUES(?, ?, ?, ?, ?)",
                          (sender, receiver, "", f"Sent a {file_type}", sender))
                c.execute("UPDATE contacts SET last_message=?, last_sender=?, timestamp=CURRENT_TIMESTAMP WHERE user_phone=? AND contact_phone=?",
                          (f"Sent a {file_type}", sender, sender, receiver))
                c.execute("INSERT OR IGNORE INTO contacts(user_phone, contact_phone, contact_name, last_message, last_sender) VALUES(?, ?, ?, ?, ?)",
                          (receiver, sender, "", f"Sent a {file_type}", sender))
                c.execute("UPDATE contacts SET last_message=?, last_sender=?, timestamp=CURRENT_TIMESTAMP WHERE user_phone=? AND contact_phone=?",
                          (f"Sent a {file_type}", sender, receiver, sender))
            else:
                # Group upload — no message_id needed here; socket will handle it
                message_id = None
            conn.commit()
        finally:
            return_db_connection(conn)
        
        return jsonify({
            'success': True, 
            'message_id': message_id,
            'file_path': unique_filename,
            'file_name': file.filename,
            'file_type': file_type,
            'file_size': file_size
        })
        
    except Exception as e:
        print(f" Error in upload_file: {e}")
        return jsonify({'success': False, 'error': 'File upload failed'}), 500

@app.route('/uploads/<filename>')
def serve_file(filename):
    """Serve uploaded files with long-lived cache headers"""
    try:
        from flask import make_response
        resp = make_response(send_from_directory(app.config['UPLOAD_FOLDER'], filename))
        resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        return resp
    except FileNotFoundError:
        return "File not found", 404

