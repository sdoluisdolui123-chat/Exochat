import os
import psycopg2
from psycopg2.extras import RealDictCursor
import secrets
from flask import Flask, render_template_string, request, redirect, url_for, jsonify, session, send_from_directory
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room, leave_room
import re
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import uuid
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import time
from functools import wraps
import logging

# Performance optimization
logging.basicConfig(level=logging.WARNING)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'exomnia-default-secret-key-change-this')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
VOICE_UPLOAD_FOLDER = os.path.join('uploads', 'voice')
os.makedirs(VOICE_UPLOAD_FOLDER, exist_ok=True)
ALLOWED_AUDIO_EXTENSIONS = {'webm', 'ogg', 'wav', 'mp3', 'm4a', 'aac'}
MAX_VOICE_FILE_SIZE = 10 * 1024 * 1024

# Performance optimizations for SocketIO
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=20,
    ping_interval=10,
    max_http_buffer_size=16 * 1024 * 1024,
    logger=False,
    engineio_logger=False,
    compression_threshold=1024,
)

# PostgreSQL connection (Render Postgres)
DATABASE_URL = os.environ.get('DATABASE_URL', '')

# Fix Render Postgres URL (starts with postgres:// but psycopg2 needs postgresql://)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

class ConnectionPool:
    def __init__(self, max_connections=20):
        self.max_connections = max_connections
        self.connections = []
        self.lock = threading.Lock()

    def get_connection(self):
        with self.lock:
            if self.connections:
                return self.connections.pop()
            else:
                conn = psycopg2.connect(DATABASE_URL)
                conn.autocommit = False
                return conn

    def return_connection(self, conn):
        with self.lock:
            if len(self.connections) < self.max_connections:
                try:
                    conn.rollback()  # reset any bad state
                    self.connections.append(conn)
                except Exception:
                    conn.close()
            else:
                conn.close()

connection_pool = ConnectionPool()

def get_db_connection():
    return connection_pool.get_connection()

def return_db_connection(conn):
    connection_pool.return_connection(conn)

# Rate limiting
from collections import defaultdict

rate_limits = defaultdict(list)

def rate_limit(limit=10, window=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            now = time.time()
            user_id = request.remote_addr
            rate_limits[user_id] = [t for t in rate_limits[user_id] if now - t < window]
            if len(rate_limits[user_id]) >= limit:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            rate_limits[user_id].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'image': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'],
    'video': ['mp4', 'mov', 'avi', 'mkv', 'webm'],
    'document': ['pdf', 'doc', 'docx', 'txt', 'ppt', 'pptx', 'xls', 'xlsx']
}

def allowed_file(filename, file_type='image'):
    """Check if file extension is allowed"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS.get(file_type, [])

def get_file_type(filename):
    """Determine file type from extension"""
    if '.' not in filename:
        return 'document'
    ext = filename.rsplit('.', 1)[1].lower()
    
    for file_type, extensions in ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            return file_type
    return 'document'

# ----------------- Enhanced Cache System -----------------
class EnhancedCache:
    def __init__(self, ttl=300):
        self.cache = {}
        self.ttl = ttl
        self.lock = threading.Lock()
    
    def get(self, key):
        with self.lock:
            if key in self.cache:
                data, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    return data
                else:
                    del self.cache[key]
        return None
    
    def set(self, key, value):
        with self.lock:
            self.cache[key] = (value, time.time())
    
    def delete(self, key):
        with self.lock:
            if key in self.cache:
                del self.cache[key]
    
    def clear_pattern(self, pattern):
        """Clear all keys matching pattern"""
        with self.lock:
            keys_to_delete = [key for key in self.cache if pattern in key]
            for key in keys_to_delete:
                del self.cache[key]
    
    def clear_for_users(self, user1, user2):
        """Clear all cache for two users"""
        with self.lock:
            keys_to_delete = []
            for key in self.cache:
                if (user1 in key) or (user2 in key):
                    keys_to_delete.append(key)
            for key in keys_to_delete:
                del self.cache[key]

cache = EnhancedCache(ttl=60)  # 60-second cache — safe since we invalidate on every write

# ----------------- Encryption Setup -----------------
class MessageEncryptor:
    def __init__(self):
        self.master_key = self._derive_master_key()
        self._key_cache = {}  # cache derived keys — PBKDF2 is slow

    def _derive_master_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'exomnia_salt_2024',
            iterations=100000,
        )
        return kdf.derive(app.config['SECRET_KEY'].encode())

    def generate_user_key(self, phone_number):
        if phone_number in self._key_cache:
            return self._key_cache[phone_number]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=phone_number.encode(),
            iterations=100000,
        )
        key = kdf.derive(self.master_key)
        self._key_cache[phone_number] = key
        return key

    def _conversation_key(self, phone_a, phone_b):
        """Always produce the same key regardless of who is sender/receiver."""
        p1, p2 = sorted([phone_a, phone_b])
        k1 = self.generate_user_key(p1)
        k2 = self.generate_user_key(p2)
        return hashlib.sha256(k1 + k2).digest()

    def encrypt_message(self, message, sender_phone, receiver_phone):
        try:
            conversation_key = self._conversation_key(sender_phone, receiver_phone)
            nonce = os.urandom(12)
            aesgcm = AESGCM(conversation_key)
            encrypted_data = aesgcm.encrypt(nonce, message.encode(), None)
            return base64.b64encode(nonce + encrypted_data).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_message(self, encrypted_message, sender_phone, receiver_phone):
        # Attempt 1: current sorted key (correct method)
        try:
            conversation_key = self._conversation_key(sender_phone, receiver_phone)
            raw = base64.b64decode(encrypted_message.encode('utf-8'))
            nonce, ciphertext = raw[:12], raw[12:]
            return AESGCM(conversation_key).decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            pass
        # Attempt 2: old key order — sender first (pre-fix messages)
        try:
            k1 = self.generate_user_key(sender_phone)
            k2 = self.generate_user_key(receiver_phone)
            old_key = hashlib.sha256(k1 + k2).digest()
            raw = base64.b64decode(encrypted_message.encode('utf-8'))
            nonce, ciphertext = raw[:12], raw[12:]
            return AESGCM(old_key).decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            pass
        # Attempt 3: old key order — receiver first (pre-fix messages, flipped)
        try:
            k1 = self.generate_user_key(receiver_phone)
            k2 = self.generate_user_key(sender_phone)
            old_key = hashlib.sha256(k1 + k2).digest()
            raw = base64.b64decode(encrypted_message.encode('utf-8'))
            nonce, ciphertext = raw[:12], raw[12:]
            return AESGCM(old_key).decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            pass
        # All attempts failed — return None so caller can fall back to stored plaintext
        return None

# Initialize encryptor
encryptor = MessageEncryptor()

# ----------------- Database Setup -----------------
def init_db():
    conn = get_db_connection()
    try:
        c = conn.cursor()
        conn.autocommit = False
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                phone TEXT PRIMARY KEY,
                last_online TEXT,
                public_key TEXT,
                encryption_version INTEGER DEFAULT 1,
                display_name TEXT DEFAULT '',
                bio TEXT DEFAULT '',
                avatar_color TEXT DEFAULT '#0E4950',
                avatar_emoji TEXT DEFAULT '',
                avatar_photo TEXT DEFAULT ''
            )
        """)
        # Migrate existing DB — add new columns if they don't exist yet
        for col, default in [
            ('display_name', "''"),
            ('bio', "''"),
            ('avatar_color', "'#0E4950'"),
            ('avatar_emoji', "''"),
            ('avatar_photo', "''"),
            ('banner_photo', "''"),
            ('username', "''"),
            ('password_hash', "''"),
        ]:
            try:
                c.execute(f"SAVEPOINT sp_{col}")
                c.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT {default}")
                c.execute(f"RELEASE SAVEPOINT sp_{col}")
            except Exception:
                c.execute(f"ROLLBACK TO SAVEPOINT sp_{col}")
        c.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                user_phone TEXT,
                contact_phone TEXT,
                contact_name TEXT,
                last_message TEXT,
                last_sender TEXT,
                timestamp TIMESTAMP DEFAULT NOW(),
                PRIMARY KEY(user_phone, contact_phone)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender TEXT,
                receiver TEXT,
                message TEXT,
                encrypted_message TEXT,
                status TEXT DEFAULT 'sent',
                timestamp TIMESTAMP DEFAULT NOW(),
                encryption_version INTEGER DEFAULT 1,
                message_type TEXT DEFAULT 'text',
                file_path TEXT,
                file_name TEXT,
                file_size INTEGER,
                thumbnail_path TEXT,
                deleted_for TEXT DEFAULT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_users ON messages(sender, receiver)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_phone)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(message_type)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(sender, receiver, timestamp)")
        try:
            c.execute("SAVEPOINT sp_deleted_for")
            c.execute("ALTER TABLE messages ADD COLUMN deleted_for TEXT DEFAULT NULL")
            c.execute("RELEASE SAVEPOINT sp_deleted_for")
        except Exception:
            c.execute("ROLLBACK TO SAVEPOINT sp_deleted_for")
        c.execute("""
            CREATE TABLE IF NOT EXISTS message_reactions (
                id SERIAL PRIMARY KEY,
                message_id INTEGER,
                user_phone TEXT,
                emoji TEXT,
                timestamp TIMESTAMP DEFAULT NOW(),
                UNIQUE(message_id, user_phone)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                created_by TEXT NOT NULL,
                avatar_letter TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER,
                user_phone TEXT,
                role TEXT DEFAULT 'member',
                joined_at TIMESTAMP DEFAULT NOW(),
                PRIMARY KEY(group_id, user_phone),
                FOREIGN KEY(group_id) REFERENCES groups(id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS group_messages (
                id SERIAL PRIMARY KEY,
                group_id INTEGER,
                sender TEXT,
                message TEXT,
                message_type TEXT DEFAULT 'text',
                file_path TEXT,
                file_name TEXT,
                file_size INTEGER,
                timestamp TIMESTAMP DEFAULT NOW(),
                FOREIGN KEY(group_id) REFERENCES groups(id)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_group_messages ON group_messages(group_id, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_group_members ON group_members(user_phone)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_reactions_msg ON message_reactions(message_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_contacts_timestamp ON contacts(user_phone, timestamp DESC)")
        # Migration: add last_sender column if it doesn't exist yet
        try:
            c.execute("ALTER TABLE contacts ADD COLUMN last_sender TEXT")
        except Exception:
            pass  # column already exists
        c.execute("""
            CREATE TABLE IF NOT EXISTS voice_messages (
                id            SERIAL PRIMARY KEY,
                sender        TEXT    NOT NULL,
                receiver      TEXT,
                group_id      INTEGER,
                file_path     TEXT    NOT NULL,
                file_name     TEXT    NOT NULL,
                file_size     INTEGER NOT NULL,
                duration_ms   INTEGER DEFAULT 0,
                waveform_data TEXT,
                status        TEXT    DEFAULT 'sent',
                timestamp     TIMESTAMP DEFAULT NOW(),
                listened_at   TIMESTAMP,
                FOREIGN KEY(group_id) REFERENCES groups(id)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_voice_dm ON voice_messages(sender, receiver, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_voice_group ON voice_messages(group_id, timestamp)")

        # ── Social Network Tables ──────────────────────────────────────────────
        # Migration: if social_posts exists with wrong schema, rebuild it
        c.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name='social_posts'")
        if c.fetchone():
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='social_posts'")
            existing_cols = [row[0] for row in c.fetchall()]
            if 'author_phone' not in existing_cols:
                c.execute("DROP TABLE IF EXISTS social_comments")
                c.execute("DROP TABLE IF EXISTS social_post_likes")
                c.execute("DROP TABLE IF EXISTS social_posts")

        c.execute("""
            CREATE TABLE IF NOT EXISTS social_posts (
                id SERIAL PRIMARY KEY,
                author_phone TEXT NOT NULL,
                content TEXT NOT NULL,
                image_path TEXT DEFAULT \'\',
                likes INTEGER DEFAULT 0,
                timestamp TIMESTAMP DEFAULT NOW()
            )
        """)
        c.execute("DROP INDEX IF EXISTS idx_social_posts_author")
        c.execute("DROP INDEX IF EXISTS idx_social_posts_ts")
        c.execute("CREATE INDEX IF NOT EXISTS idx_social_posts_author ON social_posts(author_phone, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_social_posts_ts ON social_posts(timestamp DESC)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS social_connections (
                follower_phone TEXT NOT NULL,
                following_phone TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                timestamp TIMESTAMP DEFAULT NOW(),
                PRIMARY KEY(follower_phone, following_phone)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_social_conn_follower ON social_connections(follower_phone)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_social_conn_following ON social_connections(following_phone)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS social_post_likes (
                post_id INTEGER NOT NULL,
                user_phone TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT NOW(),
                PRIMARY KEY(post_id, user_phone)
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS social_comments (
                id SERIAL PRIMARY KEY,
                post_id INTEGER NOT NULL,
                author_phone TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT NOW()
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_social_comments_post ON social_comments(post_id, timestamp)")

        # Migration: add headline/location columns to users for social profiles
        for col, default in [('headline', "''"), ('location', "''"), ('website', "''")]:
            try:
                c.execute(f"SAVEPOINT sp_social_{col}")
                c.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT {default}")
                c.execute(f"RELEASE SAVEPOINT sp_social_{col}")
            except Exception:
                c.execute(f"ROLLBACK TO SAVEPOINT sp_social_{col}")

        conn.commit()
    finally:
        return_db_connection(conn)

def validate_phone(phone):
    pattern = r'^\+\d{1,4}\d{6,14}$'
    return re.match(pattern, phone) is not None

# ----------------- Typing Status -----------------
typing_status = {}

# ----------------- Main Super App Template -----------------
main_app_html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Exomnia Super App</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&display=swap" onload="this.onload=null;this.rel='stylesheet'">
  <noscript><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet"></noscript>
  <style>
    * {margin: 0; padding: 0; box-sizing: border-box;}
    html {
      height: 100%;
      height: -webkit-fill-available;
    }

    body {
      font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      background: #eef6f6;
      height: 100vh;
      height: 100dvh;
      min-height: -webkit-fill-available;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    #main-content {
      flex: 1;
      background: #eef6f6;
      padding: 15px;
      overflow-y: auto;
      transition: 0.3s ease;
      padding-bottom: calc(75px + env(safe-area-inset-bottom, 0px));
    }

    .bottom-nav {
      display: flex;
      justify-content: space-around;
      background: #fff;
      padding: 10px 0 calc(12px + env(safe-area-inset-bottom, 0px));
      color: #0E4950;
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      width: 100%;
      box-shadow: 0 -2px 20px rgba(14,73,80,0.10);
      z-index: 1000;
      border-top: 1px solid #daeaea;
    }

    .tab {
      text-align: center;
      flex: 1;
      cursor: pointer;
      padding: 6px 4px;
      color: #7aabae;
      font-weight: 600;
      font-size: 11px;
      transition: all 0.2s;
      border-radius: 12px;
      margin: 0 4px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 3px;
    }

    .tab.active {
      background: #0E4950;
      color: #fff;
      border-radius: 12px;
      box-shadow: 0 4px 14px rgba(14,73,80,0.25);
    }

    .placeholder-content {
      background: white;
      padding: 24px 20px;
      border-radius: 18px;
      margin-top: 10px;
      text-align: center;
      border: 1px solid #daeaea;
      box-shadow: 0 2px 12px rgba(14,73,80,0.06);
    }

    /* Add Contact Modal Styles */
    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.5);
      backdrop-filter: blur(5px);
      z-index: 1000;
      align-items: center;
      justify-content: center;
    }
    .modal-content {
      background: white;
      padding: 25px;
      border-radius: 20px;
      width: 90%;
      max-width: 400px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.3);
      animation: modalSlide 0.3s ease;
    }
    @keyframes modalSlide {
      from { transform: translateY(-50px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    .modal h3 {
      margin-bottom: 20px;
      color: #333;
      text-align: center;
    }
    .form-group {
      margin-bottom: 15px;
    }
    .form-group label {
      display: block;
      margin-bottom: 5px;
      color: #666;
      font-weight: 500;
    }
    .form-control {
      width: 100%;
      padding: 12px 15px;
      border: 2px solid #e1e1e1;
      border-radius: 10px;
      font-size: 16px;
      transition: all 0.3s ease;
    }
    .form-control:focus {
      border-color: #0E4950;
      box-shadow: 0 0 0 3px rgba(14, 73, 80, 0.1);
    }
    .button-group {
      display: flex;
      gap: 10px;
      margin-top: 20px;
    }
    .btn {
      flex: 1;
      padding: 12px;
      border: none;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
    }
    .btn-primary {
      background: #0E4950;
      color: white;
    }
    .btn-primary:hover {
      background: #0a363a;
      transform: translateY(-2px);
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }
    .btn-secondary {
      background: #f8f9fa;
      color: #666;
    }
    .btn-secondary:hover {
      background: #e9ecef;
      transform: translateY(-2px);
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }

    .loading {
      opacity: 0.7;
      pointer-events: none;
    }

    /* Search Bar Styles */
    .search-container {
      display: flex;
      gap: 10px;
      margin-bottom: 15px;
      align-items: center;
    }
    .search-input {
      flex: 1;
      padding: 10px 15px;
      border: 2px solid #e1e1e1;
      border-radius: 10px;
      font-size: 14px;
      background: white;
      transition: all 0.3s ease;
    }
    .search-input:focus {
      border-color: #0E4950;
      box-shadow: 0 0 0 3px rgba(14, 73, 80, 0.1);
    }
    .search-input::placeholder {
      color: #999;
    }
    .no-contacts-found {
      text-align: center;
      padding: 20px;
      color: #666;
      font-style: italic;
    }

    /* ── Social Network Styles ─────────────────────────────── */
    .social-header {
      display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 14px;
    }
    .social-tabs {
      display: flex; gap: 6px; background: white;
      border-radius: 12px; padding: 4px;
      border: 1px solid #daeaea; margin-bottom: 14px;
      box-shadow: 0 1px 6px rgba(14,73,80,0.06);
    }
    .social-tab-btn {
      flex: 1; padding: 8px 4px; border: none; background: none;
      border-radius: 9px; font-size: 12px; font-weight: 600;
      color: #7aabae; cursor: pointer; transition: all 0.2s;
      font-family: inherit;
    }
    .social-tab-btn.active {
      background: #0E4950; color: white;
      box-shadow: 0 2px 8px rgba(14,73,80,0.22);
    }
    .social-post-card {
      background: white; border-radius: 16px;
      border: 1px solid #daeaea; margin-bottom: 12px;
      overflow: hidden; box-shadow: 0 2px 10px rgba(14,73,80,0.06);
    }
    .social-post-header {
      display: flex; align-items: center; gap: 10px;
      padding: 14px 14px 10px;
    }
    .social-avatar {
      width: 42px; height: 42px; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-weight: 700; font-size: 16px; color: white;
      flex-shrink: 0; overflow: hidden;
    }
    .social-post-meta { flex: 1; min-width: 0; }
    .social-post-name {
      font-weight: 700; font-size: 14px; color: #1a2e2f;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .social-post-headline {
      font-size: 11px; color: #7aabae; margin-top: 1px;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .social-post-time { font-size: 11px; color: #aac4c5; flex-shrink: 0; }
    .social-post-content {
      padding: 0 14px 10px; font-size: 14px; line-height: 1.6;
      color: #1a2e2f; white-space: pre-wrap; word-break: break-word;
    }
    .social-post-image {
      width: 100%; display: block; cursor: pointer;
      max-height: 340px; object-fit: cover;
    }
    .social-post-actions {
      display: flex; padding: 10px 14px 12px; gap: 20px;
      border-top: 1px solid #f0f7f7;
    }
    .social-action-btn {
      display: flex; align-items: center; gap: 6px;
      border: none; background: none; color: #7aabae;
      font-size: 13px; font-weight: 600; cursor: pointer;
      padding: 6px 10px; border-radius: 8px;
      transition: all 0.18s; font-family: inherit;
    }
    .social-action-btn:hover { background: #eef6f6; color: #0E4950; }
    .social-action-btn.liked { color: #e76f51; }
    .social-action-btn.liked svg { stroke: #e76f51; fill: rgba(231,111,81,0.12); }
    /* ── Comments section ── */
    .social-comments-section {
      border-top: 1.5px solid #eef5f5;
      padding: 14px 16px 10px;
      display: flex; flex-direction: column; gap: 0;
    }
    .comments-header {
      font-size: 11px; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.8px; color: #9ab8ba; margin-bottom: 12px;
    }
    /* Individual comment */
    .social-comment-item {
      display: flex; gap: 9px; margin-bottom: 12px; align-items: flex-start;
    }
    .social-comment-item:last-of-type { margin-bottom: 4px; }
    .social-comment-bubble {
      flex: 1; min-width: 0;
    }
    .scb-inner {
      background: #f2f8f8;
      border-radius: 0 14px 14px 14px;
      padding: 9px 13px 8px;
      border: 1px solid #e2eeee;
    }
    .social-comment-author {
      font-weight: 700; font-size: 12.5px; color: #0E4950;
      margin-bottom: 2px; line-height: 1;
    }
    .social-comment-text {
      font-size: 13.5px; color: #1a2e2f; line-height: 1.45;
    }
    .social-comment-meta {
      display: flex; align-items: center; gap: 10px;
      margin-top: 5px; padding-left: 2px;
    }
    .social-comment-time {
      font-size: 10.5px; color: #a8c4c6;
    }
    .comment-like-btn {
      background: none; border: none; cursor: pointer;
      font-size: 10.5px; color: #a8c4c6; display: flex; align-items: center; gap: 3px;
      padding: 0; transition: color 0.15s;
    }
    .comment-like-btn:hover { color: #e74c3c; }
    .comment-like-btn.liked  { color: #e74c3c; }
    /* Divider between comments */
    .comment-divider {
      height: 1px; background: #f0f7f7; margin: 0 0 12px;
    }
    /* Empty state */
    .no-comments {
      text-align: center; padding: 8px 0 12px;
      font-size: 13px; color: #b0c8ca;
    }
    /* Input row */
    .social-comment-input-row {
      display: flex; gap: 8px; align-items: flex-end;
      padding: 10px 0 4px;
      border-top: 1px solid #eef5f5;
      margin-top: 4px;
    }
    .comment-input-shell {
      flex: 1; position: relative;
    }
    .social-comment-input {
      width: 100%; padding: 10px 14px;
      border: 1.5px solid #daeaea;
      border-radius: 22px;
      font-size: 13.5px; font-family: inherit;
      outline: none; background: #f4fafa; color: #1a2e2f;
      resize: none; overflow: hidden; line-height: 1.4;
      transition: border-color 0.18s, box-shadow 0.18s, background 0.18s;
      display: block;
    }
    .social-comment-input::placeholder { color: #b0c4c6; }
    .social-comment-input:focus {
      border-color: #0E4950;
      box-shadow: 0 0 0 3px rgba(14,73,80,0.09);
      background: #fff;
    }
    .social-comment-send {
      width: 38px; height: 38px; border: none; border-radius: 50%;
      background: #0E4950; color: white;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer; flex-shrink: 0;
      box-shadow: 0 2px 8px rgba(14,73,80,0.25);
      transition: transform 0.12s, background 0.15s, box-shadow 0.15s;
    }
    .social-comment-send:hover {
      background: #0b3d43;
      box-shadow: 0 4px 12px rgba(14,73,80,0.35);
      transform: scale(1.06);
    }
    .social-comment-send:active  { transform: scale(0.93); }
    .social-comment-send:disabled { opacity: 0.45; cursor: not-allowed; transform: none; box-shadow: none; }
    @keyframes commentSlideIn {
      from { opacity: 0; transform: translateY(6px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    .social-comment-item { animation: commentSlideIn 0.22s ease both; }
    .create-post-card {
      background: white; border-radius: 16px; border: 1px solid #daeaea;
      padding: 14px; margin-bottom: 14px;
      box-shadow: 0 2px 10px rgba(14,73,80,0.06);
    }
    .create-post-row { display: flex; gap: 10px; align-items: flex-start; }
    .create-post-textarea {
      flex: 1; border: 1.5px solid #daeaea; border-radius: 12px;
      padding: 10px 14px; font-size: 14px; font-family: inherit;
      resize: none; outline: none; background: #f4fafa; min-height: 70px;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .create-post-textarea:focus {
      border-color: #0E4950; box-shadow: 0 0 0 3px rgba(14,73,80,0.08); background: white;
    }
    .create-post-actions {
      display: flex; justify-content: space-between; align-items: center;
      margin-top: 10px;
    }
    .post-submit-btn {
      background: linear-gradient(135deg,#0E4950,#1a6b75);
      color: white; border: none; padding: 9px 20px;
      border-radius: 10px; font-weight: 700; font-size: 13px;
      cursor: pointer; font-family: inherit;
      transition: transform 0.15s, box-shadow 0.15s;
    }
    .post-submit-btn:hover { transform: translateY(-1px); box-shadow: 0 4px 14px rgba(14,73,80,0.3); }
    .post-submit-btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
    .photo-attach-btn {
      background: none; border: 1.5px solid #daeaea; padding: 8px 12px;
      border-radius: 10px; color: #7aabae; cursor: pointer;
      font-size: 12px; font-weight: 600; font-family: inherit;
      display: flex; align-items: center; gap: 6px; transition: all 0.18s;
    }
    .photo-attach-btn:hover { border-color: #0E4950; color: #0E4950; background: #f0fafa; }
    /* Post creation modal */
    #postCreateModal {
      display: none; position: fixed; inset: 0;
      background: #fff;
      z-index: 2000; flex-direction: column;
    }
    #postCreateModal.open { display: flex; }
    .post-modal-sheet {
      display: flex; flex-direction: column;
      width: 100%; height: 100%;
      padding: calc(env(safe-area-inset-top,14px) + 14px) 18px calc(24px + env(safe-area-inset-bottom,0px));
      animation: slideUpSheet 0.25s cubic-bezier(.32,1,.55,1) both;
      overflow-y: auto;
    }
    @keyframes slideUpSheet {
      from { transform: translateY(40px); opacity: 0; }
      to   { transform: translateY(0);    opacity: 1; }
    }
    .post-modal-handle { display: none; }
    .post-modal-header {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 20px;
    }
    .post-modal-title { font-size: 18px; font-weight: 700; color: #0E4950; }
    .post-modal-close {
      width: 34px; height: 34px; border: none; background: #eef6f6;
      border-radius: 50%; color: #0E4950; font-size: 17px;
      cursor: pointer; display: flex; align-items: center; justify-content: center;
    }
    /* People cards */
    .people-card {
      background: white; border-radius: 16px; border: 1px solid #daeaea;
      padding: 16px; margin-bottom: 10px; display: flex; gap: 12px;
      align-items: center; box-shadow: 0 2px 8px rgba(14,73,80,0.05);
    }
    .people-info { flex: 1; min-width: 0; }
    .people-name {
      font-weight: 700; font-size: 14px; color: #1a2e2f;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .people-headline {
      font-size: 12px; color: #7aabae; margin-top: 2px;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .connect-btn {
      border: 1.5px solid #0E4950; background: none; color: #0E4950;
      padding: 7px 14px; border-radius: 10px; font-weight: 700; font-size: 12px;
      cursor: pointer; font-family: inherit; white-space: nowrap;
      transition: all 0.18s; flex-shrink: 0;
    }
    .connect-btn:hover { background: #0E4950; color: white; }
    .connect-btn.connected { background: #0E4950; color: white; border-color: #0E4950; }
    .connect-btn.pending { border-color: #aac4c5; color: #aac4c5; cursor: default; }
    /* Connection requests */
    .conn-req-card {
      background: white; border-radius: 14px; border: 1px solid #daeaea;
      padding: 14px; margin-bottom: 10px; display: flex; gap: 10px;
      align-items: center; box-shadow: 0 1px 6px rgba(14,73,80,0.05);
    }
    .conn-req-actions { display: flex; gap: 8px; flex-shrink: 0; }
    .accept-btn {
      background: #0E4950; color: white; border: none;
      padding: 7px 12px; border-radius: 9px; font-size: 12px;
      font-weight: 700; cursor: pointer; font-family: inherit;
    }
    .decline-btn {
      background: none; color: #999; border: 1.5px solid #ddd;
      padding: 7px 10px; border-radius: 9px; font-size: 12px;
      font-weight: 600; cursor: pointer; font-family: inherit;
    }
    /* Social Profile overlay */
    #socialProfileOverlay {
      display: none; position: fixed; inset: 0; background: #eef6f6;
      z-index: 9200; flex-direction: column; overflow: hidden;
      transform: translateX(100%);
      transition: transform 0.32s cubic-bezier(0.25,0.46,0.45,0.94);
    }
    #socialProfileOverlay.spo-visible {
      display: flex; transform: translateX(0);
    }
    #socialProfileBody {
      flex: 1; overflow-y: auto; padding: 15px 15px calc(30px + env(safe-area-inset-bottom,0px));
    }
    .social-profile-banner {
      height: 75px; background: linear-gradient(135deg,#0E4950,#2ec4b6); position: relative;
    }
    .social-profile-avatar-wrap {
      position: absolute; bottom: -36px; left: 18px;
    }
    .social-profile-stats {
      display: flex; gap: 0; background: white; border-radius: 14px;
      border: 1px solid #daeaea; margin-bottom: 14px;
      overflow: hidden; box-shadow: 0 2px 8px rgba(14,73,80,0.06);
    }
    .social-stat {
      flex: 1; text-align: center; padding: 14px 8px;
      border-right: 1px solid #f0f7f7;
    }
    .social-stat:last-child { border-right: none; }
    .social-stat-val {
      font-size: 20px; font-weight: 800; color: #0E4950; display: block;
    }
    .social-stat-label { font-size: 11px; color: #7aabae; font-weight: 600; }
    /* Image viewer */
    #socialImgViewer {
      display: none; position: fixed; inset: 0; z-index: 9999;
      background: rgba(0,0,0,0.92); align-items: center; justify-content: center;
    }
    #socialImgViewer.open { display: flex; }
    #socialImgViewer img { max-width: 95vw; max-height: 85vh; border-radius: 12px; }
  </style>
</head>
<body>

  <div id="main-content">
    <!-- Content will be loaded here based on active tab -->
  </div>

  <div class="bottom-nav">
    <div class="tab active" onclick="openTab('chat', this)">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      <span>Chat</span>
    </div>
    <div class="tab" onclick="openTab('social', this)">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
      <span>Social</span>
    </div>
    <div class="tab" onclick="openTab('video', this)">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/><line x1="12" y1="2" x2="12" y2="5"/><line x1="12" y1="19" x2="12" y2="22"/><line x1="2" y1="12" x2="5" y2="12"/><line x1="19" y1="12" x2="22" y2="12"/></svg>
      <span>Target</span>
    </div>
    <div class="tab" onclick="openTab('market', this)">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
      <span>History</span>
    </div>
  </div>

  <!-- Social Image Viewer -->
  <div id="socialImgViewer" onclick="closeSocialImgViewer()">
    <img id="socialImgViewerImg" src="" alt="">
  </div>

  <!-- Social Profile Overlay -->
  <div id="socialProfileOverlay">
    <div style="background:white;padding:14px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #daeaea;box-shadow:0 2px 10px rgba(14,73,80,0.07);flex-shrink:0;padding-top:calc(14px + env(safe-area-inset-top,0px));">
      <button onclick="closeSocialProfile()" style="background:none;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;color:#0E4950;padding:4px;">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      </button>
      <span style="font-size:17px;font-weight:700;color:#0E4950;">Profile</span>
    </div>
    <div id="socialProfileBody"></div>
  </div>

  <!-- Add Contact Modal -->
  <div id="contactModal" class="modal">
    <div class="modal-content">
      <h3>Add New Contact</h3>
      <form id="contactForm">
        <input type="hidden" name="user" id="userPhone">
        <div class="form-group">
          <label>Country Code</label>
          <select name="country_code" class="form-control" required>
            <option value="+91"> India (+91)</option>
            <option value="+1"> USA (+1)</option>
            <option value="+44">UK (+44)</option>
          </select>
        </div>
        <div class="form-group">
          <label>Phone Number</label>
          <input type="text" name="contact_phone" class="form-control"
                 placeholder="Enter phone number" required>
        </div>
        <div class="form-group">
          <label>Contact Name</label>
          <input type="text" name="contact_name" class="form-control"
                 placeholder="Enter full name" required>
        </div>
        <div class="button-group">
          <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
          <button type="submit" class="btn btn-primary" id="saveBtn">Save Contact</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    let allContacts = []; // Store all contacts for search functionality

    function openTab(tabName, element) {
      // Remove active class from all tabs
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));

      // Add active class to clicked tab
      if (element) {
        element.classList.add('active');
      } else {
        // If no element provided, find and activate chat tab
        document.querySelector('.tab[onclick*="chat"]').classList.add('active');
      }

      let content = document.getElementById('main-content');
      const isLoggedIn = localStorage.getItem('exomnia_user_phone');

      if (tabName === 'chat') {
        if (isLoggedIn) {
          // User is logged in - load contacts
          loadContacts(isLoggedIn);
        } else {
          content.innerHTML = `
            <h2> Chat</h2>
            <div class="placeholder-content">
              <p>Please login to access the chat feature</p>
              <button onclick="openChatLogin()" style="background: #0E4950; color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; margin-top: 10px;">
                Login to Chat
              </button>
            </div>
          `;
        }
      }
      else if (tabName === 'social') {
        loadSocialTab();
      }
      else if (tabName === 'video') {
        content.innerHTML = `
          <h2>Target</h2>
          <div class="placeholder-content">
            <p style="text-align: center; color: #666; font-style: italic;">
              Target feature coming soon...<br>
              Set and track your goals with the community.
            </p>
          </div>
        `;
      }
      else if (tabName === 'market') {
        content.innerHTML = `
          <h2>History</h2>
          <div class="placeholder-content">
            <p style="text-align: center; color: #666; font-style: italic;">
              History feature coming soon...<br>
              Review your past activity and interactions.
            </p>
          </div>
        `;
      }
      else if (tabName === 'profile') {
        loadProfileTab();
      }
    }

    function openChatLogin() {
      window.location.href = '/';
    }

    function loadContacts(phone) {
      fetch(`/api/contacts?phone=${encodeURIComponent(phone)}`)
        .then(response => response.json())
        .then(contacts => {
          allContacts = contacts; // Store contacts for search functionality
          renderContacts(contacts);
        })
        .catch(error => {
          console.error('Error loading contacts:', error);
          let content = document.getElementById('main-content');
          content.innerHTML = `
            <h2>Chat</h2>
            <div class="placeholder-content">
              <p style="color: red;">Failed to load contacts. Please try again.</p>
            </div>
          `;
        });
    }

    function renderContacts(contacts) {
      let content = document.getElementById('main-content');
      const phone = localStorage.getItem('exomnia_user_phone');

      // Shared header buttons used by both branches
      const headerButtons = `
        <div style="display:flex;gap:16px;align-items:center;">
          <!-- Create Group -->
          <button onclick="openCreateGroupModal()" title="Create Group" aria-label="Create Group"
            style="background:none;border:none;padding:4px;cursor:pointer;color:#2ec4b6;display:flex;align-items:center;justify-content:center;transition:opacity 0.15s,transform 0.15s;"
            onmouseover="this.style.opacity='0.7';this.style.transform='scale(1.15)'"
            onmouseout="this.style.opacity='1';this.style.transform='scale(1)'">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="8" cy="7" r="3"/>
              <path d="M2 21v-1.5A4.5 4.5 0 0 1 6.5 15h3A4.5 4.5 0 0 1 14 19.5V21"/>
              <circle cx="17" cy="7" r="3" opacity="0.5"/>
              <path d="M14.5 15.2A4.5 4.5 0 0 1 17 15h1A4.5 4.5 0 0 1 22 19.5V21" opacity="0.5"/>
              <line x1="19" y1="1" x2="19" y2="5" stroke-width="2.5"/>
              <line x1="17" y1="3" x2="21" y2="3" stroke-width="2.5"/>
            </svg>
          </button>
          <!-- Add Contact -->
          <button onclick="addNewContact()" title="Add Contact" aria-label="Add Contact"
            style="background:none;border:none;padding:4px;cursor:pointer;color:#0E4950;display:flex;align-items:center;justify-content:center;transition:opacity 0.15s,transform 0.15s;"
            onmouseover="this.style.opacity='0.7';this.style.transform='scale(1.15)'"
            onmouseout="this.style.opacity='1';this.style.transform='scale(1)'">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="10" cy="8" r="4"/>
              <path d="M2 21v-1a7 7 0 0 1 7-7h2a7 7 0 0 1 7 7v1"/>
              <line x1="19" y1="1" x2="19" y2="7" stroke-width="2.5"/>
              <line x1="16" y1="4" x2="22" y2="4" stroke-width="2.5"/>
            </svg>
          </button>
          <!-- Profile Avatar -->
          <button id="headerProfileBtn" onclick="openProfileFromHeader()" title="My Profile" aria-label="My Profile"
            style="background:none;border:none;padding:2px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:transform 0.18s,box-shadow 0.18s;border-radius:50%;box-shadow:0 2px 10px rgba(14,73,80,0.18);"
            onmouseover="this.style.transform='scale(1.10)';this.style.boxShadow='0 4px 16px rgba(14,73,80,0.32)'"
            onmouseout="this.style.transform='scale(1)';this.style.boxShadow='0 2px 10px rgba(14,73,80,0.18)'">
            <div style="width:40px;height:40px;border-radius:50%;padding:2px;background:linear-gradient(135deg,#2ec4b6,#0E4950);flex-shrink:0;">
              <div id="headerProfileAvatar"
                style="width:100%;height:100%;border-radius:50%;background:#0E4950;display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:15px;overflow:hidden;border:2px solid #fff;">
                <span id="headerProfileInner">?</span>
              </div>
            </div>
          </button>
        </div>`;

      let baseHTML;
      if (contacts.length === 0) {
        baseHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <h2 style="color: #0E4950; margin: 0;">Chat</h2>
            ${headerButtons}
          </div>
          <div class="placeholder-content" id="no-contacts-placeholder">
            <div style="font-size: 40px; margin-bottom: 12px;"></div>
            <h3 style="font-size: 18px; margin-bottom: 8px; color: #333;">No contacts yet</h3>
            <p style="font-size: 14px; color: #666;">Add someone to start chatting!</p>
            <button onclick="addNewContact()" style="background: #0E4950; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; margin-top: 15px; font-weight: bold;">
              + Add Contact
            </button>
          </div>
          <div id="groups-section"></div>`;
      } else {
        let contactsHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <h2 style="color: #0E4950; margin: 0;">Contacts</h2>
            ${headerButtons}
          </div>
          <div class="search-container">
            <input type="text" id="searchInput" class="search-input" placeholder="Search contacts by name or phone..." onkeyup="filterContacts()">
          </div>
          <div id="contactsList" style="display: flex; flex-direction: column; gap: 10px;">`;
        contacts.forEach(contact => { contactsHTML += generateContactHTML(contact); });
        contactsHTML += `</div><div id="groups-section"></div>`;
        baseHTML = contactsHTML;
      }

      // Render the skeleton immediately so the page isn't blank while groups load
      content.innerHTML = baseHTML;
      updateHeaderProfileAvatar();

      // Always fetch and render groups — this is the single source of truth for the groups section
      fetch('/api/groups?phone=' + encodeURIComponent(phone))
        .then(r => r.json())
        .then(groups => {
          const groupsSection = document.getElementById('groups-section');
          if (!groupsSection) return;
          if (groups.length > 0) {
            let groupsHTML = `
              <div style="margin-top:20px;">
                <h3 style="color:#0E4950;font-size:15px;font-weight:700;margin-bottom:10px;">Groups</h3>
                <div style="display:flex;flex-direction:column;gap:10px;">`;
            groups.forEach(g => { groupsHTML += generateGroupHTML(g); });
            groupsHTML += `</div></div>`;
            groupsSection.innerHTML = groupsHTML;
          } else {
            groupsSection.innerHTML = '';
          }
          attachDeleteRowEvents(content);
        })
        .catch(() => {
          const groupsSection = document.getElementById('groups-section');
          if (groupsSection) groupsSection.innerHTML = '';
        });
    }

    // ── Header Profile Avatar ──────────────────────────────────────
    function updateHeaderProfileAvatar() {
      const phone = localStorage.getItem('exomnia_user_phone');
      if (!phone) return;
      const avatarDiv = document.getElementById('headerProfileAvatar');
      const innerSpan = document.getElementById('headerProfileInner');
      if (!avatarDiv || !innerSpan) return;
      fetch('/api/profile?phone=' + encodeURIComponent(phone))
        .then(r => r.json())
        .then(data => {
          if (data.avatar_photo) {
            avatarDiv.style.background = 'transparent';
            avatarDiv.style.overflow = 'hidden';
            // Replace span with a full-bleed img so object-fit:cover fills the circle perfectly
            innerSpan.style.cssText = 'display:contents;';
            innerSpan.innerHTML = `<img src="${data.avatar_photo}" style="position:absolute;inset:0;width:100%;height:100%;object-fit:cover;border-radius:50%;display:block;" alt="">`;
            avatarDiv.style.position = 'relative';
          } else {
            const initial = (data.display_name || data.phone || '?')[0].toUpperCase();
            const content = data.avatar_emoji || initial;
            const color = data.avatar_color || '#0E4950';
            avatarDiv.style.background = color;
            avatarDiv.style.position = '';
            innerSpan.style.cssText = '';
            innerSpan.innerHTML = '';
            innerSpan.textContent = content;
          }
        })
        .catch(() => {
          const p = localStorage.getItem('exomnia_user_phone') || '?';
          if (innerSpan) innerSpan.textContent = p[0].toUpperCase();
        });
    }

    function openProfileFromHeader() {
      const phone = localStorage.getItem('exomnia_user_phone');
      if (!phone) { window.location.href = '/'; return; }
      const overlay = document.getElementById('profileFullOverlay');
      overlay.style.display = 'flex';
      // Animate in
      setTimeout(() => overlay.classList.add('pfo-visible'), 10);
      loadProfileOverlay(phone);
    }

    function closeProfileOverlay() {
      const overlay = document.getElementById('profileFullOverlay');
      overlay.classList.remove('pfo-visible');
      setTimeout(() => { overlay.style.display = 'none'; }, 320);
    }

    function openProfileNetworkPage() {
      const phone = localStorage.getItem('exomnia_user_phone');
      if (!phone) return;
      const page = document.getElementById('profileNetworkPage');
      const body = document.getElementById('profileNetworkBody');
      page.style.display = 'flex';
      requestAnimationFrame(() => page.classList.add('pnp-visible'));
      body.innerHTML = '<div class="pnp-empty"><div class="pnp-empty-icon">&#128101;</div><div class="pnp-empty-text">Loading...</div></div>';
      fetch('/api/social/connections?phone=' + encodeURIComponent(phone))
        .then(r => r.json())
        .then(data => {
          const all = [...new Set([...(data.followers || []), ...(data.following || [])])];
          if (all.length === 0) {
            body.innerHTML = '<div class="pnp-empty"><div class="pnp-empty-icon">&#128101;</div><div class="pnp-empty-text">No connections yet</div><div class="pnp-empty-sub">Connect with people to grow your network</div></div>';
            return;
          }
          return Promise.all(all.map(p => fetch('/api/profile?phone=' + encodeURIComponent(p)).then(r => r.json()).catch(() => ({phone: p, display_name: p}))));
        })
        .then(profiles => {
          if (!profiles) return;
          body.innerHTML = profiles.map(p => {
            const initial = (p.display_name || p.phone || '?')[0].toUpperCase();
            const avatarContent = p.avatar_photo
              ? `<img src="${p.avatar_photo}" style="width:100%;height:100%;object-fit:cover;" alt="">`
              : (p.avatar_emoji || initial);
            const bgColor = p.avatar_color || '#0E4950';
            return `<div class="pnp-user-card" onclick="openSocialProfile('${p.phone}')" style="cursor:pointer;">
              <div class="pnp-user-avatar" style="background:${p.avatar_photo ? 'transparent' : bgColor};">
                ${avatarContent}
              </div>
              <div style="flex:1;min-width:0;">
                <div style="font-weight:700;color:#1a2e2f;font-size:15px;">${escapeHtml(p.display_name && p.display_name.trim() ? p.display_name : 'NEOX User')}</div>
                ${p.headline ? `<div style="font-size:12px;color:#0E4950;margin-top:2px;">${escapeHtml(p.headline)}</div>` : ''}
                <div style="font-size:12px;color:#8aa3a5;margin-top:2px;"></div>
              </div>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#b0c8ca" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><polyline points="9 18 15 12 9 6"/></svg>
            </div>`;
          }).join('');
        })
        .catch(() => {
          body.innerHTML = '<div class="pnp-empty"><div class="pnp-empty-text" style="color:red;">Failed to load network</div></div>';
        });
    }

    function closeProfileNetworkPage() {
      const page = document.getElementById('profileNetworkPage');
      page.classList.remove('pnp-visible');
      setTimeout(() => { page.style.display = 'none'; }, 320);
    }

    function openProfilePostsPage() {
      const phone = localStorage.getItem('exomnia_user_phone');
      if (!phone) return;
      const page = document.getElementById('profilePostsPage');
      const body = document.getElementById('profilePostsBody');
      page.style.display = 'flex';
      requestAnimationFrame(() => page.classList.add('pnp-visible'));
      body.innerHTML = '<div class="pnp-empty"><div class="pnp-empty-icon">&#128221;</div><div class="pnp-empty-text">Loading...</div></div>';
      fetch('/api/social/user_posts?phone=' + encodeURIComponent(phone) + '&viewer=' + encodeURIComponent(phone))
        .then(r => r.json())
        .then(posts => {
          if (!posts || posts.length === 0) {
            body.innerHTML = '<div class="pnp-empty"><div class="pnp-empty-icon">&#128221;</div><div class="pnp-empty-text">No posts yet</div><div class="pnp-empty-sub">Share something with your network</div></div>';
            return;
          }
          body.innerHTML = posts.map(post => {
            const ts = post.timestamp ? new Date(post.timestamp).toLocaleDateString('en-IN', {day:'numeric',month:'short',year:'numeric'}) : '';
            const imgHtml = post.image_path ? `<img class="pnp-post-img" src="${post.image_path}" alt="" onclick="openSocialImgViewer && openSocialImgViewer('${post.image_path}')">` : '';
            return `<div class="pnp-post-card">
              <div style="font-size:13px;color:#aaa;margin-bottom:8px;">${ts}</div>
              <div style="font-size:15px;color:#1a2e2f;line-height:1.5;">${escapeHtml(post.content || '')}</div>
              ${imgHtml}
              <div style="display:flex;gap:16px;margin-top:12px;">
                <span style="font-size:13px;color:#888;">&#10084; ${post.likes || 0}</span>
                <span style="font-size:13px;color:#888;">&#128172; ${post.comment_count || 0}</span>
              </div>
            </div>`;
          }).join('');
        })
        .catch(() => {
          body.innerHTML = '<div class="pnp-empty"><div class="pnp-empty-text" style="color:red;">Failed to load posts</div></div>';
        });
    }

    function closeProfilePostsPage() {
      const page = document.getElementById('profilePostsPage');
      page.classList.remove('pnp-visible');
      setTimeout(() => { page.style.display = 'none'; }, 320);
    }

    function loadProfileOverlay(phone) {
      const body = document.getElementById('profileOverlayBody');
      body.innerHTML = `<div style="display:flex;justify-content:center;padding:60px 0;"><div style="width:28px;height:28px;border:3px solid #0E4950;border-top-color:transparent;border-radius:50%;animation:spin 0.7s linear infinite;"></div></div>`;
      Promise.all([
        fetch('/api/profile?phone=' + encodeURIComponent(phone)).then(r => r.json()),
        fetch('/api/social/user_stats?phone=' + encodeURIComponent(phone)).then(r => r.json()).catch(() => ({}))
      ]).then(([data, stats]) => {
          _profileData = data;
          renderProfileOverlay(data, stats);
        })
        .catch(() => {
          body.innerHTML = `<div style="padding:40px;text-align:center;color:red;">Failed to load profile.</div>`;
        });
    }

    function renderProfileOverlay(p, stats) {
      stats = stats || {};
      const body = document.getElementById('profileOverlayBody');
      const initial = (p.display_name || p.phone || '?')[0].toUpperCase();
      const avatarInner = p.avatar_emoji || initial;
      const memberSince = p.last_online ? new Date(p.last_online).toLocaleDateString('en-IN', {month:'long', year:'numeric'}) : '—';
      const bgColor = p.avatar_color || '#0E4950';
      const connections = (stats.followers || 0) + (stats.following || 0);
      const postsCount = stats.posts || 0;

      const avatarContent = p.avatar_photo
        ? `<img src="${p.avatar_photo}?t=${Date.now()}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;display:block;" alt="">`
        : `<span style="font-size:34px;font-weight:700;color:white;line-height:1;">${avatarInner}</span>`;

      body.innerHTML = `
        <div class="profile-card">
          <div class="profile-banner" style="${p.banner_photo ? `background-image:url('${p.banner_photo}?t=${Date.now()}');background-size:cover;background-position:center;` : ''}">
            <button class="pfo-back-btn" onclick="closeProfileOverlay()" aria-label="Back">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
            </button>
            <button onclick="triggerBannerPhotoInput()" title="Change banner" style="position:absolute;bottom:10px;right:12px;background:rgba(0,0,0,0.42);border:1.5px solid rgba(255,255,255,0.6);color:#fff;border-radius:20px;padding:5px 11px;display:flex;align-items:center;gap:5px;font-size:12px;font-weight:600;font-family:inherit;cursor:pointer;backdrop-filter:blur(4px);z-index:3;">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="3"/></svg>
              Edit cover
            </button>
          </div>
          <input type="file" id="bannerPhotoInput" accept="image/*" style="display:none" onchange="uploadBannerPhoto(this)">
          <div class="profile-avatar-wrap">
            <div style="position:relative;display:inline-block;">
              <div class="profile-avatar" style="background:${p.avatar_photo ? 'transparent' : bgColor};overflow:hidden;" onclick="triggerAvatarPhotoInput()" title="Change photo">
                ${avatarContent}
              </div>
              <button onclick="triggerAvatarPhotoInput()" title="Change photo" style="position:absolute;bottom:2px;right:2px;width:26px;height:26px;border-radius:50%;background:#0E4950;border:2.5px solid white;display:flex;align-items:center;justify-content:center;cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,0.25);z-index:3;">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="3"/></svg>
              </button>
            </div>
          </div>
          <input type="file" id="avatarPhotoInput" accept="image/*" style="display:none" onchange="uploadAvatarPhoto(this)">
          <div class="profile-info-block">
            <div class="profile-display-name">${p.display_name || 'Exomnia User'}</div>
            <div class="profile-bio">${p.bio ? escapeHtml(p.bio) : '<span style="color:#bbb;font-style:italic;">No bio yet</span>'}</div>
          </div>
          <div style="display:flex;justify-content:center;gap:0;border-top:1px solid #f0f0f0;margin-top:14px;border-radius:0 0 24px 24px;overflow:hidden;">
            <div id="profileNetworkTab" style="flex:1;text-align:center;padding:14px 8px;border-right:1px solid #f0f0f0;cursor:pointer;position:relative;" onclick="openProfileNetworkPage()">
              <div style="font-size:20px;font-weight:800;color:#0E4950;">${connections}</div>
              <div style="font-size:11px;color:#888;font-weight:500;margin-top:2px;">Network</div>

            </div>
            <div id="profilePostsTab" style="flex:1;text-align:center;padding:14px 8px;cursor:pointer;position:relative;" onclick="openProfilePostsPage()">
              <div style="font-size:20px;font-weight:800;color:#0E4950;">${postsCount}</div>
              <div style="font-size:11px;color:#888;font-weight:500;margin-top:2px;">Posts</div>
            </div>
          </div>
        </div>

        <div class="profile-section">
          <div class="profile-row" onclick="openProfileEditFromOverlay()">
            <div class="profile-row-icon" style="background:#e8f5f5;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0E4950" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            </div>
            <div>
              <div class="profile-row-label">Edit Profile</div>
              <div class="profile-row-sub">Name, bio, avatar</div>
            </div>
            <div class="profile-row-chevron"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg></div>
          </div>
          <div class="profile-row" onclick="copyPhone()">
            <div class="profile-row-icon" style="background:#fff3e0;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e76f51" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 12a19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 3.6 1.18h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.73a16 16 0 0 0 6.29 6.29l1.62-1.62a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
            </div>
            <div>
              <div class="profile-row-label">Phone Number</div>
              <div class="profile-row-sub">${p.phone} · tap to copy</div>
            </div>
          </div>
        </div>

        <div class="profile-section">
          <div class="profile-row">
            <div class="profile-row-icon" style="background:#e8f0ff;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#5c6bc0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </div>
            <div>
              <div class="profile-row-label">End-to-End Encrypted</div>
              <div class="profile-row-sub">All messages are secured</div>
            </div>
          </div>
          <div class="profile-row">
            <div class="profile-row-icon" style="background:#fce4ec;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e91e63" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            </div>
            <div>
              <div class="profile-row-label">Member Since</div>
              <div class="profile-row-sub">${memberSince}</div>
            </div>
          </div>
        </div>

        <div class="profile-section">
          <div class="profile-row" onclick="confirmLogout()" style="color:#e53935;">
            <div class="profile-row-icon" style="background:#fdecea;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e53935" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            </div>
            <div class="profile-row-label" style="color:#e53935;">Logout</div>
          </div>
        </div>
      `;
    }

    function openProfileEditFromOverlay() {
      openProfileEdit();
    }

    function generateGroupHTML(group) {
      const phone = localStorage.getItem('exomnia_user_phone');
      const letter = group.avatar_letter || group.name[0].toUpperCase();
      const memberCount = group.member_count || 0;
      const isCreator = String(group.created_by) === String(phone);
      const actionLabel = isCreator ? 'Delete Group' : 'Leave Group';
      return `
        <div class="deletable-row" data-type="group" data-id="${group.id}" data-label="${group.name.replace(/"/g,'&quot;')}" data-action="${actionLabel}">
          <a href="/group/${group.id}?phone=${encodeURIComponent(phone)}" style="text-decoration:none;color:inherit;display:block;">
            <div style="background:white;padding:14px 16px;border-radius:18px;display:flex;align-items:center;gap:13px;box-shadow:0 2px 12px rgba(14,73,80,0.07);border:1px solid #daeaea;">
              <div style="width:48px;height:48px;border-radius:14px;background:linear-gradient(135deg,#2ec4b6,#0E4950);display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:19px;flex-shrink:0;">
                ${letter}
              </div>
              <div style="flex:1;min-width:0;">
                <div style="font-weight:700;color:#1a2e2f;font-size:15px;margin-bottom:2px;">${group.name}</div>
                <div style="color:#8aa3a5;font-size:12px;">${memberCount} member${memberCount !== 1 ? 's' : ''}</div>
                <div style="color:#9bb5b7;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${group.last_message || 'No messages yet'}</div>
              </div>
              <div style="color:#ccd8d8;flex-shrink:0;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg></div>
            </div>
          </a>
        </div>
      `;
    }

    function generateContactHTML(contact) {
      const initial = contact.contact_name ? contact.contact_name[0].toUpperCase() : contact.contact_phone[0];
      const displayName = contact.contact_name || contact.contact_phone;
      const phone = localStorage.getItem('exomnia_user_phone');
      const rawMsg = contact.last_message || '';
      const isYou = contact.last_sender && String(contact.last_sender) === String(phone);

      // Detect voice message
      const isVoice = rawMsg === '' && contact.last_sender; // no text = likely voice
      let previewIcon = '';
      let previewText = '';
      if (!rawMsg && !contact.last_sender) {
        previewText = 'No messages yet';
      } else if (rawMsg.startsWith('🎤') || rawMsg === '🎤 Voice message') {
        previewIcon = '🎤 ';
        previewText = (isYou ? '<span style="color:#0E4950;font-weight:600;">You: </span>' : '') + 'Voice message';
      } else if (rawMsg) {
        previewText = (isYou ? '<span style="color:#0E4950;font-weight:600;">You: </span>' : '') + rawMsg.replace(/</g,'&lt;').replace(/>/g,'&gt;');
      } else {
        previewText = 'No messages yet';
      }

      // Avatar: photo > emoji > initial
      const avatarColor = contact.avatar_color || '#0E4950';
      let avatarInner;
      if (contact.avatar_photo) {
        avatarInner = `<img src="${contact.avatar_photo}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;" alt="">`;
      } else if (contact.avatar_emoji) {
        avatarInner = contact.avatar_emoji;
      } else {
        avatarInner = initial;
      }

      return `
        <div class="deletable-row" data-type="contact" data-phone="${contact.contact_phone}" data-label="${displayName.replace(/"/g,'&quot;')}" data-action="Delete Contact">
          <a href="/chat/${encodeURIComponent(contact.contact_phone)}?phone=${encodeURIComponent(phone)}"
             style="text-decoration: none; color: inherit; display:block;">
            <div style="background: white; padding: 14px 16px; border-radius: 18px; display: flex; align-items: center; gap: 13px; box-shadow: 0 2px 12px rgba(14,73,80,0.07); transition: all 0.25s ease; border: 1px solid #daeaea;">
              <div style="width: 48px; height: 48px; border-radius: 50%; background: linear-gradient(135deg, ${avatarColor}, #2ec4b6); display: flex; align-items: center; justify-content: center; color: white; font-weight: 700; font-size: 19px; flex-shrink: 0; box-shadow: 0 2px 8px rgba(14,73,80,0.2); overflow:hidden;">
                ${avatarInner}
              </div>
              <div style="flex: 1; min-width: 0;">
                <div style="font-weight: 700; color: #1a2e2f; font-size: 15px; margin-bottom: 1px; letter-spacing: -0.01em;">${displayName}</div>
                ${!contact.contact_name ? `<div style="color: #8aa3a5; font-size: 12px; margin-bottom: 2px;">${contact.contact_phone}</div>` : ''}
                <div style="color: #9bb5b7; font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${previewText}</div>
              </div>
              <div style="color: #ccd8d8; flex-shrink: 0;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg></div>
            </div>
          </a>
        </div>
      `;
    }

    function filterContacts() {
      const searchTerm = document.getElementById('searchInput').value.toLowerCase();
      const contactsList = document.getElementById('contactsList');

      if (!contactsList) return;

      const filteredContacts = allContacts.filter(contact => {
        const name = (contact.contact_name || '').toLowerCase();
        const phone = (contact.contact_phone || '').toLowerCase();

        return name.includes(searchTerm) || phone.includes(searchTerm);
      });

      if (filteredContacts.length === 0) {
        contactsList.innerHTML = `
          <div class="no-contacts-found">
            <p>No contacts found matching "${searchTerm}"</p>
          </div>
        `;
      } else {
        let contactsHTML = '';
        filteredContacts.forEach(contact => {
          contactsHTML += generateContactHTML(contact);
        });
        contactsList.innerHTML = contactsHTML;
      }
    }

    // Add Contact Modal Functions
    function addNewContact() {
      const phone = localStorage.getItem('exomnia_user_phone');
      if (phone) {
        document.getElementById('userPhone').value = phone;
        openModal();
      }
    }

    function openModal() {
      document.getElementById("contactModal").style.display = "flex";
    }

    function closeModal() {
      document.getElementById("contactModal").style.display = "none";
      document.getElementById("contactForm").reset();
      document.getElementById("saveBtn").classList.remove('loading');
      document.getElementById("saveBtn").textContent = 'Save Contact';
    }

    // Handle contact form submission
    document.getElementById('contactForm').addEventListener('submit', function(e) {
      e.preventDefault();
      const saveBtn = document.getElementById('saveBtn');
      const formData = new FormData(this);

      saveBtn.classList.add('loading');
      saveBtn.textContent = 'Saving...';

      fetch('/add_contact', {
        method: 'POST',
        body: formData,
        headers: {
          'X-Requested-With': 'XMLHttpRequest'
        }
      })
      .then(response => {
        if (response.ok) {
          closeModal();
          // Reload contacts
          const phone = localStorage.getItem('exomnia_user_phone');
          if (phone) {
            loadContacts(phone);
          }
        } else {
          throw new Error('Save failed');
        }
      })
      .catch(error => {
        saveBtn.classList.remove('loading');
        saveBtn.textContent = 'Save Contact';
        alert('Error saving contact. Please try again.');
        console.error('Error:', error);
      });
    });

    // Close modal when clicking outside
    document.getElementById('contactModal').addEventListener('click', function(e) {
      if (e.target === this) closeModal();
    });

    // Check for login status on page load
    window.addEventListener('load', function() {
      // Server-injected phone (most reliable on Render)
      const serverPhone = {{ logged_in_phone|tojson }};

      // URL param as fallback
      const urlParams = new URLSearchParams(window.location.search);
      const urlPhone = urlParams.get('logged_in_phone');

      const loggedInPhone = serverPhone || urlPhone;

      if (loggedInPhone) {
        localStorage.setItem('exomnia_user_phone', loggedInPhone);
        // Clean the URL
        window.history.replaceState({}, '', window.location.pathname);
        // Open chat tab
        openTab('chat');
      } else {
        // Check localStorage (already logged in before)
        const savedPhone = localStorage.getItem('exomnia_user_phone');
        if (savedPhone) {
          openTab('chat');
        } else {
          // Not logged in — send to login page
          window.location.href = '/';
        }
      }
    });
  </script>

  <!-- Create Group Modal -->
  <div id="createGroupModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,30,30,0.55);backdrop-filter:blur(6px);z-index:2000;align-items:flex-end;justify-content:center;">
    <div style="background:#fff;border-radius:28px 28px 0 0;padding:28px 22px calc(32px + env(safe-area-inset-bottom,0px));width:100%;max-height:90vh;overflow-y:auto;animation:slideUpFromBottom 0.35s cubic-bezier(0.25,0.46,0.45,0.94);">
      <div style="width:36px;height:4px;background:#ccd8d8;border-radius:2px;margin:0 auto 20px;"></div>
      <h3 style="color:#0E4950;font-size:18px;font-weight:700;margin-bottom:6px;">New Group</h3>
      <p style="color:#8aa3a5;font-size:13px;margin-bottom:20px;">Name your group and pick contacts to add.</p>

      <div style="margin-bottom:16px;">
        <label style="display:block;font-size:13px;font-weight:600;color:#4a6567;margin-bottom:6px;">Group Name</label>
        <input id="groupNameInput" type="text" placeholder="e.g. Family, Work Team…" style="width:100%;padding:12px 16px;border:1.5px solid #d8e8e8;border-radius:12px;font-size:15px;outline:none;font-family:inherit;background:#f8fafa;color:#1a2e2f;">
      </div>

      <div style="margin-bottom:20px;">
        <label style="display:block;font-size:13px;font-weight:600;color:#4a6567;margin-bottom:10px;">Select Members</label>
        <div id="groupContactPicker" style="display:flex;flex-direction:column;gap:8px;max-height:280px;overflow-y:auto;"></div>
      </div>

      <div style="display:flex;gap:10px;">
        <button onclick="closeCreateGroupModal()" style="flex:1;padding:13px;border:none;border-radius:12px;background:#eef2f2;color:#4a6567;font-weight:600;font-size:14px;cursor:pointer;font-family:inherit;">Cancel</button>
        <button onclick="submitCreateGroup()" style="flex:2;padding:13px;border:none;border-radius:12px;background:linear-gradient(135deg,#0E4950,#1a6b75);color:white;font-weight:700;font-size:14px;cursor:pointer;font-family:inherit;">Create Group</button>
      </div>
    </div>
  </div>

  <!-- Delete / Leave confirmation modal -->
  <div id="deleteRowModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,30,30,0.55);backdrop-filter:blur(6px);z-index:3000;align-items:flex-end;justify-content:center;">
    <div style="background:#fff;border-radius:28px 28px 0 0;padding:28px 22px calc(32px + env(safe-area-inset-bottom,0px));width:100%;animation:slideUpFromBottom 0.3s cubic-bezier(0.25,0.46,0.45,0.94);">
      <div style="width:36px;height:4px;background:#ccd8d8;border-radius:2px;margin:0 auto 20px;"></div>
      <p id="deleteRowLabel" style="font-size:16px;font-weight:600;color:#1a2e2f;text-align:center;margin-bottom:6px;"></p>
      <p id="deleteRowSub" style="font-size:13px;color:#8aa3a5;text-align:center;margin-bottom:24px;"></p>
      <div style="display:flex;gap:10px;">
        <button onclick="closeDeleteRowModal()" style="flex:1;padding:13px;border:none;border-radius:12px;background:#eef2f2;color:#4a6567;font-weight:600;font-size:14px;cursor:pointer;font-family:inherit;">Cancel</button>
        <button id="deleteRowConfirmBtn" style="flex:2;padding:13px;border:none;border-radius:12px;background:#e53935;color:white;font-weight:700;font-size:14px;cursor:pointer;font-family:inherit;">Delete</button>
      </div>
    </div>
  </div>

  <style>
    .deletable-row { position:relative; overflow:hidden; border-radius:18px; }
    .deletable-row.swiped-reveal { transform:translateX(-80px); transition:transform 0.2s ease; }
    .delete-swipe-btn {
      position:absolute; right:0; top:0; bottom:0; width:80px;
      background:#e53935; display:flex; align-items:center; justify-content:center;
      color:white; font-size:12px; font-weight:700; cursor:pointer;
      border-radius:0 18px 18px 0; flex-direction:column; gap:3px;
    }
  </style>

  <script>
    // ── Delete contact / group: long-press OR swipe-left ──────────
    let _delTarget = null;
    let _delPressTimer = null;
    let _swipeStartX = 0;
    let _swipeEl = null;
    let _currentlyRevealed = null;

    function openDeleteRowModal(el) {
      _delTarget = el;
      const label = el.dataset.label || '';
      const action = el.dataset.action || 'Delete';
      document.getElementById('deleteRowLabel').textContent = action + ': ' + label;
      document.getElementById('deleteRowSub').textContent =
        el.dataset.type === 'group' && action.startsWith('Leave')
          ? 'You will leave this group and no longer see its messages.'
          : el.dataset.type === 'group'
            ? 'This will permanently delete the group and all its messages for everyone.'
            : 'This contact will be removed from your list. Your chat history is kept.';
      const btn = document.getElementById('deleteRowConfirmBtn');
      btn.textContent = action.startsWith('Leave') ? 'Leave' : 'Delete';
      btn.style.background = '#e53935';
      document.getElementById('deleteRowModal').style.display = 'flex';
    }

    function closeDeleteRowModal() {
      document.getElementById('deleteRowModal').style.display = 'none';
      if (_currentlyRevealed) {
        _currentlyRevealed.style.transform = '';
        _currentlyRevealed = null;
      }
      _delTarget = null;
    }

    document.getElementById('deleteRowConfirmBtn').addEventListener('click', async function() {
      if (!_delTarget) return;
      const btn = this;
      btn.disabled = true; btn.textContent = 'Please wait…';
      const phone = localStorage.getItem('exomnia_user_phone');
      const type = _delTarget.dataset.type;
      try {
        let res, data;
        if (type === 'contact') {
          res = await fetch('/api/delete_contact', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ user_phone: phone, contact_phone: _delTarget.dataset.phone })
          });
          data = await res.json();
        } else {
          res = await fetch('/api/delete_group', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ user_phone: phone, group_id: parseInt(_delTarget.dataset.id) })
          });
          data = await res.json();
        }
        if (data.success) {
          _delTarget.style.transition = 'opacity 0.25s, transform 0.25s';
          _delTarget.style.opacity = '0';
          _delTarget.style.transform = 'translateX(-30px)';
          setTimeout(() => { _delTarget.remove(); }, 260);
          closeDeleteRowModal();
          loadContacts(phone); // refresh list
        } else {
          btn.disabled = false;
          btn.textContent = _delTarget.dataset.action || 'Delete';
          alert(data.error || 'Action failed. Please try again.');
        }
      } catch(e) {
        btn.disabled = false;
        btn.textContent = _delTarget.dataset.action || 'Delete';
        alert('Network error. Please try again.');
      }
    });

    document.getElementById('deleteRowModal').addEventListener('click', function(e) {
      if (e.target === this) closeDeleteRowModal();
    });

    // Attach long-press + swipe to any .deletable-row that appears in the DOM
    function attachDeleteRowEvents(container) {
      container.querySelectorAll('.deletable-row').forEach(row => {
        if (row._deleteEventsAttached) return;
        row._deleteEventsAttached = true;

        // ── Long-press (mobile & desktop) ──
        let pressTimer = null;
        row.addEventListener('pointerdown', function(e) {
          if (e.pointerType === 'touch') return; // handled by touchstart for touch
          pressTimer = setTimeout(() => openDeleteRowModal(row), 600);
        });
        row.addEventListener('pointerup', () => clearTimeout(pressTimer));
        row.addEventListener('pointercancel', () => clearTimeout(pressTimer));

        row.addEventListener('touchstart', function(e) {
          _swipeStartX = e.touches[0].clientX;
          _swipeEl = row;
          pressTimer = setTimeout(() => {
            clearTimeout(pressTimer);
            openDeleteRowModal(row);
          }, 600);
        }, { passive: true });
        row.addEventListener('touchmove', function(e) {
          clearTimeout(pressTimer);
          if (_swipeEl !== row) return;
          const dx = _swipeStartX - e.touches[0].clientX;
          if (dx > 10) {
            // Reveal swipe-delete button
            row.style.transition = '';
            row.style.transform = `translateX(${Math.min(-dx, -80)}px)`;
          }
        }, { passive: true });
        row.addEventListener('touchend', function(e) {
          clearTimeout(pressTimer);
          if (_swipeEl !== row) return;
          const dx = _swipeStartX - (e.changedTouches[0]?.clientX ?? _swipeStartX);
          if (dx > 60) {
            // Snap to revealed state and show delete button
            row.style.transition = 'transform 0.2s ease';
            row.style.transform = 'translateX(-80px)';
            // Add delete button overlay if not already there
            if (!row.querySelector('.delete-swipe-btn')) {
              const btn = document.createElement('div');
              btn.className = 'delete-swipe-btn';
              btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg><span>' + (row.dataset.action || 'Delete') + '</span>';
              btn.addEventListener('click', e => { e.stopPropagation(); openDeleteRowModal(row); });
              row.appendChild(btn);
            }
            if (_currentlyRevealed && _currentlyRevealed !== row) {
              _currentlyRevealed.style.transform = '';
              const old = _currentlyRevealed.querySelector('.delete-swipe-btn');
              if (old) old.remove();
            }
            _currentlyRevealed = row;
          } else {
            row.style.transition = 'transform 0.2s ease';
            row.style.transform = '';
          }
          _swipeEl = null;
        }, { passive: true });

        // Right-click on desktop
        row.addEventListener('contextmenu', function(e) {
          e.preventDefault();
          openDeleteRowModal(row);
        });
      });
    }

    // Patch renderContacts to call attachDeleteRowEvents after render
    const _origRenderContacts = window.renderContacts;
    // Re-attach after content renders (MutationObserver on main-content)
    const _mainContent = document.getElementById('main-content');
    if (_mainContent) {
      new MutationObserver(() => {
        attachDeleteRowEvents(_mainContent);
        // Dismiss swipe if user taps elsewhere
        _mainContent.addEventListener('click', function(e) {
          if (_currentlyRevealed && !_currentlyRevealed.contains(e.target)) {
            _currentlyRevealed.style.transform = '';
            const btn = _currentlyRevealed.querySelector('.delete-swipe-btn');
            if (btn) btn.remove();
            _currentlyRevealed = null;
          }
        }, true);
      }).observe(_mainContent, { childList: true, subtree: true });
    }
  </script>

  <script>
    let selectedGroupMembers = [];

    function openCreateGroupModal() {
      const phone = localStorage.getItem('exomnia_user_phone');
      if (!phone) { alert('Please login first.'); return; }

      selectedGroupMembers = [];
      document.getElementById('groupNameInput').value = '';

      // Populate contact picker from allContacts
      const picker = document.getElementById('groupContactPicker');
      picker.innerHTML = '';
      if (!allContacts || allContacts.length === 0) {
        picker.innerHTML = '<p style="color:#8aa3a5;font-size:13px;text-align:center;">No contacts yet. Add contacts first.</p>';
      } else {
        allContacts.forEach(c => {
          const displayName = c.contact_name || c.contact_phone;
          const initial = displayName[0].toUpperCase();
          const div = document.createElement('div');
          div.style.cssText = 'display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:12px;border:1.5px solid #d8e8e8;cursor:pointer;transition:all 0.2s;background:#f8fafa;';
          div.dataset.phone = c.contact_phone;
          div.innerHTML = `
            <div style="width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#0E4950,#2ec4b6);display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:15px;flex-shrink:0;">${initial}</div>
            <div style="flex:1;min-width:0;">
              <div style="font-weight:600;color:#1a2e2f;font-size:14px;">${displayName}</div>
              <div style="color:#8aa3a5;font-size:11px;">${c.contact_phone}</div>
            </div>
            <div class="check-icon" style="width:22px;height:22px;border-radius:50%;border:2px solid #d8e8e8;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:all 0.2s;"></div>
          `;
          div.addEventListener('click', () => toggleGroupMember(div, c.contact_phone));
          picker.appendChild(div);
        });
      }

      const modal = document.getElementById('createGroupModal');
      modal.style.display = 'flex';
      setTimeout(() => document.getElementById('groupNameInput').focus(), 100);
    }

    function toggleGroupMember(div, phone) {
      const idx = selectedGroupMembers.indexOf(phone);
      const check = div.querySelector('.check-icon');
      if (idx === -1) {
        selectedGroupMembers.push(phone);
        div.style.borderColor = '#2ec4b6';
        div.style.background = '#f0faf9';
        check.style.background = '#2ec4b6';
        check.style.borderColor = '#2ec4b6';
        check.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
      } else {
        selectedGroupMembers.splice(idx, 1);
        div.style.borderColor = '#d8e8e8';
        div.style.background = '#f8fafa';
        check.style.background = 'transparent';
        check.style.borderColor = '#d8e8e8';
        check.innerHTML = '';
      }
    }

    function closeCreateGroupModal() {
      document.getElementById('createGroupModal').style.display = 'none';
    }

    let isCreatingGroup = false;
    function submitCreateGroup() {
      if (isCreatingGroup) return; // prevent double submission
      const name = document.getElementById('groupNameInput').value.trim();
      const phone = localStorage.getItem('exomnia_user_phone');
      if (!name) { alert('Please enter a group name.'); return; }
      if (selectedGroupMembers.length === 0) { alert('Please select at least one member.'); return; }

      isCreatingGroup = true;
      const createBtn = document.querySelector('#createGroupModal button[onclick="submitCreateGroup()"]');
      if (createBtn) { createBtn.disabled = true; createBtn.textContent = 'Creating...'; }

      fetch('/api/create_group', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, created_by: phone, members: selectedGroupMembers })
      })
      .then(r => r.json())
      .then(data => {
        isCreatingGroup = false;
        if (createBtn) { createBtn.disabled = false; createBtn.textContent = 'Create Group'; }
        if (data.success) {
          closeCreateGroupModal();
          loadContacts(phone); // refresh to show new group
        } else {
          alert(data.error || 'Failed to create group.');
        }
      })
      .catch(() => {
        isCreatingGroup = false;
        if (createBtn) { createBtn.disabled = false; createBtn.textContent = 'Create Group'; }
        alert('Network error. Please try again.');
      });
    }

    document.getElementById('createGroupModal').addEventListener('click', function(e) {
      if (e.target === this) closeCreateGroupModal();
    });
  </script>

  <!-- ═══════════════ PROFILE SYSTEM ═══════════════ -->
  <style>
    .profile-card {
      background: white;
      border-radius: 24px;
      overflow: visible;
      box-shadow: 0 4px 20px rgba(14,73,80,0.10);
      border: 1px solid #daeaea;
      margin-bottom: 16px;
    }
    .profile-banner {
      height: 100px;
      background: linear-gradient(135deg, #0E4950 0%, #2ec4b6 100%);
      border-radius: 24px 24px 0 0;
      position: relative;
    }
    .profile-avatar-wrap {
      display: flex;
      justify-content: center;
      margin-top: -44px;
      position: relative;
      z-index: 2;
      pointer-events: none; /* let touches pass through the wrap itself */
    }
    .profile-avatar-wrap > div {
      pointer-events: auto; /* but re-enable on the actual avatar */
    }
    .profile-avatar {
      width: 88px;
      height: 88px;
      border-radius: 50%;
      border: 4px solid white;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 34px;
      font-weight: 700;
      color: white;
      box-shadow: 0 4px 16px rgba(14,73,80,0.3);
      cursor: pointer;
      transition: transform 0.2s;
      user-select: none;
      position: relative;
    }
    .profile-avatar:active { transform: scale(0.93); }
    .profile-info-block {
      padding: 12px 20px 16px;
      text-align: center;
      background: white;
    }
    .profile-display-name {
      font-size: 22px;
      font-weight: 700;
      color: #1a2e2f;
      margin-bottom: 3px;
    }
    .profile-phone {
      font-size: 13px;
      color: #8aa3a5;
      margin-bottom: 8px;
    }
    .profile-bio {
      font-size: 14px;
      color: #4a6567;
      line-height: 1.5;
      min-height: 20px;
      font-style: italic;
    }
    .profile-section {
      background: white;
      border-radius: 18px;
      padding: 6px 0;
      box-shadow: 0 2px 12px rgba(14,73,80,0.07);
      border: 1px solid #daeaea;
      margin-bottom: 14px;
      overflow: hidden;
      position: relative;
      z-index: 10; /* above avatar-wrap so Edit Profile row receives taps correctly */
    }
    .profile-row {
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 14px 18px;
      cursor: pointer;
      transition: background 0.15s;
      border-bottom: 1px solid #f0f7f7;
    }
    .profile-row:last-child { border-bottom: none; }
    .profile-row:active { background: #f0f7f7; }
    .profile-row-icon {
      width: 38px;
      height: 38px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .profile-row-label {
      flex: 1;
      font-size: 15px;
      font-weight: 600;
      color: #1a2e2f;
    }
    .profile-row-sub {
      font-size: 12px;
      color: #8aa3a5;
      margin-top: 1px;
    }
    .profile-row-chevron {
      color: #ccd8d8;
    }
    /* Edit profile sheet */
    .profile-sheet {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(10,30,30,0.55);
      backdrop-filter: blur(6px);
      z-index: 9500; /* must be above #profileFullOverlay (z-index:9000) */
      align-items: flex-end;
      justify-content: center;
    }
    .profile-sheet-inner {
      background: #fff;
      border-radius: 28px 28px 0 0;
      padding: 28px 22px calc(36px + env(safe-area-inset-bottom,0px));
      width: 100%;
      max-height: 92vh;
      overflow-y: auto;
      animation: slideUpFromBottom 0.32s cubic-bezier(0.25,0.46,0.45,0.94);
    }
    .profile-input {
      width: 100%;
      padding: 12px 15px;
      border: 1.5px solid #d8e8e8;
      border-radius: 12px;
      font-size: 15px;
      font-family: inherit;
      color: #1a2e2f;
      background: #f8fafa;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
      margin-top: 6px;
    }
    .profile-input:focus {
      border-color: #0E4950;
      box-shadow: 0 0 0 3px rgba(14,73,80,0.08);
      background: white;
    }
    .color-swatch {
      width: 34px;
      height: 34px;
      border-radius: 50%;
      border: 3px solid transparent;
      cursor: pointer;
      transition: transform 0.15s, border-color 0.15s;
      flex-shrink: 0;
    }
    .color-swatch.selected {
      border-color: #0E4950;
      transform: scale(1.18);
    }
    .emoji-btn {
      width: 42px;
      height: 42px;
      border-radius: 12px;
      border: 1.5px solid #d8e8e8;
      background: #f8fafa;
      font-size: 22px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: border-color 0.15s, background 0.15s;
    }
    .emoji-btn.selected {
      border-color: #0E4950;
      background: #e8f5f5;
    }
    @keyframes slideUpFromBottom {
      from { transform: translateY(60px); opacity: 0; }
      to   { transform: translateY(0);    opacity: 1; }
    }
  </style>

  <!-- Edit Profile Sheet -->
  <div id="profileEditSheet" class="profile-sheet">
    <div class="profile-sheet-inner">
      <div style="width:36px;height:4px;background:#ccd8d8;border-radius:2px;margin:0 auto 22px;"></div>
      <h3 style="color:#0E4950;font-size:18px;font-weight:700;margin-bottom:20px;">Edit Profile</h3>

      <!-- Avatar colour picker -->
      <div style="margin-bottom:18px;">
        <label style="font-size:13px;font-weight:600;color:#4a6567;">Avatar Colour</label>
        <div id="colorSwatches" style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;"></div>
      </div>

      <!-- Avatar emoji picker -->
      <div style="margin-bottom:18px;">
        <label style="font-size:13px;font-weight:600;color:#4a6567;">Avatar Icon <span style="font-weight:400;color:#9bb5b7;">(optional – overrides initials)</span></label>
        <div id="emojiPicker" style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;"></div>
      </div>

      <!-- Display name -->
      <div style="margin-bottom:16px;">
        <label style="font-size:13px;font-weight:600;color:#4a6567;">Display Name</label>
        <input id="editDisplayName" class="profile-input" type="text" placeholder="Your name" maxlength="40">
      </div>

      <!-- Bio -->
      <div style="margin-bottom:24px;">
        <label style="font-size:13px;font-weight:600;color:#4a6567;">Bio <span style="font-weight:400;color:#9bb5b7;">max 120 chars</span></label>
        <textarea id="editBio" class="profile-input" rows="3" placeholder="Say something about yourself…" maxlength="120" style="resize:none;"></textarea>
      </div>

      <div style="display:flex;gap:10px;">
        <button onclick="closeProfileEdit()" style="flex:1;padding:13px;border:none;border-radius:12px;background:#eef2f2;color:#4a6567;font-weight:600;font-size:14px;cursor:pointer;font-family:inherit;">Cancel</button>
        <button id="saveProfileBtn" onclick="saveProfile()" style="flex:2;padding:13px;border:none;border-radius:12px;background:linear-gradient(135deg,#0E4950,#1a6b75);color:white;font-weight:700;font-size:14px;cursor:pointer;font-family:inherit;">Save</button>
      </div>
    </div>
  </div>

  <!-- ═══════════════ FULL-SCREEN PROFILE OVERLAY ═══════════════ -->
  <style>
    #profileFullOverlay {
      display: none;
      position: fixed;
      inset: 0;
      background: #eef6f6;
      z-index: 9000;
      flex-direction: column;
      overflow: hidden;
      transform: translateX(100%);
      transition: transform 0.32s cubic-bezier(0.25,0.46,0.45,0.94);
    }
    #profileFullOverlay.pfo-visible {
      display: flex;
      transform: translateX(0);
    }
    .pfo-header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 16px calc(14px + env(safe-area-inset-top, 0px));
      padding-top: calc(14px + env(safe-area-inset-top, 0px));
      background: #fff;
      border-bottom: 1px solid #daeaea;
      box-shadow: 0 2px 10px rgba(14,73,80,0.07);
      flex-shrink: 0;
    }
    .pfo-back-btn {
      position: absolute;
      top: 12px; left: 12px;
      width: 38px; height: 38px;
      border-radius: 50%;
      background: rgba(255,255,255,0.25);
      border: none;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer;
      color: #fff;
      flex-shrink: 0;
      transition: background 0.15s;
      z-index: 10;
    }
    .pfo-back-btn:active { background: rgba(255,255,255,0.4); }
    .profile-banner {
      position: relative;
      overflow: visible;
    }
    .pfo-header-title {
      font-size: 18px;
      font-weight: 700;
      color: #0E4950;
      flex: 1;
    }
    #profileOverlayBody {
      flex: 1;
      overflow-y: auto;
      overscroll-behavior: contain;
      -webkit-overflow-scrolling: touch;
      padding: 15px 15px calc(30px + env(safe-area-inset-bottom, 0px));
    }
  </style>

  <div id="profileFullOverlay">

    <div id="profileOverlayBody"></div>
  </div>

  <!-- ═══════════════ PROFILE NETWORK PAGE ═══════════════ -->
  <style>
    #profileNetworkPage, #profilePostsPage {
      display: none;
      position: fixed;
      inset: 0;
      background: #eef6f6;
      z-index: 9100;
      flex-direction: column;
      overflow: hidden;
      transform: translateX(100%);
      transition: transform 0.32s cubic-bezier(0.25,0.46,0.45,0.94);
    }
    #profileNetworkPage.pnp-visible, #profilePostsPage.pnp-visible {
      display: flex;
      transform: translateX(0);
    }
    .pnp-header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding-top: calc(14px + env(safe-area-inset-top, 0px));
      padding-bottom: 14px;
      padding-left: 16px;
      padding-right: 16px;
      background: #fff;
      border-bottom: 1px solid #daeaea;
      box-shadow: 0 2px 10px rgba(14,73,80,0.07);
      flex-shrink: 0;
    }
    .pnp-body {
      flex: 1;
      overflow-y: auto;
      overscroll-behavior: contain;
      -webkit-overflow-scrolling: touch;
      padding: 16px 15px calc(30px + env(safe-area-inset-bottom, 0px));
    }
    .pnp-user-card {
      background: white;
      border-radius: 18px;
      padding: 14px 16px;
      display: flex;
      align-items: center;
      gap: 13px;
      box-shadow: 0 2px 12px rgba(14,73,80,0.07);
      border: 1px solid #daeaea;
      margin-bottom: 10px;
    }
    .pnp-user-avatar {
      width: 50px;
      height: 50px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
      font-weight: 700;
      color: white;
      flex-shrink: 0;
      overflow: hidden;
    }
    .pnp-post-card {
      background: white;
      border-radius: 18px;
      padding: 16px;
      box-shadow: 0 2px 12px rgba(14,73,80,0.07);
      border: 1px solid #daeaea;
      margin-bottom: 12px;
    }
    .pnp-post-img {
      width: 100%;
      border-radius: 12px;
      margin-top: 10px;
      max-height: 300px;
      object-fit: cover;
    }
    .pnp-empty {
      text-align: center;
      padding: 60px 20px;
      color: #9bb5b7;
    }
    .pnp-empty-icon { font-size: 48px; margin-bottom: 12px; }
    .pnp-empty-text { font-size: 15px; font-weight: 600; }
    .pnp-empty-sub { font-size: 13px; margin-top: 4px; opacity: 0.75; }
  </style>

  <div id="profileNetworkPage">
    <div class="pnp-header">
      <button onclick="closeProfileNetworkPage()" style="background:none;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;color:#0E4950;padding:4px;flex-shrink:0;">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      </button>
      <span style="font-size:17px;font-weight:700;color:#0E4950;">My Network</span>
    </div>
    <div class="pnp-body" id="profileNetworkBody">
      <div class="pnp-empty"><div class="pnp-empty-icon">&#128101;</div><div class="pnp-empty-text">Loading...</div></div>
    </div>
  </div>

  <div id="profilePostsPage">
    <div class="pnp-header">
      <button onclick="closeProfilePostsPage()" style="background:none;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;color:#0E4950;padding:4px;flex-shrink:0;">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      </button>
      <span style="font-size:17px;font-weight:700;color:#0E4950;">My Posts</span>
    </div>
    <div class="pnp-body" id="profilePostsBody">
      <div class="pnp-empty"><div class="pnp-empty-icon">&#128221;</div><div class="pnp-empty-text">Loading...</div></div>
    </div>
  </div>

  <script>
    // ── Profile state ──────────────────────────────────────────────
    const AVATAR_COLORS = ['#0E4950','#2ec4b6','#1a6b75','#e76f51','#f4a261','#9b5de5','#f15bb5','#00bbf9','#00f5d4','#3d405b'];
    const AVATAR_EMOJIS = ['','😊','😎','🎯','🔥','💫','🌿','🎵','⚡','🦋','🏆','💡','🌙','🎨','🚀'];
    let _profileData = { phone:'', display_name:'', bio:'', avatar_color:'#0E4950', avatar_emoji:'', avatar_photo:'', banner_photo:'' };
    let _editColor = '#0E4950';
    let _editEmoji = '';

    function loadProfileTab() {
      const phone = localStorage.getItem('exomnia_user_phone');
      const content = document.getElementById('main-content');
      if (!phone) {
        content.innerHTML = `
          <h2 style="color:#0E4950;margin-bottom:15px;">Profile</h2>
          <div class="placeholder-content">
            <p style="color:#666;">Please <a href="/" style="color:#0E4950;font-weight:600;">login</a> to view your profile.</p>
          </div>`;
        return;
      }
      content.innerHTML = `<div style="display:flex;justify-content:center;padding:40px 0;"><div style="width:28px;height:28px;border:3px solid #0E4950;border-top-color:transparent;border-radius:50%;animation:spin 0.7s linear infinite;"></div></div>
        <style>@keyframes spin{to{transform:rotate(360deg)}}</style>`;

      fetch('/api/profile?phone=' + encodeURIComponent(phone))
        .then(r => r.json())
        .then(data => {
          _profileData = data;
          // Also fetch social stats in parallel
          fetch('/api/social/user_stats?phone=' + encodeURIComponent(phone))
            .then(r => r.json())
            .then(stats => renderProfileTab(data, stats))
            .catch(() => renderProfileTab(data, {}));
        })
        .catch(() => {
          content.innerHTML = `<div class="placeholder-content"><p style="color:red;">Failed to load profile.</p></div>`;
        });
    }

    function renderProfileTab(p, stats) {
      stats = stats || {};
      const content = document.getElementById('main-content');
      const initial = (p.display_name || p.phone || '?')[0].toUpperCase();
      const avatarInner = p.avatar_emoji || initial;
      const phone = p.phone;
      const memberSince = p.last_online ? new Date(p.last_online).toLocaleDateString('en-IN', {month:'long', year:'numeric'}) : '—';

      const avatarContent = p.avatar_photo
        ? `<img src="${p.avatar_photo}?t=${Date.now()}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;display:block;" alt="">`
        : `<span style="font-size:34px;font-weight:700;color:white;line-height:1;">${avatarInner}</span>`;
      const bgColor = p.avatar_color || '#0E4950';

      const connections = (stats.followers || 0) + (stats.following || 0);
      const postsCount = stats.posts || 0;

      content.innerHTML = `
        <div class="profile-card">
          <div class="profile-banner" style="${p.banner_photo ? `background-image:url('${p.banner_photo}?t=${Date.now()}');background-size:cover;background-position:center;` : ''}">
            <button onclick="triggerBannerPhotoInput()" title="Change banner" style="position:absolute;bottom:10px;right:12px;background:rgba(0,0,0,0.42);border:1.5px solid rgba(255,255,255,0.6);color:#fff;border-radius:20px;padding:5px 11px;display:flex;align-items:center;gap:5px;font-size:12px;font-weight:600;font-family:inherit;cursor:pointer;backdrop-filter:blur(4px);z-index:3;">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="3"/></svg>
              Edit cover
            </button>
          </div>
          <input type="file" id="bannerPhotoInput" accept="image/*" style="display:none" onchange="uploadBannerPhoto(this)">
          <div class="profile-avatar-wrap">
            <div style="position:relative;display:inline-block;">
              <div class="profile-avatar" style="background:${p.avatar_photo ? 'transparent' : bgColor};overflow:hidden;" onclick="triggerAvatarPhotoInput()" title="Change photo">
                ${avatarContent}
              </div>
              <button onclick="triggerAvatarPhotoInput()" title="Change photo" style="position:absolute;bottom:2px;right:2px;width:26px;height:26px;border-radius:50%;background:#0E4950;border:2.5px solid white;display:flex;align-items:center;justify-content:center;cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,0.25);z-index:3;">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="3"/></svg>
              </button>
            </div>
          </div>
          <input type="file" id="avatarPhotoInput" accept="image/*" style="display:none" onchange="uploadAvatarPhoto(this)">
          <div class="profile-info-block">
            <div class="profile-display-name">${p.display_name || 'Exomnia User'}</div>
            <div class="profile-bio">${p.bio ? escapeHtml(p.bio) : '<span style="color:#bbb;font-style:italic;">No bio yet</span>'}</div>
          </div>
          <div style="display:flex;border-top:1px solid #f0f0f0;margin-top:14px;border-radius:0 0 24px 24px;overflow:hidden;">
            <div style="flex:1;text-align:center;padding:14px 8px;border-right:1px solid #f0f0f0;">
              <div style="font-size:20px;font-weight:800;color:#0E4950;">${connections}</div>
              <div style="font-size:11px;color:#888;font-weight:500;margin-top:2px;">Network</div>
            </div>
            <div style="flex:1;text-align:center;padding:14px 8px;">
              <div style="font-size:20px;font-weight:800;color:#0E4950;">${postsCount}</div>
              <div style="font-size:11px;color:#888;font-weight:500;margin-top:2px;">Posts</div>
            </div>
          </div>
        </div>

        <div class="profile-section">
          <div class="profile-row" onclick="openProfileEdit()">
            <div class="profile-row-icon" style="background:#e8f5f5;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0E4950" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            </div>
            <div>
              <div class="profile-row-label">Edit Profile</div>
              <div class="profile-row-sub">Name, bio, avatar</div>
            </div>
            <div class="profile-row-chevron"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg></div>
          </div>
          <div class="profile-row" onclick="copyPhone()">
            <div class="profile-row-icon" style="background:#fff3e0;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e76f51" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 12a19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 3.6 1.18h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.73a16 16 0 0 0 6.29 6.29l1.62-1.62a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
            </div>
            <div>
              <div class="profile-row-label">Phone Number</div>
              <div class="profile-row-sub">${phone} · tap to copy</div>
            </div>
          </div>
        </div>

        <div class="profile-section">
          <div class="profile-row">
            <div class="profile-row-icon" style="background:#e8f0ff;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#5c6bc0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </div>
            <div>
              <div class="profile-row-label">End-to-End Encrypted</div>
              <div class="profile-row-sub">All messages are secured</div>
            </div>
          </div>
          <div class="profile-row">
            <div class="profile-row-icon" style="background:#fce4ec;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e91e63" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            </div>
            <div>
              <div class="profile-row-label">Member Since</div>
              <div class="profile-row-sub">${memberSince}</div>
            </div>
          </div>
        </div>

        <div class="profile-section">
          <div class="profile-row" onclick="confirmLogout()" style="color:#e53935;">
            <div class="profile-row-icon" style="background:#fdecea;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e53935" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            </div>
            <div class="profile-row-label" style="color:#e53935;">Log Out</div>
          </div>
        </div>
      `;
    }

    function escapeHtml(str) {
      return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    function copyPhone() {
      const phone = localStorage.getItem('exomnia_user_phone');
      if (!phone) return;
      navigator.clipboard.writeText(phone).then(() => {
        showToast('Phone number copied!');
      }).catch(() => {
        showToast(phone);
      });
    }

    function confirmLogout() {
      if (confirm('Are you sure you want to log out?')) {
        localStorage.removeItem('exomnia_user_phone');
        window.location.href = '/';
      }
    }

    // ── Profile Edit Sheet ──────────────────────────────────────────
    function openProfileEdit() {
      const p = _profileData;
      _editColor = p.avatar_color || '#0E4950';
      _editEmoji = p.avatar_emoji || '';

      document.getElementById('editDisplayName').value = p.display_name || '';
      document.getElementById('editBio').value = p.bio || '';

      // Build colour swatches
      const swatchContainer = document.getElementById('colorSwatches');
      swatchContainer.innerHTML = '';
      AVATAR_COLORS.forEach(color => {
        const s = document.createElement('div');
        s.className = 'color-swatch' + (color === _editColor ? ' selected' : '');
        s.style.background = color;
        s.title = color;
        s.onclick = () => {
          _editColor = color;
          swatchContainer.querySelectorAll('.color-swatch').forEach(x => x.classList.remove('selected'));
          s.classList.add('selected');
        };
        swatchContainer.appendChild(s);
      });

      // Build emoji buttons
      const emojiContainer = document.getElementById('emojiPicker');
      emojiContainer.innerHTML = '';
      AVATAR_EMOJIS.forEach(em => {
        const b = document.createElement('div');
        b.className = 'emoji-btn' + (em === _editEmoji ? ' selected' : '');
        b.textContent = em || '—';
        b.title = em ? em : 'Use initials';
        b.onclick = () => {
          _editEmoji = em;
          emojiContainer.querySelectorAll('.emoji-btn').forEach(x => x.classList.remove('selected'));
          b.classList.add('selected');
        };
        emojiContainer.appendChild(b);
      });

      document.getElementById('profileEditSheet').style.display = 'flex';
    }

    function closeProfileEdit() {
      document.getElementById('profileEditSheet').style.display = 'none';
    }

    function triggerAvatarPhotoInput() {
      const inp = document.getElementById('avatarPhotoInput');
      if (inp) inp.click();
    }

    function triggerBannerPhotoInput() {
      const inp = document.getElementById('bannerPhotoInput');
      if (inp) inp.click();
    }

    function uploadBannerPhoto(input) {
      const file = input.files[0];
      if (!file) return;
      const phone = localStorage.getItem('exomnia_user_phone');
      if (!phone) return;
      const fd = new FormData();
      fd.append('phone', phone);
      fd.append('photo', file);
      showToast('Uploading cover…');
      fetch('/api/profile/upload_banner', { method: 'POST', body: fd })
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            showToast('Cover updated ✓');
            _profileData = { ..._profileData, banner_photo: data.banner_url };
            renderProfileOverlay(_profileData);
          } else {
            showToast(data.error || 'Upload failed');
          }
        })
        .catch(() => showToast('Network error'));
      input.value = '';
    }

    function uploadAvatarPhoto(input) {
      const file = input.files[0];
      if (!file) return;
      const phone = localStorage.getItem('exomnia_user_phone');
      if (!phone) return;
      const fd = new FormData();
      fd.append('phone', phone);
      fd.append('photo', file);
      showToast('Uploading…');
      fetch('/api/profile/upload_photo', { method: 'POST', body: fd })
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            showToast('Photo updated ✓');
            _profileData = { ..._profileData, avatar_photo: data.photo_url };
            renderProfileOverlay(_profileData);
            updateHeaderProfileAvatar();
          } else {
            showToast(data.error || 'Upload failed');
          }
        })
        .catch(() => showToast('Network error'));
      // Reset so same file can be re-selected
      input.value = '';
    }

    function saveProfile() {
      const phone = localStorage.getItem('exomnia_user_phone');
      const btn = document.getElementById('saveProfileBtn');
      const display_name = document.getElementById('editDisplayName').value.trim();
      const bio = document.getElementById('editBio').value.trim();

      btn.disabled = true; btn.textContent = 'Saving…';

      fetch('/api/profile/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone, display_name, bio, avatar_color: _editColor, avatar_emoji: _editEmoji })
      })
      .then(r => r.json())
      .then(data => {
        btn.disabled = false; btn.textContent = 'Save';
        if (data.success) {
          closeProfileEdit();
          showToast('Profile updated ✓');
          _profileData = { ..._profileData, display_name, bio, avatar_color: _editColor, avatar_emoji: _editEmoji };
          renderProfileOverlay(_profileData);
          updateHeaderProfileAvatar();
        } else {
          showToast(data.error || 'Failed to save');
        }
      })
      .catch(() => {
        btn.disabled = false; btn.textContent = 'Save';
        showToast('Network error');
      });
    }

    document.getElementById('profileEditSheet').addEventListener('click', function(e) {
      if (e.target === this) closeProfileEdit();
    });

    // ── Toast helper ──────────────────────────────────────────────
    function showToast(msg) {
      let t = document.getElementById('_toast');
      if (!t) {
        t = document.createElement('div');
        t.id = '_toast';
        t.style.cssText = 'position:fixed;bottom:calc(90px + env(safe-area-inset-bottom,0px));left:50%;transform:translateX(-50%);background:#1a2e2f;color:white;padding:10px 20px;border-radius:20px;font-size:13px;font-weight:600;z-index:9999;opacity:0;transition:opacity 0.25s;white-space:nowrap;pointer-events:none;';
        document.body.appendChild(t);
      }
      t.textContent = msg;
      t.style.opacity = '1';
      clearTimeout(t._timer);
      t._timer = setTimeout(() => { t.style.opacity = '0'; }, 2500);
    }

    // ═══════════════════════════════════════════════════════════════
    //  SOCIAL NETWORK MODULE
    // ═══════════════════════════════════════════════════════════════
    let _socialView = 'feed'; // 'feed' | 'network' | 'requests'
    let _socialPosts = [];
    let _socialConnections = {}; // phone -> status
    let _socialPendingIn = []; // incoming connection requests

    // ── Helpers ───────────────────────────────────────────────────
    function _socialPhone() { return localStorage.getItem('exomnia_user_phone') || ''; }

    function _socialAvatar(p, size) {
      size = size || 42;
      if (p.avatar_photo) {
        return `<div class="social-avatar" style="width:${size}px;height:${size}px;background:transparent;overflow:hidden;">
          <img src="${p.avatar_photo}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;" alt="">
        </div>`;
      }
      const initial = (p.display_name || p.phone || '?')[0].toUpperCase();
      const inner = p.avatar_emoji || initial;
      const color = p.avatar_color || '#0E4950';
      return `<div class="social-avatar" style="width:${size}px;height:${size}px;background:${color};">${inner}</div>`;
    }

    function _socialTimeAgo(ts) {
      if (!ts) return '';
      const diff = (Date.now() - new Date(ts).getTime()) / 1000;
      if (diff < 60) return 'just now';
      if (diff < 3600) return Math.floor(diff/60) + 'm';
      if (diff < 86400) return Math.floor(diff/3600) + 'h';
      if (diff < 604800) return Math.floor(diff/86400) + 'd';
      return new Date(ts).toLocaleDateString(undefined, {month:'short', day:'numeric'});
    }

    // ── Main entry ────────────────────────────────────────────────
    function loadSocialTab() {
      const phone = _socialPhone();
      const content = document.getElementById('main-content');
      if (!phone) {
        content.innerHTML = `
          <h2 style="color:#0E4950;margin-bottom:15px;">Social</h2>
          <div class="placeholder-content">
            <p>Please <a href="/" style="color:#0E4950;font-weight:600;">login</a> to access Social.</p>
          </div>`;
        return;
      }
      content.innerHTML = `
        <div class="social-header">
          <div style="display:flex;align-items:center;gap:8px;width:100%;">
            <div style="display:flex;align-items:center;background:#fff;border:1.5px solid #daeaea;border-radius:12px;padding:7px 12px;gap:8px;flex:1;box-shadow:0 1px 6px rgba(14,73,80,0.07);">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#7aabae" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              <input id="socialSearchInput" type="text" placeholder="Search people or posts…" oninput="handleSocialSearch(this.value)" style="border:none;outline:none;font-size:14px;color:#0E4950;background:transparent;width:100%;font-family:inherit;" autocomplete="off">
            </div>
            <button onclick="focusCreatePost()" style="flex-shrink:0;background:#0E4950;color:#fff;border:none;border-radius:12px;padding:8px 15px;font-size:13px;font-weight:600;font-family:inherit;cursor:pointer;box-shadow:0 2px 8px rgba(14,73,80,0.25);display:flex;align-items:center;gap:5px;white-space:nowrap;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
              Post
            </button>
          </div>
        </div>

        <div class="social-tabs">
          <button class="social-tab-btn active" id="stbFeed" onclick="switchSocialView('feed',this)">Feed</button>
          <button class="social-tab-btn" id="stbNetwork" onclick="switchSocialView('network',this)">Network</button>
          <button class="social-tab-btn" id="stbRequests" onclick="switchSocialView('requests',this)">Requests <span id="reqBadge"></span></button>
        </div>

        <div id="socialContent"></div>

        <!-- Post creation bottom sheet modal -->
        <div id="postCreateModal" onclick="if(event.target===this)closePostModal()">
          <div class="post-modal-sheet">
            <div class="post-modal-handle"></div>
            <div class="post-modal-header">
              <span class="post-modal-title">New Post</span>
              <button class="post-modal-close" onclick="closePostModal()">✕</button>
            </div>
            <div class="create-post-row" style="margin-bottom:10px;flex:1;align-items:flex-start;">
              <div id="cpAvatarModal" style="width:40px;height:40px;border-radius:50%;background:#0E4950;display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:15px;flex-shrink:0;"></div>
              <textarea id="newPostText" class="create-post-textarea" placeholder="Share something with your network…" rows="4" maxlength="1000" style="flex:1;min-height:220px;"></textarea>
            </div>
            <div id="postPhotoPreview" style="display:none;margin-bottom:10px;position:relative;">
              <img id="postPhotoImg" style="width:100%;max-height:200px;object-fit:cover;border-radius:10px;display:block;" alt="">
              <button onclick="clearPostPhoto()" style="position:absolute;top:6px;right:6px;width:26px;height:26px;border-radius:50%;background:rgba(0,0,0,0.55);border:none;color:white;cursor:pointer;display:flex;align-items:center;justify-content:center;">✕</button>
            </div>
            <div class="create-post-actions">
              <label class="photo-attach-btn" for="postPhotoInput">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                Photo
              </label>
              <input type="file" id="postPhotoInput" accept="image/*" style="display:none" onchange="onPostPhotoSelected(this)">
              <button class="post-submit-btn" onclick="submitPost()">Post</button>
            </div>
          </div>
        </div>

        <!-- Share Post bottom sheet -->
        <div id="sharePostModal" onclick="if(event.target===this)closeShareSheet()" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);backdrop-filter:blur(4px);z-index:2000;align-items:flex-end;justify-content:center;">
          <div id="sharePostSheet" style="background:#fff;border-radius:22px 22px 0 0;width:100%;max-width:540px;padding:0 0 env(safe-area-inset-bottom,0px);box-shadow:0 -8px 40px rgba(14,73,80,0.18);animation:shareSlideUp 0.28s cubic-bezier(.4,0,.2,1);">
            <div style="width:36px;height:4px;border-radius:3px;background:#ddd;margin:10px auto 0;"></div>
            <div style="padding:16px 20px 4px;display:flex;align-items:center;justify-content:space-between;">
              <span style="font-size:17px;font-weight:700;color:#0E4950;">Share Post</span>
              <button onclick="closeShareSheet()" style="background:none;border:none;font-size:20px;color:#aaa;cursor:pointer;line-height:1;">&#x2715;</button>
            </div>
            <div id="sharePostPreview" style="margin:10px 20px 14px;background:#f6fafa;border:1px solid #daeaea;border-radius:14px;padding:12px 14px;font-size:14px;color:#1a2e2f;line-height:1.5;max-height:80px;overflow:hidden;"></div>
            <div style="padding:0 16px 18px;display:flex;flex-direction:column;gap:8px;">
              <button id="shareNativeBtn" onclick="shareViaNativeAPI()" style="display:none;align-items:center;gap:14px;padding:14px 16px;border-radius:14px;border:1.5px solid #daeaea;background:#fff;cursor:pointer;font-family:inherit;font-size:15px;font-weight:600;color:#0E4950;text-align:left;width:100%;">
                <span style="width:38px;height:38px;border-radius:50%;background:#e8f5f5;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;margin-right:0;">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0E4950" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
                </span>
                Share via&#x2026;
              </button>
              <button onclick="shareCopyLink()" style="display:flex;align-items:center;gap:14px;padding:14px 16px;border-radius:14px;border:1.5px solid #daeaea;background:#fff;cursor:pointer;font-family:inherit;font-size:15px;font-weight:600;color:#0E4950;text-align:left;width:100%;">
                <span style="width:38px;height:38px;border-radius:50%;background:#fff3e0;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e76f51" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                </span>
                Copy Link
              </button>
              <button onclick="shareCopyText()" style="display:flex;align-items:center;gap:14px;padding:14px 16px;border-radius:14px;border:1.5px solid #daeaea;background:#fff;cursor:pointer;font-family:inherit;font-size:15px;font-weight:600;color:#0E4950;text-align:left;width:100%;">
                <span style="width:38px;height:38px;border-radius:50%;background:#e8f0ff;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#5c6bc0" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                </span>
                Copy Post Text
              </button>
              <button onclick="openForwardToContact()" style="display:flex;align-items:center;gap:14px;padding:14px 16px;border-radius:14px;border:1.5px solid #daeaea;background:#fff;cursor:pointer;font-family:inherit;font-size:15px;font-weight:600;color:#0E4950;text-align:left;width:100%;">
                <span style="width:38px;height:38px;border-radius:50%;background:#fce4ec;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#e91e63" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                </span>
                Send to Contact
              </button>
            </div>
            <div id="forwardContactPanel" style="display:none;padding:0 16px 18px;">
              <div style="font-size:13px;font-weight:600;color:#888;margin-bottom:10px;letter-spacing:0.4px;">CHOOSE A CONTACT</div>
              <div style="background:#f6fafa;border:1.5px solid #daeaea;border-radius:12px;padding:8px 12px;display:flex;align-items:center;gap:8px;margin-bottom:10px;">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#7aabae" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <input id="forwardSearchInput" type="text" placeholder="Search contacts&#x2026;" oninput="filterForwardContacts(this.value)" style="border:none;outline:none;font-size:14px;background:transparent;color:#0E4950;width:100%;font-family:inherit;">
              </div>
              <div id="forwardContactList" style="max-height:200px;overflow-y:auto;display:flex;flex-direction:column;gap:6px;"></div>
            </div>
          </div>
        </div>
        <style>@keyframes shareSlideUp{from{transform:translateY(100%)}to{transform:translateY(0)}}</style>
      `;
      _socialView = 'feed';
      loadSocialFeed();
      loadSocialConnectionStatus();
      loadConnectionRequests(true); // silent — just update badge
    }

    function switchSocialView(view, btn) {
      _socialView = view;
      document.querySelectorAll('.social-tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      if (view === 'feed') loadSocialFeed();
      else if (view === 'network') loadNetworkView();
      else if (view === 'requests') loadConnectionRequests(false);
    }

    // ── QUICK POST BUTTON ─────────────────────────────────────────
    function focusCreatePost() {
      openPostModal();
    }

    function openPostModal() {
      // Switch to feed view first if needed
      if (_socialView !== 'feed') {
        const feedBtn = document.getElementById('stbFeed');
        if (feedBtn) switchSocialView('feed', feedBtn);
      }
      const modal = document.getElementById('postCreateModal');
      if (!modal) return;
      modal.classList.add('open');
      // Fetch real user profile for avatar
      const phone = _socialPhone();
      if (phone) {
        fetch('/api/profile?phone=' + encodeURIComponent(phone))
          .then(r => r.json())
          .then(p => {
            const el = document.getElementById('cpAvatarModal');
            if (!el) return;
            if (p.avatar_photo) {
              el.style.cssText = 'width:40px;height:40px;border-radius:50%;overflow:hidden;flex-shrink:0;';
              el.innerHTML = `<img src="${p.avatar_photo}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;" alt="">`;
            } else {
              const initial = (p.display_name || phone || '?')[0].toUpperCase();
              const inner = p.avatar_emoji || initial;
              const color = p.avatar_color || '#0E4950';
              el.style.cssText = `width:40px;height:40px;border-radius:50%;background:${color};display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:15px;flex-shrink:0;`;
              el.innerHTML = inner;
            }
          }).catch(() => {});
      }
      // Make textarea fill available space
      const ta = document.getElementById('newPostText');
      if (ta) { ta.style.flex = '1'; ta.style.minHeight = '200px'; ta.focus(); }
    }

    function closePostModal() {
      const modal = document.getElementById('postCreateModal');
      if (modal) modal.classList.remove('open');
    }

    // ── SEARCH ───────────────────────────────────────────────────
    function handleSocialSearch(query) {
      const q = query.trim();
      const sc = document.getElementById('socialContent');
      if (!q) {
        switchSocialView(_socialView, document.querySelector('.social-tab-btn.active') || document.getElementById('stbFeed'));
        return;
      }
      // Show loading spinner
      if (sc) sc.innerHTML = `<div style="display:flex;justify-content:center;padding:30px 0;"><div style="width:24px;height:24px;border:3px solid #0E4950;border-top-color:transparent;border-radius:50%;animation:spin 0.7s linear infinite;"></div></div>`;

      const myPhone = _socialPhone();
      fetch('/api/social/search?phone=' + encodeURIComponent(myPhone) + '&q=' + encodeURIComponent(q))
        .then(r => r.json())
        .then(data => {
          const people = data.people || [];
          const matchedPosts = (_socialPosts || []).filter(p =>
            (p.content && p.content.toLowerCase().includes(q.toLowerCase())) ||
            (p.display_name && p.display_name.toLowerCase().includes(q.toLowerCase()))
          );

          let html = '';

          if (people.length > 0) {
            html += `<div style="font-weight:700;color:#0E4950;margin-bottom:10px;font-size:13px;letter-spacing:0.4px;">PEOPLE</div>`;
            people.forEach(p => {
              const status = p.connection_status; // 'connected','pending','none'
              const av = p.avatar_photo
                ? `<img src="/api/social/avatar/${p.avatar_photo}" style="width:44px;height:44px;border-radius:50%;object-fit:cover;flex-shrink:0;">`
                : `<div style="width:44px;height:44px;border-radius:50%;background:${p.avatar_color||'#0E4950'};display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:17px;flex-shrink:0;">${(p.display_name||p.phone||'?')[0].toUpperCase()}</div>`;

              let btnHtml = '';
              if (status === 'connected') {
                btnHtml = `<button onclick="disconnectUser('${p.phone}',this)" style="padding:7px 14px;border-radius:10px;font-size:12px;font-weight:700;font-family:inherit;cursor:pointer;border:none;background:#0E4950;color:white;white-space:nowrap;">✓ Connected</button>`;
              } else if (status === 'pending') {
                btnHtml = `<button disabled style="padding:7px 14px;border-radius:10px;font-size:12px;font-weight:700;font-family:inherit;border:none;background:#e0f0f0;color:#7aabae;white-space:nowrap;">Requested</button>`;
              } else if (status === 'me') {
                btnHtml = '';
              } else {
                btnHtml = `<button onclick="sendConnectionRequest('${p.phone}',this)" style="padding:7px 14px;border-radius:10px;font-size:12px;font-weight:700;font-family:inherit;cursor:pointer;border:none;background:linear-gradient(135deg,#0E4950,#1a6b75);color:white;white-space:nowrap;box-shadow:0 3px 10px rgba(14,73,80,0.25);">+ Connect</button>`;
              }

              html += `<div style="display:flex;align-items:center;gap:12px;background:#fff;border-radius:16px;padding:12px 14px;margin-bottom:8px;border:1px solid #daeaea;box-shadow:0 2px 8px rgba(14,73,80,0.05);">
                <div onclick="openSocialProfile('${p.phone}')" style="cursor:pointer;flex-shrink:0;">${av}</div>
                <div onclick="openSocialProfile('${p.phone}')" style="flex:1;min-width:0;cursor:pointer;">
                  <div style="font-weight:700;color:#1a2e2f;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(p.display_name && p.display_name.trim() ? p.display_name : 'NEOX User')}</div>
                  ${p.headline ? `<div style="font-size:12px;color:#0E4950;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(p.headline)}</div>` : ''}
                  <div style="font-size:11px;color:#aac4c5;margin-top:2px;"></div>
                </div>
                ${btnHtml ? `<div style="flex-shrink:0;">${btnHtml}</div>` : ''}
              </div>`;
            });
          }

          if (matchedPosts.length > 0) {
            html += `<div style="font-weight:700;color:#0E4950;margin:14px 0 10px;font-size:13px;letter-spacing:0.4px;">POSTS</div>`;
            matchedPosts.forEach(p => {
              html += `<div style="background:#fff;border-radius:14px;padding:12px 14px;margin-bottom:10px;border:1px solid #daeaea;cursor:pointer;" onclick="openSocialProfile('${p.author_phone}')">
                <div style="font-weight:700;color:#0E4950;margin-bottom:4px;">${escapeHtml(p.display_name && p.display_name.trim() ? p.display_name : 'NEOX User')}</div>
                <div style="font-size:14px;color:#333;line-height:1.4;">${escapeHtml(p.content)}</div>
              </div>`;
            });
          }

          if (!html) html = `<div class="placeholder-content"><div style="font-size:36px;margin-bottom:8px;">🔍</div><p style="color:#7aabae;">No results for "<b>${escapeHtml(q)}</b>"</p></div>`;
          if (sc) sc.innerHTML = html;
        })
        .catch(() => {
          if (sc) sc.innerHTML = `<div class="placeholder-content"><p style="color:#7aabae;">Search failed. Try again.</p></div>`;
        });
    }

    // ── FEED ─────────────────────────────────────────────────────
    function loadSocialFeed() {
      const sc = document.getElementById('socialContent');
      if (!sc) return;
      sc.innerHTML = `<div style="display:flex;justify-content:center;padding:30px 0;"><div style="width:24px;height:24px;border:3px solid #0E4950;border-top-color:transparent;border-radius:50%;animation:spin 0.7s linear infinite;"></div></div>
        <style>@keyframes spin{to{transform:rotate(360deg)}}</style>`;

      fetch('/api/social/feed?phone=' + encodeURIComponent(_socialPhone()))
        .then(r => r.json())
        .then(posts => {
          _socialPosts = posts;
          renderFeed(posts);
        })
        .catch(() => {
          if (sc) sc.innerHTML = `<div class="placeholder-content"><p style="color:red;">Failed to load feed.</p></div>`;
        });
    }

    function renderFeed(posts) {
      const sc = document.getElementById('socialContent');
      if (!sc) return;
      const myPhone = _socialPhone();
      let html = '';

      if (!posts || posts.length === 0) {
        html += `<div class="placeholder-content" style="margin-top:0;">
          <div style="font-size:36px;margin-bottom:8px;">👥</div>
          <h3 style="font-size:16px;color:#333;margin-bottom:6px;">Your feed is empty</h3>
          <p style="font-size:13px;color:#888;">Connect with people to see their posts, or share your own update above.</p>
        </div>`;
      } else {
        posts.forEach(p => { html += renderPostCard(p, myPhone); });
      }
      sc.innerHTML = html;
    }

    let _postPhotoFile = null;

    function onPostPhotoSelected(input) {
      const file = input.files[0];
      if (!file) return;
      _postPhotoFile = file;
      const reader = new FileReader();
      reader.onload = e => {
        document.getElementById('postPhotoPreview').style.display = 'block';
        document.getElementById('postPhotoImg').src = e.target.result;
      };
      reader.readAsDataURL(file);
    }

    function clearPostPhoto() {
      _postPhotoFile = null;
      document.getElementById('postPhotoPreview').style.display = 'none';
      document.getElementById('postPhotoImg').src = '';
      document.getElementById('postPhotoInput').value = '';
    }

    function submitPost() {
      const text = (document.getElementById('newPostText') || {}).value || '';
      if (!text.trim() && !_postPhotoFile) { showToast('Write something first!'); return; }
      const myPhone = _socialPhone();
      const btn = document.querySelector('#postCreateModal .post-submit-btn');
      if (btn) { btn.disabled = true; btn.textContent = 'Posting…'; }

      const fd = new FormData();
      fd.append('phone', myPhone);
      fd.append('content', text.trim());
      if (_postPhotoFile) fd.append('image', _postPhotoFile);

      fetch('/api/social/post', { method: 'POST', body: fd })
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            showToast('Post shared! ✓');
            _postPhotoFile = null;
            if (btn) { btn.disabled = false; btn.textContent = 'Post'; }
            const ta = document.getElementById('newPostText');
            if (ta) ta.value = '';
            clearPostPhoto();
            closePostModal();
            loadSocialFeed();
          } else {
            showToast(data.error || 'Failed to post');
            if (btn) { btn.disabled = false; btn.textContent = 'Post'; }
          }
        })
        .catch(() => {
          showToast('Network error');
          if (btn) { btn.disabled = false; btn.textContent = 'Post'; }
        });
    }

    function renderPostCard(p, myPhone) {
      const avatarHtml = _socialAvatar(p, 42);
      const name = p.display_name && p.display_name.trim() ? p.display_name : 'NEOX User';
      const headline = p.headline || '';
      const timeAgo = _socialTimeAgo(p.timestamp);
      const liked = (p.liked_by || []).includes(myPhone);
      const likeCount = p.likes || 0;
      const commentCount = p.comment_count || 0;

      const imageHtml = p.image_path
        ? `<img class="social-post-image" src="/api/social/image/${p.image_path}" onclick="openSocialImg(this.src)" alt="">`
        : '';

      return `
        <div class="social-post-card" id="post_${p.id}">
          <div class="social-post-header">
            ${avatarHtml}
            <div class="social-post-meta" onclick="openSocialProfile('${p.author_phone}')" style="cursor:pointer;">
              <div class="social-post-name">${escapeHtml(name)}</div>
              ${headline ? `<div class="social-post-headline">${escapeHtml(headline)}</div>` : ''}
            </div>
            <span class="social-post-time">${timeAgo}</span>
          </div>
          ${p.content ? `<div class="social-post-content">${escapeHtml(p.content)}</div>` : ''}
          ${imageHtml}
          <div class="social-post-actions">
            <button class="social-action-btn ${liked ? 'liked' : ''}" onclick="toggleLike(${p.id},this)">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="${liked ? 'rgba(231,111,81,0.2)' : 'none'}" stroke="${liked ? '#e76f51' : 'currentColor'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
              <span id="likeCount_${p.id}">${likeCount}</span>
            </button>
            <button class="social-action-btn" onclick="toggleComments(${p.id})">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
              <span id="commentCount_${p.id}">${commentCount}</span>
            </button>
            <button class="social-action-btn" onclick="openShareSheet(${p.id})" title="Share post">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
            </button>
            ${p.author_phone === myPhone ? `
            <button class="social-action-btn" onclick="deletePost(${p.id})" style="margin-left:auto;color:#e53935;">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#e53935" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
            </button>` : ''}
          </div>
          <div id="comments_${p.id}" style="display:none;"></div>
        </div>`;
    }

    function toggleLike(postId, btn) {
      const myPhone = _socialPhone();
      const countEl = document.getElementById('likeCount_' + postId);
      const liked = btn.classList.contains('liked');
      btn.classList.toggle('liked');
      const svg = btn.querySelector('svg');
      if (!liked) {
        svg.setAttribute('fill', 'rgba(231,111,81,0.2)');
        svg.setAttribute('stroke', '#e76f51');
        if (countEl) countEl.textContent = parseInt(countEl.textContent || 0) + 1;
      } else {
        svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor');
        if (countEl) countEl.textContent = Math.max(0, parseInt(countEl.textContent || 1) - 1);
      }
      fetch('/api/social/like', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ post_id: postId, phone: myPhone })
      }).catch(() => {});
    }

    function toggleComments(postId) {
      const div = document.getElementById('comments_' + postId);
      if (!div) return;
      if (div.style.display !== 'none' && div.dataset.loaded) {
        div.style.display = 'none';
        return;
      }
      div.style.display = 'block';
      div.dataset.loaded = '1';
      loadComments(postId);
    }

    function loadComments(postId) {
      const div = document.getElementById('comments_' + postId);
      if (!div) return;
      div.innerHTML = `<div class="social-comments-section"><div style="text-align:center;padding:10px;"><div style="width:18px;height:18px;border:2px solid #0E4950;border-top-color:transparent;border-radius:50%;animation:spin 0.7s linear infinite;display:inline-block;"></div></div></div>`;
      fetch('/api/social/comments?post_id=' + postId)
        .then(r => r.json())
        .then(comments => {
          renderComments(postId, comments);
        })
        .catch(() => {
          div.innerHTML = '';
        });
    }

    function _relTime(ts) {
      if (!ts) return '';
      const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
      if (diff < 60)   return 'just now';
      if (diff < 3600) return Math.floor(diff/60) + 'm ago';
      if (diff < 86400)return Math.floor(diff/3600) + 'h ago';
      return Math.floor(diff/86400) + 'd ago';
    }

    function renderComments(postId, comments) {
      const div = document.getElementById('comments_' + postId);
      if (!div) return;
      let html = '<div class="social-comments-section">';
      if (comments.length > 0) {
        html += `<div class="comments-header">${comments.length} Comment${comments.length !== 1 ? 's' : ''}</div>`;
        comments.forEach((c, i) => {
          const name = c.display_name && c.display_name.trim() ? c.display_name : 'NEOX User';
          const avatarHtml = _socialAvatar(c, 32);
          const timeStr = _relTime(c.created_at || c.timestamp);
          html += `<div class="social-comment-item" style="animation-delay:${i*0.04}s">
            ${avatarHtml}
            <div class="social-comment-bubble">
              <div class="scb-inner">
                <div class="social-comment-author">${escapeHtml(name)}</div>
                <div class="social-comment-text">${escapeHtml(c.content)}</div>
              </div>
              <div class="social-comment-meta">
                ${timeStr ? `<span class="social-comment-time">${timeStr}</span>` : ''}
              </div>
            </div>
          </div>`;
        });
      } else {
        html += '<div class="no-comments">No comments yet — be the first!</div>';
      }
      html += `<div class="social-comment-input-row">
        <div class="comment-input-shell">
          <input type="text" class="social-comment-input" id="commentInput_${postId}"
            placeholder="Add a comment…" maxlength="500"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendComment(${postId});}
                       document.getElementById('sendBtn_${postId}').disabled=!this.value.trim();">
        </div>
        <button class="social-comment-send" id="sendBtn_${postId}" disabled onclick="sendComment(${postId})" title="Post comment">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="22" y1="2" x2="11" y2="13"/>
            <polygon points="22 2 15 22 11 13 2 9 22 2"/>
          </svg>
        </button>
      </div></div>`;
      div.innerHTML = html;
      // Re-attach live enable/disable after innerHTML set
      const inp = document.getElementById('commentInput_' + postId);
      const btn = document.getElementById('sendBtn_' + postId);
      if (inp && btn) {
        inp.addEventListener('input', () => { btn.disabled = !inp.value.trim(); });
      }
    }

    function sendComment(postId) {
      const input = document.getElementById('commentInput_' + postId);
      const btn   = document.getElementById('sendBtn_' + postId);
      if (!input || !input.value.trim()) return;
      const myPhone = _socialPhone();
      const text = input.value.trim();
      input.value = '';
      if (btn) btn.disabled = true;
      // Optimistic count bump
      const cc = document.getElementById('commentCount_' + postId);
      if (cc) cc.textContent = parseInt(cc.textContent || 0) + 1;
      fetch('/api/social/comment', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ post_id: postId, phone: myPhone, content: text })
      }).then(r => r.json()).then(() => {
        loadComments(postId);
      }).catch(() => {
        // Roll back count on failure
        if (cc) cc.textContent = Math.max(0, parseInt(cc.textContent || 1) - 1);
        if (btn) btn.disabled = false;
        input.value = text;
      });
    }

    function deletePost(postId) {
      if (!confirm('Delete this post?')) return;
      fetch('/api/social/post/delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ post_id: postId, phone: _socialPhone() })
      }).then(r => r.json()).then(data => {
        if (data.success) {
          const el = document.getElementById('post_' + postId);
          if (el) { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }
          showToast('Post deleted');
        }
      }).catch(() => {});
    }

    // ── SHARE POST ────────────────────────────────────────────────
    let _sharePostData = null; // { id, content, author, display_name }
    let _allContactsCache = null;

    function openShareSheet(postId) {
      // Find post data from cached feed
      const post = (_socialPosts || []).find(p => p.id === postId);
      _sharePostData = post ? { id: post.id, content: post.content, author: post.author_phone, display_name: (post.display_name && post.display_name.trim()) ? post.display_name : 'NEOX User' } : { id: postId, content: '', author: '', display_name: 'NEOX User' };

      const modal = document.getElementById('sharePostModal');
      if (!modal) return;

      // Show preview text
      const preview = document.getElementById('sharePostPreview');
      if (preview) {
        const authorName = _sharePostData.display_name;
        preview.innerHTML = `<span style="font-weight:700;color:#0E4950;">${escapeHtml(authorName)}</span>` +
          (_sharePostData.content ? `<br><span style="color:#4a6567;">${escapeHtml(_sharePostData.content.slice(0, 120))}${_sharePostData.content.length > 120 ? '…' : ''}</span>` : '');
      }

      // Show native share button only if Web Share API available
      const nativeBtn = document.getElementById('shareNativeBtn');
      if (nativeBtn) nativeBtn.style.display = navigator.share ? 'flex' : 'none';

      // Hide forward panel initially
      const fcp = document.getElementById('forwardContactPanel');
      if (fcp) fcp.style.display = 'none';
      const fsi = document.getElementById('forwardSearchInput');
      if (fsi) fsi.value = '';

      modal.style.display = 'flex';
    }

    function closeShareSheet() {
      const modal = document.getElementById('sharePostModal');
      if (modal) modal.style.display = 'none';
      _sharePostData = null;
    }

    function _buildShareText(post) {
      const name = (post.display_name && post.display_name.trim()) ? post.display_name : 'NEOX User';
      const content = post.content || '';
      const link = window.location.origin + '/social/post/' + post.id;
      return (content ? `"${content}"\n— ${name} on Exomnia\n` : `Post by ${name} on Exomnia\n`) + link;
    }

    function shareViaNativeAPI() {
      if (!_sharePostData || !navigator.share) return;
      const text = _buildShareText(_sharePostData);
      navigator.share({ text: text }).catch(() => {});
      closeShareSheet();
    }

    function shareCopyLink() {
      if (!_sharePostData) return;
      const link = window.location.origin + '/social/post/' + _sharePostData.id;
      navigator.clipboard.writeText(link).then(() => {
        showToast('Link copied!');
      }).catch(() => {
        // Fallback: prompt with text
        prompt('Copy this link:', link);
      });
      closeShareSheet();
    }

    function shareCopyText() {
      if (!_sharePostData) return;
      const text = _buildShareText(_sharePostData);
      navigator.clipboard.writeText(text).then(() => {
        showToast('Post text copied!');
      }).catch(() => {
        prompt('Copy this text:', text);
      });
      closeShareSheet();
    }

    function openForwardToContact() {
      const panel = document.getElementById('forwardContactPanel');
      if (!panel) return;
      panel.style.display = 'block';
      // Load contacts list
      _loadForwardContacts();
    }

    function _loadForwardContacts() {
      const myPhone = _socialPhone();
      const listEl = document.getElementById('forwardContactList');
      if (!listEl) return;

      if (_allContactsCache) {
        _renderForwardContacts(_allContactsCache, '');
        return;
      }

      listEl.innerHTML = '<div style="text-align:center;padding:12px;"><div style="width:18px;height:18px;border:2px solid #0E4950;border-top-color:transparent;border-radius:50%;animation:spin 0.7s linear infinite;display:inline-block;"></div></div>';

      fetch('/api/contacts?phone=' + encodeURIComponent(myPhone))
        .then(r => r.json())
        .then(data => {
          _allContactsCache = data.contacts || data || [];
          _renderForwardContacts(_allContactsCache, '');
        })
        .catch(() => {
          listEl.innerHTML = '<div style="color:#aaa;font-size:13px;text-align:center;padding:12px;">Could not load contacts.</div>';
        });
    }

    function filterForwardContacts(query) {
      if (!_allContactsCache) return;
      _renderForwardContacts(_allContactsCache, query.trim().toLowerCase());
    }

    function _renderForwardContacts(contacts, query) {
      const listEl = document.getElementById('forwardContactList');
      if (!listEl) return;
      const filtered = query
        ? contacts.filter(c => (c.contact_name || c.phone || '').toLowerCase().includes(query) || (c.contact_phone || c.phone || '').includes(query))
        : contacts;

      if (!filtered.length) {
        listEl.innerHTML = '<div style="color:#aaa;font-size:13px;text-align:center;padding:12px;">No contacts found.</div>';
        return;
      }

      listEl.innerHTML = filtered.slice(0, 30).map(c => {
        const name = c.contact_name || c.display_name || c.contact_phone || c.phone || '';
        const phone = c.contact_phone || c.phone || '';
        const initial = name[0] ? name[0].toUpperCase() : '?';
        return `<button onclick="forwardPostToContact('${phone}','${escapeHtml(name)}')" style="display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:12px;border:1px solid #eee;background:#fff;cursor:pointer;font-family:inherit;text-align:left;width:100%;">
          <div style="width:36px;height:36px;border-radius:50%;background:#0E4950;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:14px;flex-shrink:0;">${initial}</div>
          <div style="flex:1;min-width:0;">
            <div style="font-size:14px;font-weight:600;color:#1a2e2f;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(name)}</div>
            <div style="font-size:11px;color:#aac4c5;">${phone}</div>
          </div>
        </button>`;
      }).join('');
    }

    function forwardPostToContact(contactPhone, contactName) {
      if (!_sharePostData) return;
      const myPhone = _socialPhone();
      const text = _buildShareText(_sharePostData);

      fetch('/api/send_message', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ sender: myPhone, receiver: contactPhone, message: text, message_type: 'text' })
      }).then(r => r.json()).then(data => {
        if (data.success !== false) {
          showToast('Sent to ' + (contactName || contactPhone) + '!');
        } else {
          showToast('Failed to send.');
        }
      }).catch(() => showToast('Failed to send.'));

      closeShareSheet();
    }

    function openSocialImg(src) {
      const v = document.getElementById('socialImgViewer');
      document.getElementById('socialImgViewerImg').src = src;
      v.classList.add('open');
    }
    function closeSocialImgViewer() {
      document.getElementById('socialImgViewer').classList.remove('open');
    }

    // ── NETWORK VIEW ─────────────────────────────────────────────
    function loadSocialConnectionStatus() {
      const myPhone = _socialPhone();
      fetch('/api/social/connections?phone=' + encodeURIComponent(myPhone))
        .then(r => r.json())
        .then(data => {
          _socialConnections = {};
          (data.following || []).forEach(p => { _socialConnections[p] = 'following'; });
          (data.followers || []).forEach(p => {
            if (!_socialConnections[p]) _socialConnections[p] = 'follower';
            else _socialConnections[p] = 'connected';
          });
          (data.pending_out || []).forEach(p => { _socialConnections[p] = 'pending'; });
        }).catch(() => {});
    }

    function loadNetworkView() {
      const sc = document.getElementById('socialContent');
      if (!sc) return;
      sc.innerHTML = `<div style="display:flex;justify-content:center;padding:30px 0;"><div style="width:24px;height:24px;border:3px solid #0E4950;border-top-color:transparent;border-radius:50%;animation:spin 0.7s linear infinite;"></div></div>`;
      fetch('/api/social/people?phone=' + encodeURIComponent(_socialPhone()))
        .then(r => r.json())
        .then(people => renderNetworkView(people))
        .catch(() => { if (sc) sc.innerHTML = `<div class="placeholder-content"><p style="color:red;">Failed to load.</p></div>`; });
    }

    function renderNetworkView(people) {
      const sc = document.getElementById('socialContent');
      if (!sc) return;
      const myPhone = _socialPhone();
      let html = `<p style="font-size:12px;color:#7aabae;margin-bottom:12px;font-weight:600;">PEOPLE YOU MAY KNOW</p>`;
      if (!people || people.length === 0) {
        html += `<div class="placeholder-content"><div style="font-size:36px;margin-bottom:8px;">🌐</div><p style="color:#888;">No suggestions yet. Add more contacts!</p></div>`;
      } else {
        people.forEach(p => {
          const status = _socialConnections[p.phone] || 'none';
          const name = p.display_name || 'Exomnia User';
          const avatarHtml = _socialAvatar(p, 48);
          const btnLabel = status === 'connected' ? '✓ Connected'
            : status === 'following' ? 'Following'
            : status === 'pending' ? 'Requested'
            : 'Connect';
          const btnClass = status === 'connected' || status === 'following' ? 'connected'
            : status === 'pending' ? 'pending' : '';
          html += `<div class="people-card">
            <div onclick="openSocialProfile('${p.phone}')" style="cursor:pointer;">${avatarHtml}</div>
            <div class="people-info" onclick="openSocialProfile('${p.phone}')" style="cursor:pointer;">
              <div class="people-name">${escapeHtml(name)}</div>
              <div class="people-headline">${escapeHtml(p.headline || p.bio || '')}</div>
            </div>
            <button class="connect-btn ${btnClass}" id="connBtn_${p.phone.replace(/\\+/g,'_')}"
              onclick="sendConnectionRequest('${p.phone}',this)"
              ${status === 'pending' || status === 'connected' || status === 'following' ? 'disabled' : ''}
            >${btnLabel}</button>
          </div>`;
        });
      }
      sc.innerHTML = html;
    }

    function sendConnectionRequest(targetPhone, btn) {
      const myPhone = _socialPhone();
      if (btn) { btn.disabled = true; btn.textContent = 'Requested'; btn.classList.add('pending'); }
      _socialConnections[targetPhone] = 'pending';
      fetch('/api/social/connect', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ from_phone: myPhone, to_phone: targetPhone })
      }).then(r => r.json()).then(data => {
        if (!data.success) {
          showToast(data.error || 'Failed');
          if (btn) { btn.disabled = false; btn.textContent = 'Connect'; btn.classList.remove('pending'); }
        } else {
          showToast('Request sent!');
        }
      }).catch(() => {
        if (btn) { btn.disabled = false; btn.textContent = 'Connect'; btn.classList.remove('pending'); }
      });
    }

    function disconnectUser(targetPhone, btn) {
      if (!confirm('Disconnect from this person?')) return;
      const myPhone = _socialPhone();
      if (btn) { btn.disabled = true; btn.textContent = 'Disconnecting…'; }
      delete _socialConnections[targetPhone];
      fetch('/api/social/disconnect', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ from_phone: myPhone, to_phone: targetPhone })
      }).then(r => r.json()).then(data => {
        if (data.success) {
          showToast('Disconnected');
          if (btn) {
            btn.disabled = false;
            btn.textContent = '+ Connect';
            btn.style.background = 'linear-gradient(135deg,#0E4950,#1a6b75)';
            btn.style.color = 'white';
            btn.style.boxShadow = '0 4px 14px rgba(14,73,80,0.28)';
            btn.style.cursor = 'pointer';
            btn.onclick = function(){ sendConnectionRequest(targetPhone, btn); };
          }
        } else {
          showToast(data.error || 'Failed to disconnect');
          if (btn) { btn.disabled = false; btn.textContent = '✓ Connected'; }
          _socialConnections[targetPhone] = 'connected';
        }
      }).catch(() => {
        showToast('Failed to disconnect');
        if (btn) { btn.disabled = false; btn.textContent = '✓ Connected'; }
        _socialConnections[targetPhone] = 'connected';
      });
    }

    // ── CONNECTION REQUESTS ───────────────────────────────────────
    function loadConnectionRequests(silent) {
      const myPhone = _socialPhone();
      fetch('/api/social/requests?phone=' + encodeURIComponent(myPhone))
        .then(r => r.json())
        .then(reqs => {
          _socialPendingIn = reqs;
          const badge = document.getElementById('reqBadge');
          if (badge) badge.textContent = reqs.length ? ` (${reqs.length})` : '';
          if (!silent) renderRequestsView(reqs);
        }).catch(() => {});
    }

    function renderRequestsView(reqs) {
      const sc = document.getElementById('socialContent');
      if (!sc) return;
      let html = `<p style="font-size:12px;color:#7aabae;margin-bottom:12px;font-weight:600;">PENDING CONNECTION REQUESTS</p>`;
      if (!reqs || reqs.length === 0) {
        html += `<div class="placeholder-content"><div style="font-size:36px;margin-bottom:8px;">🤝</div><p style="color:#888;">No pending requests</p></div>`;
      } else {
        reqs.forEach(r => {
          const name = r.display_name || 'Exomnia User';
          const avatarHtml = _socialAvatar(r, 44);
          html += `<div class="conn-req-card" id="req_${r.phone.replace(/\\+/g,'_')}">
            <div onclick="openSocialProfile('${r.phone}')" style="cursor:pointer;">${avatarHtml}</div>
            <div class="people-info" onclick="openSocialProfile('${r.phone}')" style="cursor:pointer;">
              <div class="people-name">${escapeHtml(name)}</div>
              <div class="people-headline">${escapeHtml(r.headline || r.bio || '')}</div>
            </div>
            <div class="conn-req-actions">
              <button class="accept-btn" onclick="respondRequest('${r.phone}','accept',this)">Accept</button>
              <button class="decline-btn" onclick="respondRequest('${r.phone}','decline',this)">✕</button>
            </div>
          </div>`;
        });
      }
      sc.innerHTML = html;
    }

    function respondRequest(fromPhone, action, btn) {
      const myPhone = _socialPhone();
      fetch('/api/social/respond', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ from_phone: fromPhone, to_phone: myPhone, action })
      }).then(r => r.json()).then(data => {
        if (data.success) {
          const el = document.getElementById('req_' + fromPhone.replace(/\\+/g,'_'));
          if (el) { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }
          showToast(action === 'accept' ? 'Connected! ✓' : 'Request declined');
          if (action === 'accept') { _socialConnections[fromPhone] = 'connected'; }
          const badge = document.getElementById('reqBadge');
          _socialPendingIn = _socialPendingIn.filter(r => r.phone !== fromPhone);
          if (badge) badge.textContent = _socialPendingIn.length ? ` (${_socialPendingIn.length})` : '';
        }
      }).catch(() => {});
    }

    // ── SOCIAL PROFILE OVERLAY ────────────────────────────────────
    function openSocialProfile(phone) {
      const overlay = document.getElementById('socialProfileOverlay');
      overlay.style.display = 'flex';
      setTimeout(() => overlay.classList.add('spo-visible'), 10);
      renderSocialProfileLoading();
      const myPhone = _socialPhone();
      Promise.all([
        fetch('/api/profile?phone=' + encodeURIComponent(phone)).then(r => r.json()),
        fetch('/api/social/user_posts?phone=' + encodeURIComponent(phone) + '&viewer=' + encodeURIComponent(myPhone)).then(r => r.json()),
        fetch('/api/social/user_stats?phone=' + encodeURIComponent(phone)).then(r => r.json())
      ]).then(([profile, posts, stats]) => {
        renderSocialProfile(profile, posts, stats, phone);
      }).catch(() => {
        document.getElementById('socialProfileBody').innerHTML = `<div style="padding:40px;text-align:center;color:red;">Failed to load profile.</div>`;
      });
    }

    function closeSocialProfile() {
      const overlay = document.getElementById('socialProfileOverlay');
      overlay.classList.remove('spo-visible');
      setTimeout(() => { overlay.style.display = 'none'; }, 320);
    }

    function renderSocialProfileLoading() {
      document.getElementById('socialProfileBody').innerHTML = `
        <div style="display:flex;justify-content:center;padding:60px 0;">
          <div style="width:28px;height:28px;border:3px solid #0E4950;border-top-color:transparent;border-radius:50%;animation:spin 0.7s linear infinite;"></div>
        </div>`;
    }

    function renderSocialProfile(p, posts, stats, profilePhone) {
      const myPhone = _socialPhone();
      const isMe = profilePhone === myPhone;
      const initial = (p.display_name || p.phone || '?')[0].toUpperCase();
      const avatarInner = p.avatar_emoji || initial;
      const bgColor = p.avatar_color || '#0E4950';
      const avatarContent = p.avatar_photo
        ? `<img src="${p.avatar_photo}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;display:block;" alt="">`
        : `<span style="font-size:30px;font-weight:800;color:white;line-height:1;">${avatarInner}</span>`;

      const status = _socialConnections[profilePhone];
      const connBtnHtml = isMe ? `
        <div style="font-size:12px;color:#7aabae;font-weight:600;padding:8px 16px;border:1.5px solid #daeaea;border-radius:10px;display:inline-block;">Your Profile</div>`
        : `<button
            id="spConnBtn"
            onclick="${status === 'connected' || status === 'following' ? `disconnectUser('${profilePhone}',this)` : `sendConnectionRequest('${profilePhone}',this)`}"
            ${status === 'pending' ? 'disabled' : ''}
            style="padding:10px 22px;border-radius:12px;font-size:14px;font-weight:700;font-family:inherit;cursor:${status === 'pending' ? 'default' : 'pointer'};border:none;
              background:${status === 'connected' || status === 'following' ? '#0E4950' : status === 'pending' ? '#e0f0f0' : 'linear-gradient(135deg,#0E4950,#1a6b75)'};
              color:${status === 'pending' ? '#7aabae' : 'white'};
              box-shadow:${status === 'connected' || status === 'following' ? 'none' : '0 4px 14px rgba(14,73,80,0.28)'};">
            ${status === 'connected' ? '✓ Connected' : status === 'following' ? '✓ Following' : status === 'pending' ? 'Requested…' : '+ Connect'}
          </button>`;

      let postsHtml = '';
      if (!posts || posts.length === 0) {
        postsHtml = `
          <div style="text-align:center;padding:36px 20px;background:white;border-radius:16px;border:1px solid #daeaea;">
            <div style="font-size:36px;margin-bottom:8px;">📝</div>
            <div style="color:#888;font-size:14px;font-weight:600;">No posts yet</div>
          </div>`;
      } else {
        posts.forEach(post => { postsHtml += renderPostCard(post, myPhone); });
      }

      document.getElementById('socialProfileBody').innerHTML = `
        <!-- Banner + Avatar -->
        <div style="background:white;border-radius:20px;overflow:hidden;margin-bottom:12px;box-shadow:0 3px 14px rgba(14,73,80,0.09);border:1px solid #daeaea;">
          <!-- Banner -->
          <div style="height:105px;${p.banner_photo
            ? `background-image:url('${p.banner_photo}');background-size:cover;background-position:center;`
            : 'background:linear-gradient(135deg,#0E4950 0%,#2ec4b6 100%);'}"></div>

          <!-- Avatar sits below banner, not overlapping -->
          <div style="padding:16px 18px 18px;display:flex;flex-direction:column;gap:14px;">

            <!-- Row: avatar left, connect btn right -->
            <div style="display:flex;align-items:flex-end;justify-content:space-between;margin-top:-52px;">
              <div style="width:82px;height:82px;border-radius:50%;
                background:${p.avatar_photo ? 'transparent' : bgColor};
                display:flex;align-items:center;justify-content:center;
                overflow:hidden;border:4px solid white;
                box-shadow:0 4px 16px rgba(14,73,80,0.22);flex-shrink:0;">
                ${avatarContent}
              </div>
              <div style="padding-bottom:4px;">${connBtnHtml}</div>
            </div>

            <!-- Name, tag, headline, bio -->
            <div>
              <div style="font-size:22px;font-weight:800;color:#1a2e2f;line-height:1.2;">
                ${escapeHtml(p.display_name && p.display_name.trim() ? p.display_name : (p.user_tag || 'NEOX User'))}
              </div>
              ${p.user_tag ? `<div style="font-size:13px;color:#2ec4b6;font-weight:700;margin-top:3px;">${escapeHtml(p.user_tag)}</div>` : ''}
              ${p.headline ? `<div style="font-size:14px;color:#4a6567;margin-top:6px;line-height:1.4;">${escapeHtml(p.headline)}</div>` : ''}
              ${p.bio && p.bio !== p.headline ? `<div style="font-size:13px;color:#7aabae;margin-top:6px;line-height:1.5;">${escapeHtml(p.bio)}</div>` : ''}
              ${p.location ? `<div style="font-size:12px;color:#aac4c5;margin-top:6px;display:flex;align-items:center;gap:4px;">📍 ${escapeHtml(p.location)}</div>` : ''}
              ${p.website ? `<div style="font-size:12px;margin-top:4px;"><a href="${escapeHtml(p.website)}" target="_blank" style="color:#0E4950;font-weight:600;text-decoration:none;">🔗 ${escapeHtml(p.website)}</a></div>` : ''}
            </div>

            <!-- Stats row inside the card -->
            <div style="display:flex;border-top:1px solid #f0f7f7;padding-top:14px;gap:0;">
              <div style="flex:1;text-align:center;border-right:1px solid #f0f7f7;">
                <div style="font-size:20px;font-weight:800;color:#0E4950;">${(stats.followers || 0) + (stats.following || 0)}</div>
                <div style="font-size:11px;color:#7aabae;font-weight:600;margin-top:2px;">Network</div>
              </div>
              <div style="flex:1;text-align:center;">
                <div style="font-size:20px;font-weight:800;color:#0E4950;">${stats.posts || 0}</div>
                <div style="font-size:11px;color:#7aabae;font-weight:600;margin-top:2px;">Posts</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Posts section -->
        <p style="font-size:11px;color:#7aabae;font-weight:700;letter-spacing:0.5px;margin-bottom:10px;">POSTS</p>
        ${postsHtml}
      `;
    }

  </script>

</body>
</html>"""

signin_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>NEOX — Sign In</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

        :root {
            --brand:      #0E4950;
            --brand-dark: #092f34;
            --brand-mid:  #134f57;
            --accent:     #1fd8a4;
            --text-on-dark: #1a2e2f;
            --text-dim:     #6b8c8e;
            --field-bg:     #f4f8f8;
            --field-border: #d0e4e5;
            --field-focus:  rgba(31,216,164,0.35);
        }

        html, body {
            height: 100%; min-height: 100vh; min-height: 100dvh;
        }

        body {
            display: flex;
            flex-direction: column;
            font-family: 'Plus Jakarta Sans', 'Segoe UI', system-ui, sans-serif;
            background: #ffffff;
            color: var(--text-on-dark);
            -webkit-font-smoothing: antialiased;
        }

        /* ── Mesh background (full page) ── */
        .bg-mesh {
            display: none;
        }

        /* ── Page wrapper ── */
        .page {
            position: relative; z-index: 1;
            flex: 1;
            display: flex;
            flex-direction: column;
            padding: 0 20px 32px;
            padding-top: calc(24px + env(safe-area-inset-top, 0px));
            padding-bottom: calc(32px + env(safe-area-inset-bottom, 0px));
            max-width: 460px;
            width: 100%;
            margin: 0 auto;
        }

        /* ── Brand section ── */
        .brand-section {
            text-align: center;
            padding-bottom: 24px;
        }

        .brand-name {
            font-size: 38px;
            font-weight: 800;
            color: var(--brand);
            letter-spacing: 7px;
            text-transform: uppercase;
            line-height: 1;
            position: relative;
            display: inline-block;
        }

        .brand-name::after {
            content: '';
            display: block;
            width: 32px; height: 3px;
            background: var(--accent);
            border-radius: 2px;
            margin: 8px auto 0;
        }

        .brand-tagline {
            font-size: 11.5px;
            color: var(--text-dim);
            margin-top: 12px;
            letter-spacing: 1.4px;
            text-transform: uppercase;
            font-weight: 500;
        }

        /* ── Form section ── */
        .form-section {
            flex: 1;
        }

        .form-title {
            font-size: 22px;
            font-weight: 700;
            color: var(--brand);
            margin-bottom: 4px;
        }

        .form-subtitle {
            font-size: 13.5px;
            color: var(--text-dim);
            margin-bottom: 28px;
        }

        /* ── Error banner ── */
        .error-banner {
            display: none;
            align-items: flex-start;
            gap: 9px;
            background: rgba(225,29,72,0.08);
            border: 1px solid rgba(225,29,72,0.3);
            border-radius: 10px;
            padding: 12px 14px;
            margin-bottom: 20px;
            font-size: 13px;
            color: #c0152a;
            line-height: 1.45;
        }
        .error-banner.show { display: flex; }
        .error-banner i { margin-top: 1px; flex-shrink: 0; }

        /* ── Fields ── */
        .field { margin-bottom: 18px; }

        .field-label {
            display: flex; align-items: center; gap: 7px;
            font-size: 11.5px; font-weight: 600;
            color: var(--text-dim);
            text-transform: uppercase; letter-spacing: 0.8px;
            margin-bottom: 8px;
        }
        .field-label i { font-size: 10px; }

        .input-wrap { position: relative; }

        .input-wrap .pfx {
            position: absolute;
            left: 14px; top: 50%;
            transform: translateY(-50%);
            color: #9ab8ba;
            font-size: 13px;
            pointer-events: none; z-index: 2;
            transition: color 0.15s;
        }

        .input-wrap input,
        .input-wrap select {
            width: 100%;
            padding: 14px 14px 14px 42px;
            background: var(--field-bg);
            border: 1.5px solid var(--field-border);
            border-radius: 12px;
            font-size: 15px; font-family: inherit; font-weight: 500;
            color: #1a2e2f;
            -webkit-appearance: none; appearance: none;
            outline: none;
            transition: border-color 0.15s, background 0.15s, box-shadow 0.15s;
        }

        .input-wrap input::placeholder {
            color: #9ab8ba;
            font-weight: 400;
        }

        .input-wrap select {
            cursor: pointer;
            background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%239ab8ba' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
            background-repeat: no-repeat;
            background-position: right 12px center;
            background-size: 13px;
        }

        /* Fix select option colors for light bg */
        .input-wrap select option {
            background: #ffffff;
            color: #1a2e2f;
        }

        .input-wrap input:focus,
        .input-wrap select:focus {
            border-color: var(--accent);
            background: #edfaf6;
            box-shadow: 0 0 0 3px var(--field-focus);
        }

        .input-wrap:focus-within .pfx { color: var(--accent); }

        /* Phone row */
        .phone-row { display: flex; gap: 10px; }
        .phone-row .input-wrap:first-child { flex: 0 0 112px; }
        .phone-row .input-wrap:last-child  { flex: 1; }

        /* ── Sign In button ── */
        .btn-signin {
            display: flex; align-items: center; justify-content: center; gap: 10px;
            width: 100%; margin-top: 8px;
            padding: 16px;
            border: none; border-radius: 12px;
            font-size: 15.5px; font-weight: 700; font-family: inherit;
            cursor: pointer;
            background: #0E4950;
            color: #ffffff;
            box-shadow: 0 4px 20px rgba(14,73,80,0.3);
            transition: background 0.15s, transform 0.1s, box-shadow 0.15s;
            position: relative; overflow: hidden;
        }

        .btn-signin::after {
            content: '';
            position: absolute; top: 0; left: -100%; width: 55%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
            transition: left 0.45s ease;
        }
        .btn-signin:hover::after { left: 150%; }
        .btn-signin:hover {
            background: #0a363a;
            box-shadow: 0 6px 24px rgba(14,73,80,0.4);
            transform: translateY(-1px);
        }
        .btn-signin:active  { transform: translateY(0); box-shadow: 0 2px 10px rgba(14,73,80,0.2); }
        .btn-signin:disabled { opacity: 0.6; cursor: not-allowed; transform: none; box-shadow: none; }
        .btn-signin:disabled::after { display: none; }

        @keyframes spin { to { transform: rotate(360deg); } }

        .spinner {
            width: 16px; height: 16px;
            border: 2.5px solid rgba(255,255,255,0.3);
            border-top-color: #ffffff;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
            flex-shrink: 0;
        }

        /* ── Divider ── */
        .sep {
            display: flex; align-items: center; gap: 12px;
            margin: 28px 0 0;
            font-size: 11px; font-weight: 600;
            color: var(--text-dim); letter-spacing: 1px; text-transform: uppercase;
        }
        .sep::before, .sep::after {
            content: ''; flex: 1; height: 1px;
            background: #d0e4e5;
        }

        /* ── Footer ── */
        .footer {
            text-align: center;
            margin-top: 22px;
        }

        .signup-line {
            font-size: 14px;
            color: var(--text-dim);
        }
        .signup-line a {
            color: var(--brand);
            font-weight: 700; text-decoration: none;
        }
        .signup-line a:hover { text-decoration: underline; }

        .footer-links {
            display: flex; justify-content: center;
            gap: 20px; margin-top: 14px;
        }
        .footer-links a {
            font-size: 11.5px;
            color: #9ab8ba;
            text-decoration: none;
            transition: color 0.15s;
        }
        .footer-links a:hover { color: var(--brand); }

        .footer-brand {
            margin-top: 20px;
            padding-top: 16px;
            border-top: 1px solid #d0e4e5;
            font-size: 11px;
            color: #9ab8ba;
            letter-spacing: 0.3px;
        }
        .footer-brand strong { color: var(--text-dim); }

        /* ── Loading overlay ── */
        #overlay {
            display: none; position: fixed; inset: 0;
            background: rgba(255,255,255,0.92);
            z-index: 9999;
            flex-direction: column; align-items: center; justify-content: center;
            gap: 16px; color: var(--brand); font-size: 15px; font-weight: 500;
        }
        #overlay.show { display: flex; }

        .overlay-ring {
            width: 44px; height: 44px;
            border: 3px solid rgba(14,73,80,0.15);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.75s linear infinite;
        }

        /* ── Entrance animation ── */
        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(20px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .brand-section  { animation: fadeUp 0.4s cubic-bezier(0.22,1,0.36,1) both; }
        .form-section   { animation: fadeUp 0.4s 0.07s cubic-bezier(0.22,1,0.36,1) both; }
        .footer         { animation: fadeUp 0.4s 0.12s cubic-bezier(0.22,1,0.36,1) both; }
        .eye-btn {
            position: absolute; right: 14px; top: 50%; transform: translateY(-50%);
            background: none; border: none; cursor: pointer;
            color: #9ab8ba; font-size: 14px; padding: 4px;
            transition: color 0.15s; z-index: 3;
        }
        .eye-btn:hover { color: var(--brand); }
        .forgot-link {
            display: block; text-align: right; font-size: 12px;
            color: #9ab8ba; text-decoration: none;
            margin-top: 6px; transition: color 0.15s;
        }
        .forgot-link:hover { color: var(--brand); }
    </style>
</head>
<body>

    <div class="bg-mesh"></div>

    <!-- Loading overlay -->
    <div id="overlay">
        <div class="overlay-ring"></div>
        <span>Signing you in…</span>
    </div>

    <div class="page">

        <!-- Brand -->
        <div class="brand-section">
            <div class="brand-name">NEOX</div>
            <div class="brand-tagline">Connect · Communicate · Grow</div>
        </div>

        <!-- Form -->
        <div class="form-section">

            <div class="form-title">Sign in</div>
            <div class="form-subtitle">Enter your phone number to continue</div>

            <!-- Error -->
            <div class="error-banner" id="errorMsg">
                <i class="fas fa-circle-exclamation"></i>
                <span id="errorText"></span>
            </div>

            <form method="POST" id="loginForm" novalidate>

                <!-- Phone -->
                <div class="field">
                    <label class="field-label">
                        <i class="fas fa-mobile-alt"></i> Phone number
                    </label>
                    <div class="phone-row">
                        <div class="input-wrap">
                            <i class="pfx fas fa-globe"></i>
                            <select id="country_code" name="country_code" required>
                                <option value="+91">🇮🇳 +91</option>
                                <option value="+1">🇺🇸 +1</option>
                                <option value="+44">🇬🇧 +44</option>
                                <option value="+61">🇦🇺 +61</option>
                                <option value="+971">🇦🇪 +971</option>
                                <option value="+65">🇸🇬 +65</option>
                                <option value="+49">🇩🇪 +49</option>
                            </select>
                        </div>
                        <div class="input-wrap">
                            <i class="pfx fas fa-hashtag"></i>
                            <input type="tel" id="phone_number" name="phone_number"
                                   placeholder="Enter number"
                                   pattern="[0-9]*" inputmode="numeric"
                                   autocomplete="tel-national" required>
                        </div>
                    </div>
                </div>

                <!-- Password -->
                <div class="field" style="margin-top:4px;">
                    <label class="field-label">
                        <i class="fas fa-lock"></i> Password
                    </label>
                    <div class="input-wrap">
                        <i class="pfx fas fa-lock"></i>
                        <input type="password" id="password" name="password"
                               placeholder="Enter your password"
                               autocomplete="current-password" required>
                        <button type="button" class="eye-btn" onclick="togglePwd()">
                            <i class="fas fa-eye" id="eyeIcon"></i>
                        </button>
                    </div>
                    <a href="#" class="forgot-link">Forgot password?</a>
                </div>

                <input type="hidden" name="phone" id="full_number">

                <button type="submit" class="btn-signin" id="loginBtn">
                    <i class="fas fa-right-to-bracket"></i>
                    Sign In
                </button>

                <div style="text-align:center;margin-top:14px;">
                    <a href="/" style="font-size:13px;color:rgba(255,255,255,0.4);text-decoration:none;">
                        ← Back to Create Account
                    </a>
                </div>

            </form>
        </div>

        <div class="sep">or</div>

        <!-- Footer -->
        <div class="footer">
            <p class="signup-line">New here? <a href="/">Create an account</a></p>
            <div class="footer-links">
                <a href="#">Help</a>
                <a href="#">Privacy</a>
                <a href="/security">Security</a>
                <a href="#">Terms</a>
            </div>
            <div class="footer-brand">Created by <strong>EXOMNIA</strong></div>
        </div>

    </div>

    <script>
        const form     = document.getElementById('loginForm');
        const phoneEl  = document.getElementById('phone_number');
        const ccEl     = document.getElementById('country_code');
        const hiddenEl = document.getElementById('full_number');
        const errBox   = document.getElementById('errorMsg');
        const errText  = document.getElementById('errorText');

        function showErr(msg) {
            errText.textContent = msg;
            errBox.classList.add('show');
            errBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
        function hideErr() { errBox.classList.remove('show'); }
        function buildPhone() { hiddenEl.value = ccEl.value + phoneEl.value.replace(/\\D/g, ''); }

        {% if error %}
            showErr("{{ error }}");
        {% endif %}

        phoneEl.addEventListener('input', function() {
            this.value = this.value.replace(/\\D/g, '');
            hideErr(); buildPhone();
        });

        ccEl.addEventListener('change', buildPhone);

        function togglePwd() {
            const f = document.getElementById('password');
            const i = document.getElementById('eyeIcon');
            if (f.type === 'password') { f.type = 'text';     i.className = 'fas fa-eye-slash'; }
            else                       { f.type = 'password'; i.className = 'fas fa-eye'; }
        }

        form.addEventListener('submit', function(e) {
            hideErr();
            const p   = phoneEl.value.trim();
            const pwd = document.getElementById('password').value;
            if (!p) {
                e.preventDefault();
                showErr('Please enter your phone number.');
                phoneEl.focus();
                return;
            }
            if (!pwd) {
                e.preventDefault();
                showErr('Please enter your password.');
                document.getElementById('password').focus();
                return;
            }
            buildPhone();
            document.getElementById('overlay').classList.add('show');
            const btn = document.getElementById('loginBtn');
            btn.innerHTML = '<span class="spinner"></span> Signing in…';
            btn.disabled = true;
        });
    </script>
</body>
</html>"""


signup_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>NEOX — Create Account</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --brand:      #0E4950;
            --brand-dark: #092f34;
            --accent:     #1fd8a4;
            --field-bg:   #f4f8f8;
            --field-border:#d0e4e5;
            --field-focus: rgba(31,216,164,0.35);
        }
        html, body { height: 100%; min-height: 100vh; min-height: 100dvh; }
        body {
            display: flex; flex-direction: column;
            font-family: 'Plus Jakarta Sans', 'Segoe UI', system-ui, sans-serif;
            background: #ffffff; color: #1a2e2f;
            -webkit-font-smoothing: antialiased;
        }
        .bg-mesh { display: none; }
        .page {
            position: relative; z-index: 1; flex: 1;
            display: flex; flex-direction: column;
            padding: 0 20px 32px;
            padding-top: calc(24px + env(safe-area-inset-top, 0px));
            padding-bottom: calc(32px + env(safe-area-inset-bottom, 0px));
            max-width: 460px; width: 100%; margin: 0 auto;
        }
        .brand-section { text-align: center; padding-bottom: 20px; }
        .brand-name {
            font-size: 36px; font-weight: 800; color: var(--brand);
            letter-spacing: 7px; text-transform: uppercase; line-height: 1;
            position: relative; display: inline-block;
        }
        .brand-name::after {
            content: ''; display: block;
            width: 30px; height: 3px; background: var(--accent);
            border-radius: 2px; margin: 8px auto 0;
        }
        .brand-tagline {
            font-size: 11.5px; color: #6b8c8e;
            margin-top: 10px; letter-spacing: 1.4px;
            text-transform: uppercase; font-weight: 500;
        }
        .form-section { flex: 1; }
        .form-title   { font-size: 22px; font-weight: 700; color: var(--brand); margin-bottom: 3px; }
        .form-subtitle { font-size: 13.5px; color: #6b8c8e; margin-bottom: 26px; }
        .error-banner {
            display: none; align-items: flex-start; gap: 9px;
            background: rgba(225,29,72,0.08); border: 1px solid rgba(225,29,72,0.3);
            border-radius: 10px; padding: 12px 14px; margin-bottom: 18px;
            font-size: 13px; color: #c0152a; line-height: 1.45;
        }
        .error-banner.show { display: flex; }
        .error-banner i { margin-top: 1px; flex-shrink: 0; }
        .field { margin-bottom: 16px; }
        .field-label {
            display: flex; align-items: center; gap: 7px;
            font-size: 11.5px; font-weight: 600;
            color: #6b8c8e; text-transform: uppercase;
            letter-spacing: 0.8px; margin-bottom: 8px;
        }
        .field-label i { font-size: 10px; }
        .input-wrap { position: relative; }
        .input-wrap .pfx {
            position: absolute; left: 14px; top: 50%;
            transform: translateY(-50%); color: #9ab8ba;
            font-size: 13px; pointer-events: none; z-index: 2; transition: color 0.15s;
        }
        .input-wrap input, .input-wrap select {
            width: 100%; padding: 14px 14px 14px 42px;
            background: var(--field-bg); border: 1.5px solid var(--field-border);
            border-radius: 12px; font-size: 15px; font-family: inherit;
            font-weight: 500; color: #1a2e2f;
            -webkit-appearance: none; appearance: none; outline: none;
            transition: border-color 0.15s, background 0.15s, box-shadow 0.15s;
        }
        .input-wrap input::placeholder { color: #9ab8ba; font-weight: 400; }
        .input-wrap select {
            cursor: pointer;
            background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%239ab8ba' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
            background-repeat: no-repeat; background-position: right 12px center; background-size: 13px;
        }
        .input-wrap select option { background: #ffffff; color: #1a2e2f; }
        .input-wrap input:focus, .input-wrap select:focus {
            border-color: var(--accent); background: #edfaf6;
            box-shadow: 0 0 0 3px var(--field-focus);
        }
        .input-wrap:focus-within .pfx { color: var(--accent); }
        .phone-row { display: flex; gap: 10px; }
        .phone-row .input-wrap:first-child { flex: 0 0 112px; }
        .phone-row .input-wrap:last-child  { flex: 1; }
        .btn-primary {
            display: flex; align-items: center; justify-content: center; gap: 10px;
            width: 100%; margin-top: 8px; padding: 16px;
            border: none; border-radius: 12px;
            font-size: 15.5px; font-weight: 700; font-family: inherit;
            cursor: pointer; background: #0E4950; color: #ffffff;
            box-shadow: 0 4px 20px rgba(14,73,80,0.3);
            transition: background 0.15s, transform 0.1s, box-shadow 0.15s;
            position: relative; overflow: hidden;
        }
        .btn-primary::after {
            content: ''; position: absolute; top: 0; left: -100%; width: 55%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
            transition: left 0.45s ease;
        }
        .btn-primary:hover::after { left: 150%; }
        .btn-primary:hover { background: #0a363a; box-shadow: 0 6px 24px rgba(14,73,80,0.4); transform: translateY(-1px); }
        .btn-primary:active { transform: translateY(0); }
        .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; transform: none; box-shadow: none; }
        .btn-primary:disabled::after { display: none; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .spinner {
            width: 16px; height: 16px;
            border: 2.5px solid rgba(255,255,255,0.3); border-top-color: #ffffff;
            border-radius: 50%; animation: spin 0.7s linear infinite; flex-shrink: 0;
        }
        .sep {
            display: flex; align-items: center; gap: 12px; margin: 24px 0 0;
            font-size: 11px; font-weight: 600; color: #6b8c8e;
            letter-spacing: 1px; text-transform: uppercase;
        }
        .sep::before, .sep::after { content: ''; flex: 1; height: 1px; background: #d0e4e5; }
        .footer { text-align: center; margin-top: 20px; }
        .switch-line { font-size: 14px; color: #6b8c8e; }
        .switch-line a { color: var(--brand); font-weight: 700; text-decoration: none; }
        .switch-line a:hover { text-decoration: underline; }
        .footer-links { display: flex; justify-content: center; gap: 20px; margin-top: 12px; }
        .footer-links a { font-size: 11.5px; color: #9ab8ba; text-decoration: none; transition: color 0.15s; }
        .footer-links a:hover { color: var(--brand); }
        .footer-brand { margin-top: 18px; padding-top: 14px; border-top: 1px solid #d0e4e5; font-size: 11px; color: #9ab8ba; letter-spacing: 0.3px; }
        .footer-brand strong { color: #6b8c8e; }
        #overlay {
            display: none; position: fixed; inset: 0; background: rgba(255,255,255,0.92);
            z-index: 9999; flex-direction: column; align-items: center; justify-content: center;
            gap: 16px; color: var(--brand); font-size: 15px; font-weight: 500;
        }
        #overlay.show { display: flex; }
        .overlay-ring {
            width: 44px; height: 44px; border: 3px solid rgba(14,73,80,0.15);
            border-top-color: var(--accent); border-radius: 50%;
            animation: spin 0.75s linear infinite;
        }
        @keyframes fadeUp { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }
        .brand-section { animation: fadeUp 0.4s cubic-bezier(0.22,1,0.36,1) both; }
        .form-section  { animation: fadeUp 0.4s 0.07s cubic-bezier(0.22,1,0.36,1) both; }
        .footer        { animation: fadeUp 0.4s 0.12s cubic-bezier(0.22,1,0.36,1) both; }
        /* Password eye toggle */
        .input-wrap { position: relative; }
        .eye-btn {
            position: absolute; right: 14px; top: 50%; transform: translateY(-50%);
            background: none; border: none; cursor: pointer;
            color: #9ab8ba; font-size: 14px; padding: 4px;
            transition: color 0.15s; z-index: 3;
        }
        .eye-btn:hover { color: var(--brand); }
        /* Strength bar */
        .strength-wrap { margin-top: 6px; height: 3px; border-radius: 2px; background: #d0e4e5; overflow: hidden; }
        .strength-bar  { height: 100%; border-radius: 2px; width: 0; transition: width 0.3s, background 0.3s; }
        .strength-label { font-size: 10.5px; color: #6b8c8e; margin-top: 4px; }
        /* Match indicator */
        .match-hint { font-size: 10.5px; margin-top: 5px; }
        .match-ok  { color: var(--accent); }
        .match-bad { color: #c0152a; }
    </style>
</head>
<body>
    <div class="bg-mesh"></div>
    <div id="overlay"><div class="overlay-ring"></div><span>Creating your account\u2026</span></div>

    <div class="page">
        <div class="brand-section">
            <div class="brand-name">NEOX</div>
            <div class="brand-tagline">Connect \u00b7 Communicate \u00b7 Grow</div>
        </div>

        <div class="form-section">
            <div class="form-title">Create account</div>
            <div class="form-subtitle">Join NEOX \u2014 it only takes a moment</div>

            <div class="error-banner" id="errorMsg">
                <i class="fas fa-circle-exclamation"></i>
                <span id="errorText"></span>
            </div>

            <form method="POST" action="/" id="signupForm" novalidate>
                <input type="hidden" name="action" value="signup">

                <div class="field">
                    <label class="field-label" for="display_name"><i class="fas fa-user"></i> Your Name</label>
                    <div class="input-wrap">
                        <i class="pfx fas fa-user"></i>
                        <input type="text" id="display_name" name="display_name"
                               placeholder="Enter your full name or nickname"
                               autocomplete="name" autocorrect="off" spellcheck="false" required>
                    </div>
                </div>

                <div class="field">
                    <label class="field-label"><i class="fas fa-mobile-alt"></i> Phone Number</label>
                    <div class="phone-row">
                        <div class="input-wrap">
                            <i class="pfx fas fa-globe"></i>
                            <select id="country_code" name="country_code" required>
                                <option value="+91">\U0001f1ee\U0001f1f3 +91</option>
                                <option value="+1">\U0001f1fa\U0001f1f8 +1</option>
                                <option value="+44">\U0001f1ec\U0001f1e7 +44</option>
                                <option value="+61">\U0001f1e6\U0001f1fa +61</option>
                                <option value="+971">\U0001f1e6\U0001f1ea +971</option>
                                <option value="+65">\U0001f1f8\U0001f1ec +65</option>
                                <option value="+49">\U0001f1e9\U0001f1ea +49</option>
                            </select>
                        </div>
                        <div class="input-wrap">
                            <i class="pfx fas fa-hashtag"></i>
                            <input type="tel" id="phone_number" name="phone_number"
                                   placeholder="Enter number"
                                   pattern="[0-9]*" inputmode="numeric"
                                   autocomplete="tel-national" required>
                        </div>
                    </div>
                </div>

                <div class="field">
                    <label class="field-label"><i class="fas fa-lock"></i> Password</label>
                    <div class="input-wrap">
                        <i class="pfx fas fa-lock"></i>
                        <input type="password" id="password" name="password"
                               placeholder="Create a password (min. 6 chars)"
                               autocomplete="new-password" required>
                        <button type="button" class="eye-btn" onclick="togglePwd('password','eyeIcon1')">
                            <i class="fas fa-eye" id="eyeIcon1"></i>
                        </button>
                    </div>
                </div>

                <div class="field">
                    <label class="field-label"><i class="fas fa-lock"></i> Confirm Password</label>
                    <div class="input-wrap">
                        <i class="pfx fas fa-lock"></i>
                        <input type="password" id="password_confirm" name="password_confirm"
                               placeholder="Re-enter your password"
                               autocomplete="new-password" required>
                        <button type="button" class="eye-btn" onclick="togglePwd('password_confirm','eyeIcon2')">
                            <i class="fas fa-eye" id="eyeIcon2"></i>
                        </button>
                    </div>
                </div>

                <input type="hidden" name="phone" id="full_number">
                <button type="submit" class="btn-primary" id="submitBtn">
                    <i class="fas fa-user-plus"></i> Create Account
                </button>
            </form>
        </div>

        <div class="sep">or</div>
        <div class="footer">
            <p class="switch-line">Already have an account? <a href="/signin">Sign in</a></p>
            <div class="footer-links">
                <a href="#">Help</a>
                <a href="#">Privacy</a>
                <a href="/security">Security</a>
                <a href="#">Terms</a>
            </div>
            <div class="footer-brand">Created by <strong>EXOMNIA</strong></div>
        </div>
    </div>

    <script>
        const form     = document.getElementById('signupForm');
        const phoneEl  = document.getElementById('phone_number');
        const ccEl     = document.getElementById('country_code');
        const hiddenEl = document.getElementById('full_number');
        const errBox   = document.getElementById('errorMsg');
        const errText  = document.getElementById('errorText');

        function showErr(msg) { errText.textContent = msg; errBox.classList.add('show'); errBox.scrollIntoView({behavior:'smooth',block:'nearest'}); }
        function hideErr()    { errBox.classList.remove('show'); }
        function buildPhone() { hiddenEl.value = ccEl.value + phoneEl.value.replace(/\\D/g, ''); }

        {% if error %}showErr("{{ error }}");{% endif %}

        phoneEl.addEventListener('input', function() { this.value = this.value.replace(/\\D/g,''); hideErr(); buildPhone(); });
        ccEl.addEventListener('change', buildPhone);

        function togglePwd(fieldId, iconId) {
            const f = document.getElementById(fieldId);
            const i = document.getElementById(iconId);
            if (f.type === 'password') { f.type = 'text';     i.className = 'fas fa-eye-slash'; }
            else                       { f.type = 'password'; i.className = 'fas fa-eye'; }
        }

        const pwdEl  = document.getElementById('password');
        const confEl = document.getElementById('password_confirm');

        // Strength meter
        pwdEl.closest('.input-wrap').insertAdjacentHTML('afterend',
            '<div class="strength-wrap"><div class="strength-bar" id="sBar"></div></div>' +
            '<div class="strength-label" id="sLabel"></div>');

        pwdEl.addEventListener('input', function() {
            const v = this.value;
            const sBar  = document.getElementById('sBar');
            const sLabel= document.getElementById('sLabel');
            let score = 0;
            if (v.length >= 6)           score++;
            if (v.length >= 10)          score++;
            if (/[A-Z]/.test(v))         score++;
            if (/[0-9]/.test(v))         score++;
            if (/[^A-Za-z0-9]/.test(v))  score++;
            const levels = [
                {w:'20%', bg:'#ef4444', t:'Weak'},
                {w:'40%', bg:'#f97316', t:'Fair'},
                {w:'60%', bg:'#eab308', t:'Good'},
                {w:'80%', bg:'#22c55e', t:'Strong'},
                {w:'100%',bg:'#1fd8a4', t:'Very strong'}
            ];
            const lv = levels[Math.min(score, 4)];
            sBar.style.width      = v.length ? lv.w  : '0';
            sBar.style.background = v.length ? lv.bg : 'transparent';
            sLabel.textContent    = v.length ? lv.t  : '';
            checkMatch();
        });

        // Match hint
        confEl.closest('.input-wrap').insertAdjacentHTML('afterend',
            '<div class="match-hint" id="matchHint"></div>');
        function checkMatch() {
            const hint = document.getElementById('matchHint');
            if (!confEl.value) { hint.textContent = ''; return; }
            if (pwdEl.value === confEl.value) {
                hint.className = 'match-hint match-ok';
                hint.innerHTML = '✓ Passwords match';
            } else {
                hint.className = 'match-hint match-bad';
                hint.innerHTML = '× Passwords do not match';
            }
        }
        confEl.addEventListener('input', checkMatch);

        form.addEventListener('submit', function(e) {
            hideErr();
            const name = document.getElementById('display_name').value.trim();
            const num  = phoneEl.value.trim();
            const pwd  = pwdEl.value;
            const conf = confEl.value;
            if (!name)          { e.preventDefault(); showErr('Please enter your name.');                  document.getElementById('display_name').focus(); return; }
            if (!num)           { e.preventDefault(); showErr('Please enter your phone number.');          phoneEl.focus(); return; }
            if (pwd.length < 6) { e.preventDefault(); showErr('Password must be at least 6 characters.'); pwdEl.focus();   return; }
            if (pwd !== conf)   { e.preventDefault(); showErr('Passwords do not match.');                  confEl.focus();  return; }
            buildPhone();
            document.getElementById('overlay').classList.add('show');
            const btn = document.getElementById('submitBtn');
            btn.innerHTML = '<span class="spinner"></span> Creating…';
            btn.disabled = true;
        });
        });
    </script>
</body>
</html>"""

# ----------------- Routes -----------------
@app.route("/", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        display_name  = request.form.get("display_name", "").strip()
        country_code  = request.form.get("country_code", "").strip()
        phone_number  = request.form.get("phone_number", "").strip()
        phone         = request.form.get("phone", "").strip()
        password      = request.form.get("password", "").strip()
        password_conf = request.form.get("password_confirm", "").strip()

        if not phone and country_code and phone_number:
            phone = country_code + phone_number

        if not display_name:
            return render_template_string(signup_html, error="Please enter your name")
        if not phone:
            return render_template_string(signup_html, error="Please enter your phone number")
        if not validate_phone(phone):
            return render_template_string(signup_html, error="Please use correct phone number format with country code")
        if not password or len(password) < 6:
            return render_template_string(signup_html, error="Password must be at least 6 characters")
        if password != password_conf:
            return render_template_string(signup_html, error="Passwords do not match")

        try:
            now_iso   = datetime.now().isoformat()
            pwd_hash  = generate_password_hash(password)
            conn = get_db_connection()
            try:
                c = conn.cursor()
                # Check if phone already registered with a password
                c.execute("SELECT password_hash FROM users WHERE phone=%s", (phone,))
                row = c.fetchone()
                if row and row[0]:
                    return render_template_string(signup_html, error="An account with this number already exists. Please sign in.")
                c.execute("INSERT INTO users(phone,last_online) VALUES(%s,%s)", (phone, now_iso))
                c.execute("UPDATE users SET last_online=%s, username=%s, password_hash=%s WHERE phone=%s",
                          (now_iso, display_name, pwd_hash, phone))
                c.execute("UPDATE users SET display_name=%s WHERE phone=%s AND (display_name IS NULL OR display_name='')",
                          (display_name, phone))
                conn.commit()
            finally:
                return_db_connection(conn)
            return redirect(url_for('main_app', logged_in_phone=phone))
        except Exception as e:
            print(f"Error in signup: {e}")
            return render_template_string(signup_html, error="An error occurred. Please try again.")

    return render_template_string(signup_html)

@app.route("/signin", methods=["GET","POST"])
def signin():
    if request.method == "POST":
        country_code = request.form.get("country_code", "").strip()
        phone_number = request.form.get("phone_number", "").strip()
        phone        = request.form.get("phone", "").strip()
        password     = request.form.get("password", "").strip()

        if not phone and country_code and phone_number:
            phone = country_code + phone_number

        if not phone:
            return render_template_string(signin_html, error="Please enter your phone number")
        if not validate_phone(phone):
            return render_template_string(signin_html, error="Please use correct phone number format with country code")
        if not password:
            return render_template_string(signin_html, error="Please enter your password")

        try:
            now_iso = datetime.now().isoformat()
            conn = get_db_connection()
            try:
                c = conn.cursor()
                c.execute("SELECT password_hash FROM users WHERE phone=%s", (phone,))
                row = c.fetchone()
                if not row:
                    return render_template_string(signin_html, error="No account found with this number. Please create an account first.")
                stored_hash = row[0] or ""
                # Allow sign-in without password for old accounts that predate password system
                if stored_hash and not check_password_hash(stored_hash, password):
                    return render_template_string(signin_html, error="Incorrect password. Please try again.")
                c.execute("UPDATE users SET last_online=%s WHERE phone=%s", (now_iso, phone))
                conn.commit()
            finally:
                return_db_connection(conn)
            return redirect(url_for('main_app', logged_in_phone=phone))
        except Exception as e:
            print(f"Error in signin: {e}")
            return render_template_string(signin_html, error="An error occurred. Please try again.")

    return render_template_string(signin_html)

@app.route("/main")
def main_app():
    logged_in_phone = request.args.get('logged_in_phone', '')
    return render_template_string(main_app_html, logged_in_phone=logged_in_phone)

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
                    VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
                """, (sender, receiver, f"Sent a {file_type}", file_type, unique_filename, file.filename, file_size, thumbnail_path, "sent", now_iso))
                message_id = c.fetchone()[0]
                c.execute("INSERT INTO contacts(user_phone, contact_phone, contact_name, last_message, last_sender) VALUES(%s, %s, %s, %s, %s) ON CONFLICT(user_phone, contact_phone) DO UPDATE SET last_message=EXCLUDED.last_message, last_sender=EXCLUDED.last_sender, timestamp=EXCLUDED.timestamp",
                          (sender, receiver, "", f"Sent a {file_type}", sender))
                c.execute("UPDATE contacts SET last_message=%s, last_sender=%s, timestamp=CURRENT_TIMESTAMP WHERE user_phone=%s AND contact_phone=%s",
                          (f"Sent a {file_type}", sender, sender, receiver))
                c.execute("INSERT INTO contacts(user_phone, contact_phone, contact_name, last_message, last_sender) VALUES(%s, %s, %s, %s, %s) ON CONFLICT(user_phone, contact_phone) DO UPDATE SET last_message=EXCLUDED.last_message, last_sender=EXCLUDED.last_sender, timestamp=EXCLUDED.timestamp",
                          (receiver, sender, "", f"Sent a {file_type}", sender))
                c.execute("UPDATE contacts SET last_message=%s, last_sender=%s, timestamp=CURRENT_TIMESTAMP WHERE user_phone=%s AND contact_phone=%s",
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

# ----------------- Contacts API -----------------
@app.route("/api/contacts")
def api_contacts():
    phone = request.args.get("phone")
    if not phone:
        return jsonify([]), 400
    
    # Check cache first
    cache_key = f"contacts_{phone}"
    cached_contacts = cache.get(cache_key)
    if cached_contacts:
        return jsonify(cached_contacts)
    
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("""
                SELECT c.contact_phone, c.contact_name,
                       substr(COALESCE(c.last_message,''), 1, 50) ||
                       CASE WHEN length(c.last_message) > 50 THEN '...' ELSE '' END as last_message,
                       c.last_sender,
                       COALESCE(u.avatar_photo, '') as avatar_photo,
                       COALESCE(u.avatar_color, '#0E4950') as avatar_color,
                       COALESCE(u.avatar_emoji, '') as avatar_emoji
                FROM contacts c
                LEFT JOIN users u ON u.phone = c.contact_phone
                WHERE c.user_phone=?
                ORDER BY c.timestamp DESC
            """,(phone,))
            rows = c.fetchall()
        finally:
            return_db_connection(conn)
        contacts = [{"contact_phone": r[0], "contact_name": r[1], "last_message": r[2], "last_sender": r[3], "avatar_photo": r[4], "avatar_color": r[5], "avatar_emoji": r[6]} for r in rows]
        
        # Cache the results
        cache.set(cache_key, contacts)
        
        return jsonify(contacts)
    except Exception as e:
        print(f" Error in api_contacts: {e}")
        return jsonify([]), 500

@app.route("/add_contact", methods=["POST"])
def add_contact():
    try:
        user = request.form.get("user")
        country_code = request.form.get("country_code","")
        contact_phone = request.form.get("contact_phone","").strip()
        contact_name = request.form.get("contact_name","").strip()
        if not all([user, contact_phone, contact_name]):
            return jsonify({"success": False, "error": "Please fill all information"}), 400

        full_contact_phone = contact_phone
        if country_code and not contact_phone.startswith(country_code):
            full_contact_phone = country_code + contact_phone

        if not validate_phone(full_contact_phone):
            return jsonify({"success": False, "error": "Please enter valid phone number"}), 400

        now_iso = datetime.now().isoformat()
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("INSERT INTO users(phone,last_online) VALUES(%s,%s) ON CONFLICT(phone) DO UPDATE SET last_online=EXCLUDED.last_online",(full_contact_phone, now_iso))
            c.execute("""
                INSERT INTO contacts(user_phone,contact_phone,contact_name,last_message)
                VALUES(%s,%s,%s,COALESCE((SELECT last_message FROM contacts WHERE user_phone=%s AND contact_phone=%s), ''))
                ON CONFLICT(user_phone, contact_phone) DO UPDATE SET last_message=EXCLUDED.last_message
            """, (user, full_contact_phone, contact_name, user, full_contact_phone))
            conn.commit()
        finally:
            return_db_connection(conn)

        # Clear cache for this user's contacts
        cache.delete(f"contacts_{user}")

        return jsonify({"success": True})

    except Exception as e:
        print(f" Error in add_contact: {e}")
        return jsonify({"success": False, "error": "An error occurred"}), 500

# ----------------- Profile API -----------------
@app.route("/api/profile")
def api_get_profile():
    phone = request.args.get("phone", "").strip()
    if not phone:
        return jsonify({"error": "Phone required"}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT phone, display_name, bio, avatar_color, avatar_emoji, last_online, avatar_photo, banner_photo FROM users WHERE phone=%s", (phone,))
        row = c.fetchone()
    finally:
        return_db_connection(conn)
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "phone": row[0],
        "display_name": row[1] or "",
        "bio": row[2] or "",
        "avatar_color": row[3] or "#0E4950",
        "avatar_emoji": row[4] or "",
        "last_online": row[5] or "",
        "avatar_photo": row[6] or "",
        "banner_photo": row[7] or "",
    })

@app.route("/api/profile/update", methods=["POST"])
def api_update_profile():
    data = request.get_json() or {}
    phone = data.get("phone", "").strip()
    display_name = data.get("display_name", "").strip()[:40]
    bio = data.get("bio", "").strip()[:120]
    avatar_color = data.get("avatar_color", "#0E4950").strip()
    avatar_emoji = data.get("avatar_emoji", "").strip()
    if not phone:
        return jsonify({"success": False, "error": "Phone required"}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("""
            UPDATE users SET display_name=?, bio=?, avatar_color=?, avatar_emoji=?
            WHERE phone=?
        """, (display_name, bio, avatar_color, avatar_emoji, phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    cache.delete(f"profile_{phone}")
    return jsonify({"success": True})

# ----------------- Profile Photo Upload -----------------
AVATAR_UPLOAD_FOLDER = os.path.join('uploads', 'avatars')
os.makedirs(AVATAR_UPLOAD_FOLDER, exist_ok=True)
ALLOWED_AVATAR_EXTS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}

@app.route("/api/profile/upload_photo", methods=["POST"])
def api_upload_profile_photo():
    phone = request.form.get("phone", "").strip()
    if not phone:
        return jsonify({"success": False, "error": "Phone required"}), 400
    if 'photo' not in request.files:
        return jsonify({"success": False, "error": "No file"}), 400
    f = request.files['photo']
    if not f or f.filename == '':
        return jsonify({"success": False, "error": "Empty file"}), 400
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ALLOWED_AVATAR_EXTS:
        return jsonify({"success": False, "error": "Invalid file type"}), 400
    # Limit to 5 MB
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > 5 * 1024 * 1024:
        return jsonify({"success": False, "error": "File too large (max 5 MB)"}), 400
    filename = f"avatar_{phone.replace('+','')}.{ext}"
    path = os.path.join(AVATAR_UPLOAD_FOLDER, filename)
    f.save(path)
    photo_url = f"/uploads/avatars/{filename}"
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE users SET avatar_photo=%s WHERE phone=%s", (photo_url, phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    cache.delete(f"profile_{phone}")
    return jsonify({"success": True, "photo_url": photo_url})

@app.route("/uploads/avatars/<path:filename>")
def serve_avatar(filename):
    from flask import send_from_directory as sfd
    return sfd(AVATAR_UPLOAD_FOLDER, filename)

@app.route("/api/profile/upload_banner", methods=["POST"])
def api_upload_banner_photo():
    phone = request.form.get("phone", "").strip()
    if not phone:
        return jsonify({"success": False, "error": "Phone required"}), 400
    if 'photo' not in request.files:
        return jsonify({"success": False, "error": "No file"}), 400
    f = request.files['photo']
    if not f or f.filename == '':
        return jsonify({"success": False, "error": "Empty file"}), 400
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ALLOWED_AVATAR_EXTS:
        return jsonify({"success": False, "error": "Invalid file type"}), 400
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > 8 * 1024 * 1024:
        return jsonify({"success": False, "error": "File too large (max 8 MB)"}), 400
    filename = f"banner_{phone.replace('+','')}.{ext}"
    path = os.path.join(AVATAR_UPLOAD_FOLDER, filename)
    f.save(path)
    photo_url = f"/uploads/avatars/{filename}"
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE users SET banner_photo=%s WHERE phone=%s", (photo_url, phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    cache.delete(f"profile_{phone}")
    return jsonify({"success": True, "banner_url": photo_url})
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
                WHERE ((m.sender=%s AND m.receiver=%s) OR (m.sender=%s AND m.receiver=%s))
                  AND (m.deleted_for IS NULL OR POSITION(',' || %s || ',' IN ',' || COALESCE(m.deleted_for,'') || ',') = 0)
                ORDER BY m.timestamp ASC
                LIMIT %s OFFSET %s
            """, (user_phone, contact_phone, contact_phone, user_phone, user_phone, limit, offset))
            messages_data = c.fetchall()

            message_ids = [m[0] for m in messages_data]
            reactions_dict = {}
            if message_ids:
                c.execute("""
                    SELECT message_id, user_phone, emoji
                    FROM message_reactions
                    WHERE message_id = ANY(%s)
                """, (list(message_ids),))
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

# ----------------- Enhanced Chat Page -----------------
chat_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Chat</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, interactive-widget=resizes-content">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap" onload="this.onload=null;this.rel='stylesheet'">
    <noscript><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap"></noscript>
    <style>
        :root {
            --primary-color: #0E4950;
            --primary-light: #1a6b75;
            --primary-dark: #092f34;
            --secondary-color: #A8D0CF;
            --accent-color: #2ec4b6;
            --accent-warm: #ff9f1c;
            --sent-bubble: #e8f8f5;
            --sent-bubble-border: #c3ede8;
            --received-bubble: #ffffff;
            --background-color: #eef6f6;
            --chat-bg: #f0f4f4;
            --text-color: #1a2e2f;
            --text-secondary: #4a6567;
            --light-text: #8aa3a5;
            --border-color: #d8e8e8;
            --shadow: 0 4px 20px rgba(14, 73, 80, 0.08);
            --shadow-strong: 0 8px 32px rgba(14, 73, 80, 0.15);
            --radius-bubble: 20px;
            --radius-ui: 16px;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }

        html {
            height: 100%;
            height: -webkit-fill-available;
        }

        body {
            font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            display: flex;
            flex-direction: column;
            height: 100vh;
            height: 100dvh;
            min-height: -webkit-fill-available;
            background: var(--chat-bg);
            color: var(--text-color);
            overflow: hidden;
            /* Prevent elastic scroll from exposing background */
            position: fixed;
            width: 100%;
            top: 0;
            left: 0;
        }

        #chat-header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-light) 100%);
            color: #fff;
            padding: calc(14px + env(safe-area-inset-top, 0px)) 18px 14px;
            padding-left: calc(18px + env(safe-area-inset-left, 0px));
            padding-right: calc(18px + env(safe-area-inset-right, 0px));
            font-weight: 600;
            font-size: 17px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 16px rgba(14, 73, 80, 0.25);
            z-index: 10;
            position: relative;
        }

        #contact-info {
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;
        }

        .left-header-actions {
            display: flex;
            gap: 8px;
            align-items: center;
            margin-right: 12px;
        }

        #saveBtn {
            background: rgba(255,255,255,0.18);
            border: 1.5px solid rgba(255,255,255,0.5);
            color: #fff;
            cursor: pointer;
            padding: 7px 14px;
            border-radius: 20px;
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.2s;
            backdrop-filter: blur(4px);
            white-space: nowrap;
        }

        #saveBtn:hover {
            background: rgba(255,255,255,0.3);
        }

        .contact-avatar-unsaved {
            cursor: pointer;
            background: linear-gradient(135deg, rgba(255,255,255,0.25), rgba(255,255,255,0.1));
            border: 2px dashed rgba(255,255,255,0.7);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.15s, background 0.15s;
        }
        .contact-avatar-unsaved:active {
            transform: scale(0.93);
            background: rgba(255,255,255,0.3);
        }
        .contact-avatar {
            width: 42px;
            height: 42px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--accent-color), #1a6b75);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 17px;
            border: 2px solid rgba(255,255,255,0.3);
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        }

        .contact-details {
            display: flex;
            flex-direction: column;
            flex: 1;
        }

        .contact-name {
            font-size: 17px;
            font-weight: 700;
            letter-spacing: -0.01em;
        }

        .connection-status {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 12px;
            margin-top: 1px;
            opacity: 0.85;
        }

        .status-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            display: inline-block;
        }

        .status-online {
            background: #4ade80;
            box-shadow: 0 0 6px rgba(74, 222, 128, 0.6);
            animation: statusPulse 2s ease-in-out infinite;
        }
        @keyframes statusPulse {
            0%,100% { box-shadow: 0 0 4px rgba(74,222,128,0.5); }
            50%      { box-shadow: 0 0 10px rgba(74,222,128,0.9); }
        }
        .status-offline {
            background: #94a3b8;
            box-shadow: none;
        }

        .header-actions {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        #chat-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            min-height: 0; /* critical for flex children to shrink */
            background: #eef6f6;
            background-image: radial-gradient(circle, rgba(14,73,80,0.045) 1px, transparent 1px);
            background-size: 22px 22px;
        }

        #chat {
            flex: 1;
            overflow-y: auto;
            padding: 20px 16px 12px;
            display: flex;
            flex-direction: column;
            gap: 4px;
            scroll-behavior: auto;
            overscroll-behavior: contain;
        }

        .message-group {
            display: flex;
            flex-direction: column;
            margin-bottom: 10px;
            max-width: 82%;
            contain: layout style;
        }

        /* Image bubbles wider than text — up to 72% of viewport */
        .message-group:has(.media-message) {
            max-width: min(72vw, 320px);
        }

        .sent-group {
            align-self: flex-end;
            align-items: flex-end;
        }

        .received-group {
            align-self: flex-start;
            align-items: flex-start;
        }

        .bubble {
            padding: 11px 15px;
            border-radius: 20px;
            margin: 2px 0;
            font-size: 15px;
            line-height: 1.5;
            word-wrap: break-word;
            position: relative;
            white-space: pre-wrap;
            word-break: break-word;
            overflow-wrap: break-word;
            max-width: 100%;
            user-select: none;
            -webkit-user-select: none;
            transition: transform 0.1s ease;
            will-change: transform;
        }

        .bubble.media-message {
            padding: 6px;
            overflow: hidden;
        }

        .bubble:active {
            transform: scale(0.985);
        }

        .sent {
            background: linear-gradient(135deg, #d4f5ef 0%, #c8ede7 100%);
            border-bottom-right-radius: 5px;
            border: 1px solid rgba(46, 196, 182, 0.2);
            box-shadow: 0 1px 4px rgba(14, 73, 80, 0.08);
        }

        .received {
            background: #ffffff;
            border-bottom-left-radius: 5px;
            border: 1px solid #e8eeee;
            box-shadow: 0 1px 4px rgba(0, 0, 0, 0.05);
        }

        .status {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            margin-top: 3px;
            padding-right: 2px;
            color: var(--accent-color);
            line-height: 1;
        }

        .status svg {
            color: var(--accent-color);
        }

        .message-time {
            font-size: 10px;
            color: var(--light-text);
            margin-top: 2px;
            padding: 0 2px;
            font-family: 'DM Mono', monospace;
        }

        #typing {
            font-size: 13px;
            color: var(--text-secondary);
            margin: 0 16px 8px;
            height: 18px;
            font-style: italic;
        }

        #message-box {
            display: flex;
            padding: 10px 12px calc(14px + env(safe-area-inset-bottom, 0px));
            padding-bottom: calc(14px + env(safe-area-inset-bottom, 0px) + var(--keyboard-offset, 0px));
            background: #fff;
            border-top: 1px solid var(--border-color);
            gap: 8px;
            align-items: center;
            min-height: 66px;
            box-shadow: 0 -4px 20px rgba(14, 73, 80, 0.06);
            flex-shrink: 0;
        }

        #message {
            flex: 1;
            padding: 11px 16px;
            font-size: 15px;
            border: 1.5px solid var(--border-color);
            border-radius: 24px;
            outline: none;
            resize: none;
            max-height: 120px;
            font-family: 'DM Sans', inherit;
            transition: border-color 0.2s, box-shadow 0.2s;
            background: #f8fafa;
            line-height: 1.45;
            overflow-y: auto;
            min-height: 44px;
            height: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            word-break: break-word;
            color: var(--text-color);
        }

        #message::placeholder {
            color: var(--light-text);
        }

        #message:focus {
            border-color: var(--accent-color);
            background: #fff;
            box-shadow: 0 0 0 3px rgba(46, 196, 182, 0.12);
        }

        #send-btn {
            width: 48px;
            height: 48px;
            border: none;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary-color), var(--primary-light));
            color: white;
            font-size: 18px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.15s, box-shadow 0.15s;
            flex-shrink: 0;
            box-shadow: 0 3px 14px rgba(14, 73, 80, 0.35);
        }

        #send-btn:hover {
            transform: scale(1.07);
            box-shadow: 0 5px 18px rgba(14, 73, 80, 0.45);
        }

        #send-btn:active {
            transform: scale(0.93);
        }

        /* File Upload Button */
        #file-upload-btn {
            width: 40px;
            height: 40px;
            border: none;
            border-radius: 50%;
            background: #e8f6f5;
            color: var(--accent-color);
            font-size: 18px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background 0.18s, transform 0.15s;
            flex-shrink: 0;
        }

        #file-upload-btn:hover {
            background: #d0efed;
            transform: scale(1.07);
        }

        #file-upload-btn:active {
            transform: scale(0.93);
        }

        /* Mic button — same weight as send */
        #vm-mic-btn {
            width: 48px !important;
            height: 48px !important;
            border-radius: 50% !important;
            border: none !important;
            background: linear-gradient(135deg, var(--primary-color), var(--primary-light)) !important;
            color: #fff !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            cursor: pointer !important;
            flex-shrink: 0 !important;
            transition: transform 0.15s, box-shadow 0.15s !important;
            box-shadow: 0 3px 14px rgba(14,73,80,.35) !important;
        }
        #vm-mic-btn:hover  { transform: scale(1.07) !important; box-shadow: 0 5px 18px rgba(14,73,80,.45) !important; }
        #vm-mic-btn:active { transform: scale(0.93) !important; }
        #vm-mic-btn.vm-recording { background: #e63946 !important; box-shadow: 0 0 0 4px rgba(230,57,70,.25) !important; animation: vmMicPulse 1s infinite !important; }

        /* Modern Bottom Sheet Modal Styles */
        .file-upload-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(10, 30, 30, 0.55);
            backdrop-filter: blur(4px);
            z-index: 2000;
            align-items: flex-end;
            justify-content: center;
        }

        .file-upload-content {
            background: #fff;
            border-radius: 28px 28px 0 0;
            padding: 28px 22px 32px;
            width: 100%;
            max-width: 100%;
            text-align: center;
            box-shadow: 0 -12px 48px rgba(14, 73, 80, 0.18);
            animation: slideUpFromBottom 0.38s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            position: relative;
            overflow: hidden;
            max-height: 80vh;
            overflow-y: auto;
        }

        @keyframes slideUpFromBottom {
            from { opacity: 0; transform: translateY(100%); }
            to { opacity: 1; transform: translateY(0); }
        }

        .file-upload-content::before {
            content: '';
            position: absolute;
            top: 10px;
            left: 50%;
            transform: translateX(-50%);
            width: 36px;
            height: 4px;
            background: #ccd8d8;
            border-radius: 2px;
        }

        .file-upload-content h3 {
            margin-bottom: 6px;
            color: var(--primary-color);
            font-size: 20px;
            font-weight: 700;
            margin-top: 18px;
            letter-spacing: -0.02em;
        }

        .file-upload-subtitle {
            color: var(--text-secondary);
            font-size: 14px;
            margin-bottom: 24px;
        }

        .file-upload-options {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin: 20px 0;
        }

        .file-upload-option {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
            padding: 18px 10px;
            border: 1.5px solid var(--border-color);
            border-radius: 18px;
            cursor: pointer;
            transition: all 0.25s ease;
            background: #f7fafa;
        }

        .file-upload-option:hover {
            background: #eef6f6;
            border-color: var(--accent-color);
            transform: translateY(-3px);
            box-shadow: 0 6px 20px rgba(46, 196, 182, 0.15);
        }

        .option-icon {
            width: 52px;
            height: 52px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 26px;
            transition: all 0.25px ease;
        }

        .photo-option .option-icon { background: linear-gradient(135deg, #d4edda, #a8d8b0); }
        .video-option .option-icon { background: linear-gradient(135deg, #fde8c8, #f9c784); }
        .document-option .option-icon { background: linear-gradient(135deg, #dbeafe, #93c5fd); }

        .option-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-color);
        }

        .option-description {
            font-size: 10px;
            color: var(--light-text);
            line-height: 1.3;
        }

        .file-upload-info {
            margin-top: 18px;
            padding: 12px 16px;
            background: #f0f8f7;
            border-radius: 12px;
            border-left: 3px solid var(--accent-color);
        }

        .info-text {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 500;
        }

        #fileInput { display: none; }

        .modal-close-btn {
            position: absolute;
            top: 14px;
            right: 14px;
            background: #f0f4f4;
            border: none;
            font-size: 18px;
            color: var(--text-secondary);
            cursor: pointer;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
        }

        .modal-close-btn:hover {
            background: var(--border-color);
            color: var(--text-color);
        }

        /* Enhanced Media Message Styles */
        .media-message {
            max-width: 280px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .media-message:hover {
            transform: translateY(-2px);
        }

        .media-preview {
            border-radius: 14px;
            overflow: hidden;
            position: relative;
            transition: opacity 0.2s ease;
            cursor: pointer;
        }

        .media-preview:active {
            opacity: 0.85;
        }

        .media-preview img, .media-preview video {
            width: 100%;
            max-height: 280px;
            object-fit: cover;
            display: block;
            border-radius: 14px;
        }

        .media-info {
            padding: 8px 4px;
        }

        .media-filename {
            font-weight: 600;
            font-size: 13px;
            color: #333;
            margin-bottom: 4px;
            word-break: break-word;
            line-height: 1.3;
        }

        .media-metadata {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 11px;
            color: #666;
        }

        .media-size {
            font-weight: 500;
        }

        .media-type {
            background: #0E4950;
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: 600;
        }

        /* Enhanced File Message Styles */
        .file-message {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 16px;
            background: linear-gradient(135deg, #f8f9fa, #ffffff);
            border-radius: 16px;
            border: 1px solid #e9ecef;
            transition: all 0.3s ease;
        }

        .file-message:hover {
            background: linear-gradient(135deg, #ffffff, #f8f9fa);
            box-shadow: 0 6px 20px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }

        .file-icon {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            flex-shrink: 0;
        }

        .file-icon.photo { background: #E8F5E8; color: #4CAF50; }
        .file-icon.video { background: #FFF3E0; color: #FF9800; }
        .file-icon.document { background: #E3F2FD; color: #2196F3; }

        .file-info {
            flex: 1;
            min-width: 0;
        }

        .file-name {
            font-weight: 700;
            font-size: 14px;
            margin-bottom: 6px;
            word-break: break-word;
            color: #333;
            line-height: 1.3;
        }

        .file-details {
            display: flex;
            gap: 12px;
            align-items: center;
            font-size: 12px;
            color: #666;
        }

        .file-size {
            font-weight: 600;
            color: #0E4950;
        }

        .file-type {
            background: #0E4950;
            color: white;
            padding: 2px 8px;
            border-radius: 8px;
            font-size: 10px;
            font-weight: 600;
        }

        .download-btn {
            background: linear-gradient(135deg, #0E4950, #1a6b75);
            color: white;
            border: none;
            border-radius: 10px;
            padding: 10px 16px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            flex-shrink: 0;
        }

        .download-btn:hover {
            background: linear-gradient(135deg, #1a6b75, #0E4950);
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(14, 73, 80, 0.3);
        }

        .download-btn:active {
            transform: translateY(0);
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .file-upload-options {
                grid-template-columns: 1fr;
                gap: 10px;
            }
            
            .file-upload-option {
                flex-direction: row;
                justify-content: flex-start;
                padding: 12px 15px;
                gap: 15px;
            }
            
            .option-text {
                text-align: left;
            }
        }

        /* Rest of the existing styles remain the same */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(10, 30, 30, 0.55);
            backdrop-filter: blur(6px);
            justify-content: center;
            align-items: center;
            z-index: 1000;
            animation: fadeIn 0.2s ease-out;
        }

        .modal-content {
            background: #fff;
            padding: 28px 24px;
            border-radius: 20px;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 20px 60px rgba(14, 73, 80, 0.2);
            animation: slideUp 0.3s ease-out;
        }

        .modal h3 {
            margin-bottom: 18px;
            color: var(--primary-color);
            font-size: 18px;
            font-weight: 700;
            letter-spacing: -0.01em;
        }

        .modal input {
            width: 100%;
            padding: 13px 16px;
            border: 1.5px solid var(--border-color);
            border-radius: 12px;
            font-size: 15px;
            margin-bottom: 20px;
            outline: none;
            font-family: 'DM Sans', sans-serif;
            transition: border-color 0.2s, box-shadow 0.2s;
            background: #f8fafa;
            color: var(--text-color);
        }

        .modal input:focus {
            border-color: var(--accent-color);
            box-shadow: 0 0 0 3px rgba(46, 196, 182, 0.12);
            background: #fff;
        }

        .modal-buttons {
            display: flex;
            gap: 10px;
        }

        .modal-btn {
            flex: 1;
            padding: 13px;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.2s;
            font-family: 'DM Sans', sans-serif;
        }

        .modal-btn.primary {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-light));
            color: white;
            box-shadow: 0 4px 14px rgba(14, 73, 80, 0.25);
        }

        .modal-btn.primary:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(14, 73, 80, 0.35);
        }

        .modal-btn.secondary {
            background: #eef2f2;
            color: var(--text-secondary);
        }

        .modal-btn.secondary:hover {
            background: #e0e8e8;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .message-appear {
            animation: messageAppear 0.25s ease-out;
        }

        @keyframes messageAppear {
            from { opacity: 0; transform: translateY(8px) scale(0.98); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        #chat::-webkit-scrollbar { width: 4px; }
        #chat::-webkit-scrollbar-track { background: transparent; }
        #chat::-webkit-scrollbar-thumb {
            background: rgba(14, 73, 80, 0.2);
            border-radius: 4px;
        }
        #chat::-webkit-scrollbar-thumb:hover { background: rgba(14, 73, 80, 0.35); }

        .back-button {
            background: rgba(255,255,255,0.15);
            border: none;
            color: white;
            font-size: 18px;
            cursor: pointer;
            padding: 7px 10px;
            border-radius: 10px;
            transition: background 0.2s;
        }

        .back-button:hover { background: rgba(255,255,255,0.25); }

        /* Message Context Menu */
        .context-menu {
            position: fixed;
            background: rgba(255,255,255,0.96);
            border-radius: 16px;
            box-shadow: 0 12px 40px rgba(14, 73, 80, 0.18), 0 2px 8px rgba(0,0,0,0.08);
            z-index: 1000;
            min-width: 168px;
            padding: 6px 0;
            display: none;
            border: 1px solid rgba(14, 73, 80, 0.08);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            animation: contextMenuAppear 0.15s ease-out;
        }

        .context-menu-item {
            padding: 11px 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 14px;
            color: var(--text-color);
            transition: background 0.15s;
            user-select: none;
            -webkit-user-select: none;
            font-weight: 500;
        }

        .context-menu-item:hover { background: rgba(46, 196, 182, 0.08); }
        .context-menu-item:first-child { border-radius: 10px 10px 0 0; }
        .context-menu-item:last-child { border-radius: 0 0 10px 10px; }

        .context-menu-item i,
        .context-menu-item svg {
            font-size: 15px;
            width: 20px;
            text-align: center;
            color: var(--primary-color);
        }

        .context-menu-divider {
            height: 1px;
            background: rgba(14, 73, 80, 0.08);
            margin: 4px 0;
        }

        @keyframes contextMenuAppear {
            from { opacity: 0; transform: scale(0.92) translateY(-6px); }
            to { opacity: 1; transform: scale(1) translateY(0); }
        }

        /* Emoji Reaction Menu */
        .emoji-menu {
            position: fixed;
            background: rgba(255,255,255,0.96);
            border-radius: 28px;
            box-shadow: 0 10px 36px rgba(14, 73, 80, 0.18);
            z-index: 1001;
            padding: 8px 10px;
            display: none;
            animation: slideUp 0.2s ease-out;
            border: 1px solid rgba(14, 73, 80, 0.08);
            backdrop-filter: blur(16px);
        }

        .emoji-options { display: flex; gap: 4px; }

        .emoji-option {
            font-size: 22px;
            padding: 8px;
            cursor: pointer;
            border-radius: 50%;
            transition: all 0.18s;
        }

        .emoji-option:hover {
            background: rgba(46, 196, 182, 0.12);
            transform: scale(1.25);
        }

        /* Message Reactions */
        .message-reactions {
            display: flex;
            gap: 4px;
            margin-top: 5px;
            flex-wrap: wrap;
        }

        .reaction {
            background: rgba(14, 73, 80, 0.06);
            border-radius: 12px;
            padding: 2px 7px;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 3px;
            border: 1px solid rgba(14, 73, 80, 0.08);
        }

        .reaction-emoji { font-size: 13px; }
        .reaction-count { font-size: 10px; color: var(--text-secondary); font-weight: 600; }

        .bubble.selected {
            background: rgba(46, 196, 182, 0.08) !important;
            border-color: var(--accent-color) !important;
            box-shadow: 0 0 0 2px rgba(46, 196, 182, 0.2) !important;
        }

        /* Copy Feedback */
        .copy-feedback {
            position: fixed;
            background: rgba(14, 73, 80, 0.88);
            color: white;
            padding: 9px 18px;
            border-radius: 22px;
            font-size: 13px;
            font-weight: 600;
            z-index: 1002;
            animation: fadeInOut 2s ease-in-out;
            backdrop-filter: blur(8px);
        }

        @keyframes fadeInOut {
            0%, 100% { opacity: 0; transform: translateY(10px); }
            20%, 80% { opacity: 1; transform: translateY(0); }
        }

        /* Media Viewer */
        .media-viewer {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 3000;
            align-items: center;
            justify-content: center;
        }

        .media-viewer-content {
            max-width: 90%;
            max-height: 90%;
            position: relative;
        }

        .media-viewer-content img,
        .media-viewer-content video {
            max-width: 100%;
            max-height: 90vh;
            border-radius: 8px;
        }

        .close-viewer {
            position: absolute;
            top: -40px;
            right: 0;
            background: none;
            border: none;
            color: white;
            font-size: 24px;
            cursor: pointer;
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        @media (max-width: 768px) {
            #chat-header {
                padding: 14px 16px;
            }

            #chat {
                padding: 16px;
            }

            .message-group {
                max-width: 90%;
            }

            #message-box {
                padding: 14px 16px;
                min-height: 65px;
            }

            #message {
                min-height: 44px;
                max-height: 100px;
            }

            #saveBtn {
                width: 34px;
                height: 34px;
                padding: 6px;
            }

            .context-menu {
                min-width: 140px;
            }

            .emoji-menu {
                padding: 6px;
            }

            .emoji-option {
                font-size: 18px;
                padding: 6px;
            }

            .media-message {
                max-width: 250px;
            }
        }

        @media (max-width: 480px) {
            .contact-avatar {
                width: 36px;
                height: 36px;
                font-size: 16px;
            }

            .contact-name {
                font-size: 16px;
            }

            .bubble {
                padding: 10px 14px;
                font-size: 14px;
            }

            #message {
                padding: 10px 16px;
                font-size: 15px;
                min-height: 42px;
                max-height: 90px;
            }

            #send-btn, #file-upload-btn {
                width: 44px;
                height: 44px;
            }

            #message-box {
                min-height: 60px;
            }            #saveBtn {
                width: 32px;
                height: 32px;
                padding: 5px;
            }

            .media-message {
                max-width: 200px;
            }

            .file-message {
                padding: 12px;
                gap: 12px;
            }
            
            .file-icon {
                width: 40px;
                height: 40px;
                font-size: 20px;
            }
        }

        /* Loading Indicator */
        .loading-indicator {
            text-align: center;
            padding: 12px;
            color: var(--light-text);
            font-size: 13px;
            font-style: italic;
        }

        .loading-indicator.hidden { display: none; }

        .message-group .bubble:first-child { margin-top: 0; }
        .message-group .bubble:last-child { margin-bottom: 0; }

        /* ── Voice Message Styles ── */
        #vm-overlay{display:none;position:fixed;inset:0;z-index:9000;background:rgba(14,73,80,0.94);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);flex-direction:column;align-items:center;justify-content:center;gap:22px;}
        #vm-overlay.active{display:flex;}
        #vm-rec-timer{font-size:54px;font-weight:700;color:#fff;letter-spacing:-2px;font-variant-numeric:tabular-nums;font-family:'DM Mono',monospace;}
        #vm-rec-label{font-size:11px;font-weight:600;color:rgba(255,255,255,.6);text-transform:uppercase;letter-spacing:3px;}
        #vm-live-canvas{width:280px;height:60px;border-radius:12px;}
        .vm-dot{width:10px;height:10px;border-radius:50%;background:#ff4d4d;animation:vmPulse 1.1s ease-in-out infinite;}
        @keyframes vmPulse{0%,100%{transform:scale(1);opacity:1;}50%{transform:scale(1.6);opacity:.4;}}
        #vm-cancel-hint{font-size:12px;color:rgba(255,255,255,.4);display:flex;align-items:center;gap:5px;}
        .vm-rec-actions{display:flex;gap:28px;margin-top:6px;}
        .vm-act-btn{width:62px;height:62px;border-radius:50%;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:transform .14s;}
        .vm-act-btn:active{transform:scale(.9);}
        #vm-cancel-act{background:rgba(255,255,255,.14);color:#fff;}
        #vm-send-act{background:#fff;color:var(--primary-color);box-shadow:0 6px 22px rgba(0,0,0,.26);}
        #vm-mic-btn.vm-recording{background:#e63946;animation:vmMicPulse 1s infinite;}
        @keyframes vmMicPulse{0%,100%{box-shadow:0 0 0 0 rgba(230,57,70,.55);}50%{box-shadow:0 0 0 10px rgba(230,57,70,0);}}
        .vm-bubble{display:flex;align-items:center;gap:10px;padding:10px 13px;border-radius:20px;max-width:300px;min-width:210px;font-family:'DM Sans',sans-serif;user-select:none;position:relative;}
        .vm-bubble.vm-out{background:linear-gradient(135deg,#d4f5ef,#c8ede7);border-bottom-right-radius:5px;border:1px solid rgba(46,196,182,.2);box-shadow:0 1px 4px rgba(14,73,80,.08);margin-left:auto;}
        .vm-bubble.vm-in{background:#fff;border-bottom-left-radius:5px;border:1px solid #e8eeee;box-shadow:0 1px 4px rgba(0,0,0,.05);}
        .vm-bubble.vm-uploading::after{content:'';position:absolute;inset:0;border-radius:inherit;background:linear-gradient(90deg,transparent,rgba(255,255,255,.3),transparent);background-size:200% 100%;animation:vmShimmer 1.3s infinite;}
        @keyframes vmShimmer{0%{background-position:-200% 0;}100%{background-position:200% 0;}}
        .vm-play{width:38px;height:38px;border-radius:50%;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:transform .14s;}
        .vm-play:active{transform:scale(.9);}
        .vm-bubble.vm-out .vm-play{background:rgba(14,73,80,.13);color:var(--primary-color);}
        .vm-bubble.vm-in .vm-play{background:#e0f2f4;color:var(--primary-color);}
        .vm-ww{flex:1;display:flex;flex-direction:column;gap:4px;min-width:0;}
        .vm-wave{display:flex;align-items:center;gap:2px;height:30px;cursor:pointer;}
        .vm-bar{flex:1;border-radius:2px;min-width:2px;transition:background .1s;}
        .vm-bubble.vm-out .vm-bar{background:rgba(14,73,80,.22);}
        .vm-bubble.vm-out .vm-bar.vm-p{background:var(--primary-color);}
        .vm-bubble.vm-in .vm-bar{background:rgba(14,73,80,.18);}
        .vm-bubble.vm-in .vm-bar.vm-p{background:var(--primary-color);}
        .vm-meta{display:flex;justify-content:space-between;align-items:center;font-size:10px;opacity:.7;}
        .vm-dur{font-variant-numeric:tabular-nums;font-weight:500;}
        .vm-ticks{display:flex;gap:1px;align-items:center;}
        .vm-tick{width:9px;height:5px;border-bottom:2px solid currentColor;border-right:2px solid currentColor;transform:rotate(45deg) translate(-1px,-2px);opacity:.4;display:inline-block;transition:opacity .25s,color .25s;}
        .vm-tick.vm-on{opacity:1;}
        .vm-ticks.vm-heard .vm-tick{color:#4fc3f7;opacity:1;}
        /* Voice message reaction wrapper */
        .vm-react-wrap{display:flex;flex-direction:column;max-width:300px;}
        .vm-react-wrap.vm-out{align-items:flex-end;margin-left:auto;}
        .vm-react-wrap.vm-in{align-items:flex-start;}
        .vm-react-wrap .message-reactions{margin-top:3px;margin-left:4px;margin-right:4px;}
    </style>
</head>
<body>
    <div id="chat-header">
        <div class="left-header-actions">
            <button class="back-button" onclick="goBack()">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
            </button>
        </div>

        <div id="contact-info" onclick="{% if contact_name != contact_phone %}openAvatarLightbox(){% else %}openSaveModal(){% endif %}" style="cursor:pointer;">
            {% if contact_name == contact_phone %}
                <div class="contact-avatar contact-avatar-unsaved" title="Tap to save contact">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>
                </div>
            {% else %}
                <div class="contact-avatar" id="chatHeaderAvatar">{{ contact_name[0] if contact_name else '?' }}</div>
            {% endif %}
            <div class="contact-details">
                <div class="contact-name">{{ contact_name }}</div>
                <div class="connection-status">
                    <span class="status-dot status-offline" id="statusDot"></span>
                    <span id="statusText">Loading…</span>
                </div>
            </div>
        </div>

        <div class="header-actions"></div>
    </div>

    <div id="chat-container">
        <div id="chat">
            <div id="loadingIndicator" class="loading-indicator hidden">Loading more messages...</div>
        </div>
        <div id="typing"></div>
    </div>

    <!-- Voice Recording Overlay -->
    <div id="vm-overlay">
        <div style="display:flex;align-items:center;gap:10px;">
            <div class="vm-dot"></div>
            <span id="vm-rec-label">RECORDING</span>
        </div>
        <canvas id="vm-live-canvas" width="560" height="120"></canvas>
        <div id="vm-rec-timer">0:00</div>
        <div id="vm-cancel-hint">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            Tap ✕ to cancel &nbsp;·&nbsp; ✓ to send
        </div>
        <div class="vm-rec-actions">
            <button class="vm-act-btn" id="vm-cancel-act" onclick="VM.cancel()">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
            <button class="vm-act-btn" id="vm-send-act" onclick="VM.stopAndSend()">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
            </button>
        </div>
    </div>

    <div id="message-box">
        <button id="file-upload-btn" onclick="openFileUploadModal()" title="Send file">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke="currentColor" stroke-width="2"/>
                <polyline points="14,2 14,8 20,8" stroke="currentColor" stroke-width="2"/>
                <line x1="16" y1="13" x2="8" y2="13" stroke="currentColor" stroke-width="2"/>
                <line x1="16" y1="17" x2="8" y2="17" stroke="currentColor" stroke-width="2"/>
            </svg>
        </button>
        <textarea id="message" placeholder="Type a message..." rows="1"></textarea>
        <button id="vm-mic-btn" onclick="VM.toggle()" title="Voice message">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
                <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
                <line x1="12" y1="19" x2="12" y2="23"/>
                <line x1="8" y1="23" x2="16" y2="23"/>
            </svg>
        </button>
        <button id="send-btn" onclick="sendMessage()">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" fill="white"/>
            </svg>
        </button>
    </div>

    <!-- Modern Bottom Sheet File Upload Modal -->
    <div id="fileUploadModal" class="file-upload-modal">
        <div class="file-upload-content">
            <button class="modal-close-btn" onclick="closeFileUploadModal()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
            <h3>Share File</h3>
            <div class="file-upload-subtitle">Choose what you'd like to share</div>
            
            <div class="file-upload-options">
                <div class="file-upload-option photo-option" onclick="triggerFileInput('image')">
                    <div class="option-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg></div>
                    <div class="option-text">
                        <div class="option-title">Photos</div>
                        <div class="option-description">JPG, PNG, GIF</div>
                    </div>
                </div>
                <div class="file-upload-option video-option" onclick="triggerFileInput('video')">
                    <div class="option-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg></div>
                    <div class="option-text">
                        <div class="option-title">Videos</div>
                        <div class="option-description">MP4, MOV, AVI</div>
                    </div>
                </div>
                <div class="file-upload-option document-option" onclick="triggerFileInput('document')">
                    <div class="option-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg></div>
                    <div class="option-text">
                        <div class="option-title">Documents</div>
                        <div class="option-description">PDF, DOC, TXT</div>
                    </div>
                </div>
            </div>
            
            <input type="file" id="fileInput" accept="*/*">
            
            <div class="file-upload-info">
                <div class="info-text">
                    <span>Max file size: 16MB • All files are securely encrypted</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Save Contact Modal -->
    <!-- Avatar Lightbox -->
    <div id="avatarLightbox" onclick="closeAvatarLightbox()" style="display:none;position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,0.88);align-items:center;justify-content:center;backdrop-filter:blur(6px);opacity:0;transition:opacity 0.22s ease;">
        <div id="avatarLightboxInner" style="transform:scale(0.82);transition:transform 0.25s cubic-bezier(.34,1.56,.64,1);max-width:88vw;max-height:88vw;">
        </div>
    </div>

    <div id="saveModal" class="modal">
        <div class="modal-content">
            <h3>Save Contact</h3>
            <form id="saveContactForm">
                <input type="hidden" name="user" value="{{ phone }}">
                <input type="hidden" name="country_code" value="">
                <input type="hidden" name="contact_phone" value="{{ contact_phone }}">
                <input type="text" name="contact_name" placeholder="Enter name" required>
                <div class="modal-buttons">
                    <button type="submit" class="modal-btn primary">Save</button>
                    <button type="button" onclick="closeSaveModal()" class="modal-btn secondary">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Context Menu -->
    <div id="contextMenu" class="context-menu">
        <div class="context-menu-item" id="ctxCopy" onclick="copyMessage()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            <span>Copy</span>
        </div>
        <div class="context-menu-item" onclick="showEmojiMenu()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>
            <span>React</span>
        </div>
        <div class="context-menu-item" id="ctxDelete" onclick="showDeleteSheet()" style="color:#e53935;display:none;">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#e53935" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
            <span>Delete</span>
        </div>
    </div>

    <!-- WhatsApp-style Delete Sheet -->
    <div id="deleteSheet" style="display:none;position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,0.45);align-items:flex-end;justify-content:center;">
        <div style="background:#fff;border-radius:20px 20px 0 0;width:100%;padding:20px 0 calc(20px + env(safe-area-inset-bottom,0px));box-shadow:0 -4px 30px rgba(0,0,0,0.15);">
            <div style="text-align:center;font-size:13px;color:#888;padding-bottom:14px;border-bottom:1px solid #f0f0f0;margin-bottom:4px;">Delete message</div>
            <button id="dsDeleteForMe" onclick="commitDelete('me')"
                style="display:flex;align-items:center;gap:14px;width:100%;padding:15px 24px;border:none;background:none;font-size:16px;color:#1a2e2f;cursor:pointer;font-family:inherit;">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                Delete for me
            </button>
            <button id="dsDeleteForAll" onclick="commitDelete('everyone')"
                style="display:flex;align-items:center;gap:14px;width:100%;padding:15px 24px;border:none;background:none;font-size:16px;color:#e53935;cursor:pointer;font-family:inherit;">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#e53935" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                Delete for everyone
            </button>
            <button onclick="closeDeleteSheet()"
                style="display:flex;align-items:center;justify-content:center;width:100%;padding:15px 24px;border:none;background:none;font-size:16px;color:#888;cursor:pointer;font-family:inherit;border-top:1px solid #f0f0f0;margin-top:4px;">
                Cancel
            </button>
        </div>
    </div>

    <!-- Emoji Reaction Menu -->
    <div id="emojiMenu" class="emoji-menu">
        <div class="emoji-options">
            <div class="emoji-option" data-emoji="👍">👍</div>
            <div class="emoji-option" data-emoji="❤️">❤️</div>
            <div class="emoji-option" data-emoji="😂">😂</div>
            <div class="emoji-option" data-emoji="😮">😮</div>
            <div class="emoji-option" data-emoji="😢">😢</div>
            <div class="emoji-option" data-emoji="🙏">🙏</div>
        </div>
    </div>

    <!-- Media Viewer -->
    <div id="mediaViewer" class="media-viewer">
        <div class="media-viewer-content">
            <button class="close-viewer" onclick="closeMediaViewer()"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
            <img id="viewerImage" src="" alt="">
            <video id="viewerVideo" controls style="display: none;"></video>
        </div>
    </div>

    <script src="https://cdn.socket.io/4.7.2/socket.io.min.js" crossorigin="anonymous"></script>
    <script>
        let myPhone = {{ phone|tojson }};
        let contactPhone = {{ contact_phone|tojson }};
        const typingDiv = document.getElementById('typing');
        let chatDiv = document.getElementById('chat');
        const messageInput = document.getElementById('message');
        const messageBox = document.getElementById('message-box');
        const statusDot = document.getElementById('statusDot');
        const statusText = document.getElementById('statusText');
        const contextMenu = document.getElementById('contextMenu');
        const emojiMenu = document.getElementById('emojiMenu');
        const fileInput = document.getElementById('fileInput');
        const fileUploadModal = document.getElementById('fileUploadModal');
        const mediaViewer = document.getElementById('mediaViewer');
        const viewerImage = document.getElementById('viewerImage');
        const viewerVideo = document.getElementById('viewerVideo');
        const loadingIndicator = document.getElementById('loadingIndicator');
        
        let typingTimeout;
        let isConnected = false;
        let lastSender = null;
        let messageGroups = {};
        let groupCounter = 0;
        let currentGroupKey = null;
        let lastMarkedSeenTime = 0;
        let selectedMessage = null;
        let selectedMessageId = null;
        let contextMenuMessageId = null;

        // Enhanced variables for better performance
        let currentPage = 1;
        let isLoading = false;
        let hasMoreMessages = true;
        let scrollPositionBeforeLoad = 0;

        // Context Menu Variables
        let pressTimer;
        let longPressActive = false;

        function goBack() {
            window.location.href = '/main?phone=' + encodeURIComponent(myPhone);
        }

        function autoResizeTextarea() {
            messageInput.style.height = 'auto';
            const scrollHeight = messageInput.scrollHeight;
            const maxHeight = 120;
            if (scrollHeight <= maxHeight) {
                messageInput.style.height = scrollHeight + 'px';
                messageBox.style.minHeight = Math.max(70, scrollHeight + 22) + 'px';
            } else {
                messageInput.style.height = maxHeight + 'px';
                messageInput.style.overflowY = 'auto';
                messageBox.style.minHeight = '140px';
            }
            scrollToBottom(false);
        }

        messageInput.addEventListener('input', autoResizeTextarea);
        messageInput.addEventListener('keydown', autoResizeTextarea);
        messageInput.addEventListener('keyup', autoResizeTextarea);
        messageInput.addEventListener('focus', function() {
            setTimeout(autoResizeTextarea, 10);
        });

        function resetTextareaHeight() {
            setTimeout(() => {
                messageInput.style.height = 'auto';
                messageInput.style.overflowY = 'hidden';
                messageBox.style.minHeight = '70px';
            }, 100);
        }

        // ==================== FIXED CONTEXT MENU SYSTEM ====================
        function initializeContextMenuSystem() {
            console.log('Initializing fixed context menu system...');
            
            // Remove any existing event listeners first
            document.removeEventListener('contextmenu', handleContextMenu);
            document.removeEventListener('touchstart', handleTouchStart);
            document.removeEventListener('touchend', handleTouchEnd);
            document.removeEventListener('touchmove', handleTouchMove);
            
            // Add new event listeners
            document.addEventListener('contextmenu', handleContextMenu);
            document.addEventListener('touchstart', handleTouchStart);
            document.addEventListener('touchend', handleTouchEnd);
            document.addEventListener('touchmove', handleTouchMove);
            
            console.log('Fixed context menu system initialized');
        }

        function handleContextMenu(e) {
            const bubble = e.target.closest('.bubble, .vm-bubble, .gvm-bubble');
            if (bubble) {
                // Get messageId from bubble itself or its vm-react-wrap parent
                const msgId = bubble.dataset.messageId ||
                    (bubble.parentElement && bubble.parentElement.dataset.messageId) || null;
                if (msgId) {
                    e.preventDefault();
                    e.stopPropagation();
                    // Pass the vm-react-wrap as the "bubble" target so showEmojiMenu positions correctly
                    const target = (bubble.classList.contains('vm-bubble') && bubble.parentElement &&
                        bubble.parentElement.classList.contains('vm-react-wrap'))
                        ? bubble.parentElement : bubble;
                    showContextMenu(e.clientX, e.clientY, msgId, target);
                }
            }
        }

        function handleTouchStart(e) {
            const bubble = e.target.closest('.bubble, .vm-bubble, .gvm-bubble');
            if (bubble) {
                const msgId = bubble.dataset.messageId ||
                    (bubble.parentElement && bubble.parentElement.dataset.messageId) || null;
                if (msgId) {
                    longPressActive = true;
                    pressTimer = setTimeout(() => {
                        const touch = e.touches[0];
                        const target = (bubble.classList.contains('vm-bubble') && bubble.parentElement &&
                            bubble.parentElement.classList.contains('vm-react-wrap'))
                            ? bubble.parentElement : bubble;
                        showContextMenu(touch.clientX, touch.clientY, msgId, target);
                        longPressActive = false;
                        e.preventDefault();
                    }, 500);
                }
            }
        }

        function handleTouchEnd(e) {
            // Don't cancel anything if the user is tapping inside the emoji menu
            if (emojiMenu.style.display === 'block' && emojiMenu.contains(e.target)) return;
            clearTimeout(pressTimer);
            longPressActive = false;
        }

        function handleTouchMove(e) {
            if (emojiMenu.style.display === 'block' && emojiMenu.contains(e.target)) return;
            clearTimeout(pressTimer);
            longPressActive = false;
        }

        function showContextMenu(x, y, messageId, bubble) {
            // Hide any existing menus immediately (clear all state for a fresh open)
            hideContextMenu(true);
            hideEmojiMenu(true);
            
            selectedMessage = bubble;
            selectedMessageId = messageId;
            contextMenuMessageId = messageId;

            // Determine if this is a voice message and if it's the user's own message
            const isVoice = bubble.classList.contains('vm-react-wrap') ||
                            bubble.classList.contains('vm-bubble') ||
                            !!bubble.querySelector('.vm-bubble');
            const isOwn = bubble.classList.contains('vm-out') ||
                          bubble.classList.contains('sent') ||
                          !!bubble.querySelector('.vm-out') ||
                          !!bubble.querySelector('.out');

            // Show/hide Copy vs Delete
            const ctxCopy = document.getElementById('ctxCopy');
            const ctxDelete = document.getElementById('ctxDelete');
            if (ctxCopy) ctxCopy.style.display = isVoice ? 'none' : '';
            // Show Delete for ANY own message (text, media, voice)
            if (ctxDelete) ctxDelete.style.display = isOwn ? '' : 'none';
            
            // Position calculation
            const menuWidth = 160;
            const menuHeight = 180;
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            
            let adjustedX = Math.min(x, viewportWidth - menuWidth - 10);
            let adjustedY = Math.min(y, viewportHeight - menuHeight - 10);
            
            // Show menu immediately
            contextMenu.style.display = 'block';
            contextMenu.style.left = adjustedX + 'px';
            contextMenu.style.top = adjustedY + 'px';
            
            // Select bubble
            document.querySelectorAll('.bubble.selected, .vm-react-wrap.selected').forEach(b => b.classList.remove('selected'));
            bubble.classList.add('selected');
            
            console.log('Context menu shown for message:', messageId);
        }

        function hideContextMenu(clearState = true) {
            contextMenu.style.display = 'none';
            if (clearState) {
                if (selectedMessage) {
                    selectedMessage.classList.remove('selected');
                    selectedMessage = null;
                }
                contextMenuMessageId = null;
            }
        }

        function hideEmojiMenu(clearState = true) {
            emojiMenu.style.display = 'none';
            if (clearState) {
                if (selectedMessage) {
                    selectedMessage.classList.remove('selected');
                    selectedMessage = null;
                }
                contextMenuMessageId = null;
            }
        }

        function showEmojiMenu() {
            if (!selectedMessage || !contextMenuMessageId) return;
            
            const rect = selectedMessage.getBoundingClientRect();
            const menuWidth = 240;
            const menuHeight = 60;
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            
            let adjustedX = rect.left + rect.width / 2 - menuWidth / 2;
            let adjustedY = rect.top - menuHeight - 10;
            
            if (adjustedX < 10) adjustedX = 10;
            if (adjustedX + menuWidth > viewportWidth) adjustedX = viewportWidth - menuWidth - 10;
            if (adjustedY < 10) adjustedY = rect.bottom + 10;
            
            emojiMenu.style.display = 'block';
            emojiMenu.style.left = adjustedX + 'px';
            emojiMenu.style.top = adjustedY + 'px';

            // Hide the context menu visually but keep contextMenuMessageId and selectedMessage intact
            hideContextMenu(false);
        }

        function copyMessage() {
            if (!selectedMessage) return;
            
            const messageContent = selectedMessage.querySelector('div:first-child');
            if (messageContent) {
                const textToCopy = messageContent.textContent;
                navigator.clipboard.writeText(textToCopy).then(() => {
                    showCopyFeedback('Copied to clipboard!');
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                    showCopyFeedback('Copy failed!');
                });
            }
            
            hideContextMenu();
        }

        function showCopyFeedback(message) {
            const feedback = document.createElement('div');
            feedback.className = 'copy-feedback';
            feedback.textContent = message;
            feedback.style.left = '50%';
            feedback.style.top = '50%';
            feedback.style.transform = 'translate(-50%, -50%)';
            document.body.appendChild(feedback);
            
            setTimeout(() => {
                document.body.removeChild(feedback);
            }, 2000);
        }

        // Stash for delete sheet (survives hideContextMenu clearing selectedMessage)
        let _deleteSheetMsgId = null;
        let _deleteSheetEl    = null;
        let _deleteSheetVoice = false;

        function showDeleteSheet() {
            if (!contextMenuMessageId || !selectedMessage) return;

            // Save state BEFORE hideContextMenu wipes it
            _deleteSheetMsgId = contextMenuMessageId;
            _deleteSheetEl    = selectedMessage;
            _deleteSheetVoice = _deleteSheetEl.classList.contains('vm-react-wrap') ||
                                _deleteSheetEl.classList.contains('vm-bubble') ||
                                !!_deleteSheetEl.querySelector('.vm-bubble');

            // hideContextMenu(false) hides the menu visually but keeps selectedMessage intact;
            // pass false so we don't null it out before we've stashed it above.
            hideContextMenu(false);
            contextMenu.style.display = 'none';

            // "Delete for everyone" only for own messages
            const isOwn = _deleteSheetEl.classList.contains('out') ||
                          _deleteSheetEl.classList.contains('sent') ||
                          _deleteSheetEl.classList.contains('vm-out') ||
                          !!_deleteSheetEl.querySelector('.out') ||
                          !!_deleteSheetEl.querySelector('.vm-out');
            const dsAll = document.getElementById('dsDeleteForAll');
            if (dsAll) dsAll.style.display = isOwn ? 'flex' : 'none';

            document.getElementById('deleteSheet').style.display = 'flex';
        }

        function closeDeleteSheet() {
            document.getElementById('deleteSheet').style.display = 'none';
            _deleteSheetMsgId = null;
            _deleteSheetEl    = null;
            _deleteSheetVoice = false;
            if (selectedMessage) { selectedMessage.classList.remove('selected'); selectedMessage = null; }
            contextMenuMessageId = null;
        }

        function commitDelete(scope) {
            const messageId = _deleteSheetMsgId;
            const el        = _deleteSheetEl;
            const isVoice   = _deleteSheetVoice;
            closeDeleteSheet();

            if (!messageId || !el) return;

            // Optimistically remove only this bubble, then clean up empty group
            const group = el.closest('.message-group');
            el.remove();
            if (group && group.children.length === 0) group.remove();

            const endpoint = isVoice ? '/api/voice/delete' : '/api/message/delete';
            const body = isVoice
                ? { id: messageId, user_phone: String(myPhone) }
                : { id: messageId, user_phone: String(myPhone), scope };

            fetch(endpoint, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(body)
            }).then(r => r.json()).then(data => {
                if (!data.success) showToast('Could not delete message.');
            }).catch(() => showToast('Could not delete message.'));
        }

        // Keep legacy alias
        function deleteMessage() { showDeleteSheet(); }

        function addReaction(emoji) {
            if (!contextMenuMessageId) return;

            const messageId = contextMenuMessageId;

            // Skip temp messages - no DB ID yet
            if (String(messageId).startsWith('temp_') || String(messageId).startsWith('vmtmp_') || String(messageId).startsWith('gvmtmp_')) {
                hideEmojiMenu();
                showToast('Cannot react before message is sent.');
                return;
            }

            // Strip the "vm-" DOM prefix to get the real DB integer ID for the server
            const isVoiceReaction = String(messageId).startsWith('vm-');
            const dbMessageId = isVoiceReaction ? String(messageId).slice(3) : messageId;

            // Optimistic UI update immediately (server will confirm shortly)
            updateReactionsOnBubble(messageId, String(myPhone), emoji, 'optimistic');

            socket.emit('add_reaction', {
                message_id: dbMessageId,
                emoji: emoji,
                user_phone: myPhone,
                is_voice: isVoiceReaction
            });

            hideEmojiMenu(true);
        }

        function updateReactionsOnBubble(messageId, reactingUser, emoji, source, serverReactions) {
            // Only vm-react-wrap elements carry data-message-id (vm-bubble does NOT),
            // so querySelector always returns the right element unambiguously.
            const el = document.querySelector('[data-message-id="' + String(messageId) + '"]');
            if (!el) return;

            const isVoiceWrap = el.classList.contains('vm-react-wrap');
            let container = el.querySelector('.message-reactions');

            // ── Server update: replace reactions wholesale ──────────────
            if (source === 'server' && serverReactions) {
                if (container) container.remove();
                if (serverReactions.length > 0) {
                    const rc = createReactionsElement(serverReactions);
                    if (isVoiceWrap) {
                        el.appendChild(rc);
                    } else {
                        const anchor = el.querySelector('.status') || el.querySelector('.message-time') || null;
                        if (anchor) el.insertBefore(rc, anchor);
                        else el.appendChild(rc);
                    }
                }
                return;
            }

            // ── Optimistic update ───────────────────────────────────────
            if (!container) {
                container = document.createElement('div');
                container.className = 'message-reactions';
                if (isVoiceWrap) {
                    el.appendChild(container);
                } else {
                    const anchor = el.querySelector('.status') || el.querySelector('.message-time') || null;
                    if (anchor) el.insertBefore(container, anchor);
                    else el.appendChild(container);
                }
            }

            const allPips = Array.from(container.querySelectorAll('.reaction'));
            const myPip   = allPips.find(p => p.dataset.reactingUser === String(reactingUser));

            if (myPip) {
                const sameEmoji = myPip.dataset.emoji === emoji;
                const oldCountEl = myPip.querySelector('.reaction-count');
                const oldCount = parseInt(oldCountEl.textContent) - 1;
                if (oldCount <= 0) {
                    myPip.remove();
                } else {
                    oldCountEl.textContent = oldCount;
                    myPip.dataset.reactingUser = '';
                }
                // Toggle-off: same emoji tapped again → just remove
                if (sameEmoji) {
                    if (container.children.length === 0) container.remove();
                    return;
                }
            }

            // Add or increment the newly chosen emoji
            const freshPips = Array.from(container.querySelectorAll('.reaction'));
            const targetPip = freshPips.find(p => p.dataset.emoji === emoji);
            if (targetPip) {
                const countEl = targetPip.querySelector('.reaction-count');
                countEl.textContent = parseInt(countEl.textContent) + 1;
                targetPip.dataset.reactingUser = String(reactingUser);
            } else {
                const pip = document.createElement('div');
                pip.className = 'reaction';
                pip.dataset.emoji = emoji;
                pip.dataset.reactingUser = String(reactingUser);
                pip.innerHTML = '<span class="reaction-emoji">' + emoji + '</span><span class="reaction-count">1</span>';
                container.appendChild(pip);
            }

            if (container.children.length === 0) container.remove();
        }

        // ==================== ENHANCED MESSAGE LOADING ====================
        function onChatScroll() {
            if (chatDiv.scrollTop < 100 && !isLoading && hasMoreMessages) {
                loadMoreMessages();
            }
        }

        function setupInfiniteScroll() {
            chatDiv.removeEventListener('scroll', onChatScroll);
            chatDiv.addEventListener('scroll', onChatScroll);
        }

        async function loadMoreMessages() {
            if (isLoading || !hasMoreMessages) return;
            
            isLoading = true;
            currentPage++;
            scrollPositionBeforeLoad = chatDiv.scrollHeight - chatDiv.scrollTop;
            
            loadingIndicator.classList.remove('hidden');
            
            try {
                const response = await fetch(`/api/get_messages?user_phone=${encodeURIComponent(myPhone)}&contact_phone=${encodeURIComponent(contactPhone)}&page=${currentPage}&limit=50`);
                const newMessages = await response.json();
                
                if (newMessages.length === 0) {
                    hasMoreMessages = false;
                    loadingIndicator.textContent = 'No more messages';
                    return;
                }
                
                // Prepend messages to chat
                prependMessages(newMessages);
                
                // Restore scroll position
                const newScrollHeight = chatDiv.scrollHeight;
                chatDiv.scrollTop = newScrollHeight - scrollPositionBeforeLoad;
                
            } catch (error) {
                console.error('Error loading more messages:', error);
                currentPage--; // Revert page on error
            } finally {
                isLoading = false;
                loadingIndicator.classList.add('hidden');
                
                // Re-initialize context menu for new messages
                setTimeout(initializeContextMenuSystem, 100);
            }
        }

        function prependMessages(messages) {
            const fragment = document.createDocumentFragment();
            let currentGroup = null;
            let lastMessageSender = null;

            messages.forEach(message => {
                if (message.sender !== lastMessageSender) {
                    currentGroup = createMessageGroup(message.sender === String(myPhone));
                    fragment.appendChild(currentGroup);
                }
                if (message.message_type === 'text') {
                    const messageElement = createTextMessage(message);
                    currentGroup.appendChild(messageElement);
                } else {
                    const messageElement = createMediaMessage(message);
                    currentGroup.appendChild(messageElement);
                }
                lastMessageSender = message.sender;
            });

            chatDiv.prepend(fragment);
        }

        function createMessageGroup(isSent) {
            const group = document.createElement('div');
            group.className = `message-group ${isSent ? 'sent-group' : 'received-group'}`;
            return group;
        }

        function createTextMessage(message) {
            const bubble = document.createElement('div');
            bubble.className = `bubble ${message.sender === String(myPhone) ? 'sent' : 'received'} message-appear`;
            
            // Use database ID or temp ID
            if (message.id && message.id !== 'null' && !message.id.toString().startsWith('temp_')) {
                bubble.dataset.messageId = message.id;
                console.log(' Message with DB ID:', message.id);
            } else {
                const tempId = 'temp_' + Date.now();
                bubble.dataset.messageId = tempId;
                console.log('Message with temp ID:', tempId);
            }

            const messageContent = document.createElement('div');
            messageContent.textContent = message.message;
            bubble.appendChild(messageContent);

            // Add reactions if any
            if (message.reactions && message.reactions.length > 0) {
                bubble.appendChild(createReactionsElement(message.reactions));
            }

            // Add status and time
            if (message.sender === String(myPhone)) {
                bubble.appendChild(createStatusElement(message.status));
            }
            bubble.appendChild(createTimeElement());

            return bubble;
        }

        function createMediaMessage(message) {
            const bubble = document.createElement('div');
            bubble.className = `bubble ${message.sender === String(myPhone) ? 'sent' : 'received'} media-message message-appear`;
            
            // Use database ID or temp ID
            if (message.id && message.id !== 'null' && !message.id.toString().startsWith('temp_')) {
                bubble.dataset.messageId = message.id;
                console.log('Media message with DB ID:', message.id);
            } else {
                const tempId = 'temp_' + Date.now();
                bubble.dataset.messageId = tempId;
                console.log('Media message with temp ID:', tempId);
            }

            // Media content will be added here based on message type
            if (message.message_type === 'image') {
                bubble.appendChild(createImageMessage(message));
            } else if (message.message_type === 'video') {
                bubble.appendChild(createVideoMessage(message));
            } else {
                bubble.appendChild(createFileMessage(message));
            }

            // Add reactions if any
            if (message.reactions && message.reactions.length > 0) {
                bubble.appendChild(createReactionsElement(message.reactions));
            }

            // Add status and time
            if (message.sender === String(myPhone)) {
                bubble.appendChild(createStatusElement(message.status));
            }
            bubble.appendChild(createTimeElement());

            return bubble;
        }

        function createReactionsElement(reactions) {
            const container = document.createElement('div');
            container.className = 'message-reactions';

            // Group by emoji, tracking which users reacted with each
            const emojiMap = {};
            reactions.forEach(reaction => {
                if (!emojiMap[reaction.emoji]) emojiMap[reaction.emoji] = [];
                emojiMap[reaction.emoji].push(reaction.user_phone);
            });

            Object.entries(emojiMap).forEach(([emoji, users]) => {
                const pip = document.createElement('div');
                pip.className = 'reaction';
                pip.dataset.emoji = emoji;
                // Track current user so optimistic updates work after server sync
                if (users.map(String).includes(String(myPhone))) pip.dataset.reactingUser = String(myPhone);
                pip.innerHTML = '<span class="reaction-emoji">' + emoji + '</span><span class="reaction-count">' + users.length + '</span>';
                container.appendChild(pip);
            });

            return container;
        }

        function createStatusElement(status) {
            const statusDiv = document.createElement('div');
            statusDiv.className = 'status';
            statusDiv.innerHTML = status === 'seen' ? '<svg width="18" height="14" viewBox="0 0 28 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/><polyline points="26 6 15 17"/></svg>' : (status === 'delivered') ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
            return statusDiv;
        }

        function createTimeElement(timestamp) {
            const timeDiv = document.createElement('div');
            timeDiv.className = 'message-time';
            timeDiv.textContent = timestamp
                ? new Date(timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})
                : new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            return timeDiv;
        }

        // ==================== EVENT LISTENERS ====================
        document.addEventListener('click', function(e) {
            if (contextMenu.style.display === 'block' && !contextMenu.contains(e.target)) {
                hideContextMenu(true);
            }
            if (emojiMenu.style.display === 'block' && !emojiMenu.contains(e.target)) {
                hideEmojiMenu(true);
            }
        });

        contextMenu.addEventListener('click', function(e) {
            e.stopPropagation();
        });

        // Delegated click handler for emoji options
        function handleEmojiPick(e) {
            const option = e.target.closest('.emoji-option');
            if (option && option.dataset.emoji) {
                e.stopPropagation();
                addReaction(option.dataset.emoji);
            }
        }
        emojiMenu.addEventListener('click', handleEmojiPick);
        emojiMenu.addEventListener('touchend', function(e) {
            const option = e.target.closest('.emoji-option');
            if (option && option.dataset.emoji) {
                e.preventDefault();
                e.stopPropagation();
                addReaction(option.dataset.emoji);
            }
        });

        document.getElementById('saveModal').addEventListener('click', function(e) {
            if (e.target === this) closeSaveModal();
        });

        document.getElementById('fileUploadModal').addEventListener('click', function(e) {
            if (e.target === this) closeFileUploadModal();
        });

        // Escape key to close menus
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeFileUploadModal();
                closeSaveModal();
                closeMediaViewer();
                hideContextMenu(true);
                hideEmojiMenu(true);
            }
        });

        // Load messages from API
        function scrollToBottom(smooth = false) {
            requestAnimationFrame(() => {
                chatDiv.scrollTop = chatDiv.scrollHeight;
            });
        }

        function loadMessages() {
            const bust = Date.now();
            const textUrl  = `/api/get_messages?user_phone=${encodeURIComponent(myPhone)}&contact_phone=${encodeURIComponent(contactPhone)}&page=1&limit=50&_=${bust}`;
            const voiceUrl = `/api/voice/history?sender=${encodeURIComponent(myPhone)}&receiver=${encodeURIComponent(contactPhone)}&limit=50`;

            Promise.all([
                fetch(textUrl).then(r => r.json()).catch(() => []),
                fetch(voiceUrl).then(r => r.json()).catch(() => [])
            ]).then(([textMsgs, voiceMsgs]) => {
                // Tag each message with its type if not already set
                voiceMsgs.forEach(m => { m.message_type = 'voice'; });

                // Merge and sort by timestamp ascending
                const all = [...textMsgs, ...voiceMsgs].sort((a, b) => {
                    return new Date(a.timestamp) - new Date(b.timestamp);
                });

                chatDiv.innerHTML = '<div id="loadingIndicator" class="loading-indicator hidden">Loading more messages...</div>';
                messageGroups = {};
                lastSender = null;
                groupCounter = 0;
                currentGroupKey = null;
                currentPage = 1;
                hasMoreMessages = true;
                isLoading = false;

                const frag = document.createDocumentFragment();
                all.forEach(m => {
                    if (m.message_type === 'voice') {
                        const el = VM.renderBubble(m);
                        const group = ensureGroup(m.sender, frag);
                        group.appendChild(el);
                        lastSender = m.sender;
                    } else if (m.message_type === 'text') {
                        addMessage(m.sender, m.message, m.status, m.id, m.reactions, m.timestamp, frag);
                    } else {
                        addMediaMessage(m.sender, m.message_type, m.file_path, m.file_name, m.file_size, m.status, m.id, m.reactions, frag, m.timestamp);
                    }
                });

                chatDiv.appendChild(frag);
                // Strip entry animation from history — animating 50+ bubbles at once causes jank
                chatDiv.querySelectorAll('.message-appear').forEach(el => el.classList.remove('message-appear'));
                // Reset group tracking so live incoming messages create fresh groups
                // attached directly to chatDiv, not to the now-consumed fragment
                lastSender = null;
                currentGroupKey = null;

                // If the API returned empty but the server-side render has messages,
                // fall back to server-side messages (handles first-open race condition)
                const ssMessages = {{ messages|tojson }};
                if (all.length === 0 && ssMessages.length > 0) {
                    const fallbackFrag = document.createDocumentFragment();
                    ssMessages.forEach(m => {
                        if (m.message_type === 'text' || !m.message_type) {
                            addMessage(m.sender, m.message, m.status, m.id, m.reactions || [], m.timestamp, fallbackFrag);
                        } else {
                            addMediaMessage(m.sender, m.message_type, m.file_path, m.file_name, m.file_size, m.status, m.id, m.reactions || [], fallbackFrag, m.timestamp);
                        }
                    });
                    chatDiv.appendChild(fallbackFrag);
                    chatDiv.querySelectorAll('.message-appear').forEach(el => el.classList.remove('message-appear'));
                    lastSender = null;
                    currentGroupKey = null;
                }

                scrollToBottom(false);
                setupInfiniteScroll();
                initializeContextMenuSystem();
            }).catch(error => {
                console.error('Error loading messages:', error);
                const oldMessages = {{ messages|tojson }};
                const frag = document.createDocumentFragment();
                oldMessages.forEach(m => {
                    if (m.message_type === 'text' || !m.message_type) {
                        addMessage(m.sender, m.message, m.status, m.id, [], m.timestamp, frag);
                    } else {
                        addMediaMessage(m.sender, m.message_type, m.file_path, m.file_name, m.file_size, m.status, m.id, [], frag, m.timestamp);
                    }
                });
                chatDiv.appendChild(frag);
                chatDiv.querySelectorAll('.message-appear').forEach(el => el.classList.remove('message-appear'));
                scrollToBottom(false);
            });
        }

        // Enhanced socket connection
        var socket = io({
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            reconnectionAttempts: Infinity,
            timeout: 20000,
            autoConnect: true,
            transports: ['websocket', 'polling']
        });

        // Connection quality monitoring
        let connectionAttempts = 0;
        const MAX_CONNECTION_ATTEMPTS = 5;

        // ── Presence helpers ─────────────────────────────────────────
        function formatLastSeen(isoStr) {
            if (!isoStr) return 'Offline';
            const diff = Math.floor((Date.now() - new Date(isoStr)) / 1000);
            if (diff < 60)  return 'Last seen just now';
            if (diff < 3600) {
                const m = Math.floor(diff / 60);
                return `Last seen ${m} min${m>1?'s':''} ago`;
            }
            if (diff < 86400) {
                const h = Math.floor(diff / 3600);
                return `Last seen ${h} hour${h>1?'s':''} ago`;
            }
            const d = Math.floor(diff / 86400);
            return `Last seen ${d} day${d>1?'s':''} ago`;
        }

        function setPresence(status, lastOnline) {
            if (status === 'online') {
                statusDot.className = 'status-dot status-online';
                statusText.textContent = 'Online';
            } else {
                statusDot.className = 'status-dot status-offline';
                statusText.textContent = formatLastSeen(lastOnline);
            }
        }

        function updateConnectionStatus(connected) {
            isConnected = connected;
            // Only update the dot for our own socket state if the contact
            // presence hasn't been received yet
            if (!connected) {
                statusDot.className = 'status-dot status-offline';
                statusText.textContent = 'Reconnecting…';
            }
        }

        // Listen for real-time presence updates from the server
        socket.on('presence_update', data => {
            if (String(data.phone) === String(contactPhone)) {
                setPresence(data.status, data.last_online);
            }
        });

        // Heartbeat — tell server we're still here every 30s
        setInterval(() => {
            if (socket.connected) {
                socket.emit('heartbeat', { phone: String(myPhone) });
            }
        }, 30000);
        // ─────────────────────────────────────────────────────────────

        // Fallback: if socket doesn't fire presence_update within 4s, show sensible status
        setTimeout(() => {
            if (statusText.textContent === 'Loading…') {
                fetch('/api/profile?phone=' + encodeURIComponent(contactPhone))
                    .then(r => r.json())
                    .then(data => {
                        if (statusText.textContent === 'Loading…') {
                            statusText.textContent = data.last_online
                                ? formatLastSeen(data.last_online)
                                : 'Offline';
                            statusDot.className = 'status-dot status-offline';
                        }
                    }).catch(() => {
                        if (statusText.textContent === 'Loading…') {
                            statusText.textContent = 'Offline';
                            statusDot.className = 'status-dot status-offline';
                        }
                    });
            }
        }, 4000);

        socket.on('connect', () => {
            console.log('Connected to server with ID:', socket.id);
            connectionAttempts = 0;
            isConnected = true;
            updateConnectionStatus(true);
            joinChatRoom();
        });

        function joinChatRoom() {
            if (socket.connected) {
                socket.emit('join', {
                    user: myPhone,
                    contact: contactPhone
                });
            }
        }

        // Load contact's profile photo into the header avatar
        (function loadContactAvatar() {
            fetch('/api/profile?phone=' + encodeURIComponent(contactPhone))
                .then(r => r.json())
                .then(data => {
                    const avatarEl = document.querySelector('.contact-avatar');
                    if (!avatarEl) return;
                    if (data.avatar_photo) {
                        avatarEl.innerHTML = `<img src="${data.avatar_photo}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;display:block;" alt="">`;
                        avatarEl.style.background = 'transparent';
                        avatarEl.style.overflow = 'hidden';
                        avatarEl.style.padding = '0';
                        avatarEl.style.fontSize = '0';
                    }
                })
                .catch(() => {});
        })();

        // join_success confirms the room was joined
        socket.on('join_success', () => {
            markAllMessagesAsSeen();
        });

        // Handle connection errors
        socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            connectionAttempts++;
            
            if (connectionAttempts >= MAX_CONNECTION_ATTEMPTS) {
                console.error(' Max connection attempts reached');
                showToast('Connection lost. Retrying…', 5000);
            } else {
                console.log(` Connection attempt ${connectionAttempts}/${MAX_CONNECTION_ATTEMPTS}`);
            }
            
            updateConnectionStatus(false);
        });

        // Modern Bottom Sheet File Upload Functions
        function openFileUploadModal() {
            fileUploadModal.style.display = 'flex';
        }

        function closeFileUploadModal() {
            fileUploadModal.style.display = 'none';
            fileInput.value = '';
        }

        fileUploadModal.addEventListener('click', function(e) {
            if (e.target === this) {
                closeFileUploadModal();
            }
        });

        function triggerFileInput(fileType) {
            let accept = '';
            switch(fileType) {
                case 'image':
                    accept = 'image/*';
                    break;
                case 'video':
                    accept = 'video/*';
                    break;
                case 'document':
                    accept = '*/*';
                    break;
            }
            fileInput.accept = accept;
            fileInput.onchange = function() {
                if (this.files.length > 0) {
                    uploadFile(this.files[0], fileType);
                }
            };
            fileInput.click();
            closeFileUploadModal();
        }

        function getFileIcon(fileType, fileName) {
            const extension = fileName ? fileName.split('.').pop()?.toLowerCase() : '';

            if (fileType === 'image') return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>';
            if (fileType === 'video') return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>';

            const svgDoc = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
            const svgZip = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10V8l-6-6H5a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h7"/><path d="M15 2v6h6"/><path d="M18 22v-6m0 0l-2 2m2-2l2 2"/></svg>';

            const docIcons = {
                'pdf': svgDoc, 'doc': svgDoc, 'docx': svgDoc,
                'txt': svgDoc, 'ppt': svgDoc, 'pptx': svgDoc,
                'xls': svgDoc, 'xlsx': svgDoc,
                'zip': svgZip, 'rar': svgZip
            };

            return docIcons[extension] || svgDoc;
        }

        function getFileTypeClass(fileType) {
            switch(fileType) {
                case 'image': return 'photo';
                case 'video': return 'video';
                default: return 'document';
            }
        }

        function uploadFile(file, fileType) {
            if (!file) return;

            const maxSize = 16 * 1024 * 1024;
            if (file.size > maxSize) {
                alert('File size too large. Maximum size is 16MB.');
                return;
            }

            const formData = new FormData();
            formData.append('file', file);
            formData.append('sender', myPhone);
            formData.append('receiver', contactPhone);

            // Show uploading indicator
            const tempMessageId = 'temp_' + Date.now();
            addTempMediaMessage(file, tempMessageId);

            fetch('/upload_file', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Remove temp message and add real one
                    removeTempMessage(tempMessageId);
                    addMediaMessage(myPhone, data.file_type, data.file_path, data.file_name, data.file_size, 'sent', data.message_id, []);
                    
                    // Emit socket event for real-time update
                    socket.emit('send_file_message', {
                        sender: String(myPhone),
                        receiver: String(contactPhone),
                        message_type: data.file_type,
                        file_path: data.file_path,
                        file_name: data.file_name,
                        file_size: data.file_size,
                        message_id: data.message_id,
                        timestamp: new Date().toISOString()
                    });
                } else {
                    throw new Error(data.error || 'Upload failed');
                }
            })
            .catch(error => {
                console.error('Upload error:', error);
                removeTempMessage(tempMessageId);
                alert('File upload failed: ' + error.message);
            });
        }

        function addTempMediaMessage(file, tempId) {
            const isSent = true;
            const messageGroupId = 'sent';

            if (lastSender !== String(myPhone) || !messageGroups[messageGroupId]) {
                messageGroups[messageGroupId] = document.createElement('div');
                messageGroups[messageGroupId].className = 'message-group sent-group';
                chatDiv.appendChild(messageGroups[messageGroupId]);
            }

            const bubble = document.createElement('div');
            bubble.className = 'bubble sent message-appear';
            bubble.id = tempId;

            const messageContent = document.createElement('div');
            messageContent.textContent = `Uploading ${file.name}...`;
            messageContent.style.fontStyle = 'italic';
            messageContent.style.color = '#666';
            bubble.appendChild(messageContent);

            messageGroups[messageGroupId].appendChild(bubble);
            lastSender = String(myPhone);
            scrollToBottom(true);
        }

        function removeTempMessage(messageId) {
            const tempElement = document.getElementById(messageId);
            if (tempElement) {
                tempElement.remove();
            }
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function downloadFile(filePath, fileName) {
            const link = document.createElement('a');
            link.href = `/uploads/${filePath}`;
            link.download = fileName;
            link.click();
        }

        function viewMedia(filePath, mediaType) {
            const mediaUrl = `/uploads/${filePath}`;
            
            if (mediaType === 'image') {
                viewerImage.src = mediaUrl;
                viewerImage.style.display = 'block';
                viewerVideo.style.display = 'none';
            } else if (mediaType === 'video') {
                viewerVideo.src = mediaUrl;
                viewerVideo.style.display = 'block';
                viewerImage.style.display = 'none';
            }
            
            mediaViewer.style.display = 'flex';
        }

        function closeMediaViewer() {
            mediaViewer.style.display = 'none';
            viewerVideo.pause();
        }

        function addMediaMessage(sender, messageType, filePath, fileName, fileSize, status, messageId = null, reactions = [], frag = null, timestamp = null) {
            const isSent = sender === String(myPhone);
            const target = frag || chatDiv;
            const group = ensureGroup(sender, target);

            const bubble = document.createElement('div');
            bubble.className = `bubble ${isSent ? 'sent' : 'received'} media-message message-appear`;
            
            if (messageId && messageId !== 'null' && !messageId.toString().startsWith('temp_')) {
                bubble.dataset.messageId = messageId;
                console.log('Added media with DB ID:', messageId);
            } else {
                const tempId = 'temp_' + Date.now();
                bubble.dataset.messageId = tempId;
                console.log('Added media with temp ID:', tempId);
            }

            const fileIcon = getFileIcon(messageType, fileName);
            const fileTypeClass = getFileTypeClass(messageType);

            if (messageType === 'image') {
                const mediaPreview = document.createElement('div');
                mediaPreview.className = 'media-preview';
                mediaPreview.onclick = () => viewMedia(filePath, 'image');

                const img = document.createElement('img');
                img.src = `/uploads/${filePath}`;
                img.alt = '';
                img.loading = 'lazy';

                mediaPreview.appendChild(img);
                bubble.appendChild(mediaPreview);
                
            } else if (messageType === 'video') {
                const mediaContainer = document.createElement('div');
                mediaContainer.style.position = 'relative';
                
                const mediaPreview = document.createElement('div');
                mediaPreview.className = 'media-preview';
                mediaPreview.onclick = () => viewMedia(filePath, 'video');
                
                const video = document.createElement('video');
                video.src = `/uploads/${filePath}`;
                video.alt = fileName;
                video.controls = false;
                
                const playOverlay = document.createElement('div');
                playOverlay.style.cssText = `
                    position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
                    background: rgba(0,0,0,0.7); border-radius: 50%; width: 50px; height: 50px;
                    display: flex; align-items: center; justify-content: center; color: white;
                    font-size: 20px; pointer-events: none;
                `;
                playOverlay.innerHTML = '<svg width="22" height="22" viewBox="0 0 24 24" fill="white" stroke="none"><polygon points="5 3 19 12 5 21 5 3"/></svg>';
                
                mediaPreview.appendChild(video);
                mediaPreview.appendChild(playOverlay);
                mediaContainer.appendChild(mediaPreview);
                
                const mediaInfo = document.createElement('div');
                mediaInfo.className = 'media-info';
                
                const fileNameDiv = document.createElement('div');
                fileNameDiv.className = 'media-filename';
                fileNameDiv.textContent = fileName;
                
                const metadataDiv = document.createElement('div');
                metadataDiv.className = 'media-metadata';
                
                const sizeDiv = document.createElement('div');
                sizeDiv.className = 'media-size';
                sizeDiv.textContent = formatFileSize(fileSize);
                
                const typeDiv = document.createElement('div');
                typeDiv.className = 'media-type';
                typeDiv.textContent = 'VIDEO';
                
                metadataDiv.appendChild(sizeDiv);
                metadataDiv.appendChild(typeDiv);
                
                mediaInfo.appendChild(fileNameDiv);
                mediaInfo.appendChild(metadataDiv);
                mediaContainer.appendChild(mediaInfo);
                
                bubble.appendChild(mediaContainer);
                
            } else {
                const fileMessage = document.createElement('div');
                fileMessage.className = 'file-message';
                fileMessage.onclick = () => downloadFile(filePath, fileName);
                
                const fileIconDiv = document.createElement('div');
                fileIconDiv.className = `file-icon ${fileTypeClass}`;
                fileIconDiv.innerHTML = fileIcon;
                
                const fileInfo = document.createElement('div');
                fileInfo.className = 'file-info';
                
                const fileNameDiv = document.createElement('div');
                fileNameDiv.className = 'file-name';
                fileNameDiv.textContent = fileName;
                
                const fileDetails = document.createElement('div');
                fileDetails.className = 'file-details';
                
                const fileSizeDiv = document.createElement('div');
                fileSizeDiv.className = 'file-size';
                fileSizeDiv.textContent = formatFileSize(fileSize);
                
                const fileTypeDiv = document.createElement('div');
                fileTypeDiv.className = 'file-type';
                fileTypeDiv.textContent = messageType.toUpperCase();
                
                fileDetails.appendChild(fileSizeDiv);
                fileDetails.appendChild(fileTypeDiv);
                
                fileInfo.appendChild(fileNameDiv);
                fileInfo.appendChild(fileDetails);
                
                const downloadBtn = document.createElement('button');
                downloadBtn.className = 'download-btn';
                downloadBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right:5px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Download';
                downloadBtn.onclick = (e) => {
                    e.stopPropagation();
                    downloadFile(filePath, fileName);
                };
                
                fileMessage.appendChild(fileIconDiv);
                fileMessage.appendChild(fileInfo);
                fileMessage.appendChild(downloadBtn);
                
                bubble.appendChild(fileMessage);
            }

            // Add reactions if any
            if (reactions && reactions.length > 0) {
                const reactionsContainer = document.createElement('div');
                reactionsContainer.className = 'message-reactions';
                
                const reactionCounts = {};
                reactions.forEach(reaction => {
                    if (!reactionCounts[reaction.emoji]) {
                        reactionCounts[reaction.emoji] = 0;
                    }
                    reactionCounts[reaction.emoji]++;
                });

                Object.entries(reactionCounts).forEach(([emoji, count]) => {
                    const reactionElement = document.createElement('div');
                    reactionElement.className = 'reaction';
                    reactionElement.innerHTML = `
                        <span class="reaction-emoji">${emoji}</span>
                        <span class="reaction-count">${count}</span>
                    `;
                    reactionsContainer.appendChild(reactionElement);
                });

                bubble.appendChild(reactionsContainer);
            }

            if (isSent) {
                const statusDiv = document.createElement('div');
                statusDiv.className = 'status';
                statusDiv.innerHTML = (status === 'seen') ? '<svg width="18" height="14" viewBox="0 0 28 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/><polyline points="26 6 15 17"/></svg>' : (status === 'delivered') ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
                bubble.appendChild(statusDiv);
            }

            const timeDiv = document.createElement('div');
            timeDiv.className = 'message-time';
            timeDiv.textContent = timestamp
                ? new Date(timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})
                : new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            bubble.appendChild(timeDiv);

            group.appendChild(bubble);
            lastSender = sender;

            if (!frag) {
                scrollToBottom(true);
                if (!isSent) {
                    setTimeout(() => {
                        markAllMessagesAsSeen();
                    }, 500);
                }
            }
        }

        // Close media viewer when clicking outside
        mediaViewer.addEventListener('click', function(e) {
            if (e.target === this) {
                closeMediaViewer();
            }
        });

        socket.on('disconnect', () => {
            console.log(' Disconnected from server');
            updateConnectionStatus(false);
        });

        // Handle socket errors
        socket.on('error', (error) => {
            console.error('Socket error:', error);
            if (error.message && error.message.includes('unauthorized')) {
                console.log(' Authentication error, reloading...');
                setTimeout(() => location.reload(), 2000);
            }
        });

        messageInput.addEventListener('input', ()=>{
            if(!isConnected) return;
            socket.emit('typing', {actor: myPhone, target: contactPhone});
            clearTimeout(typingTimeout);
            typingTimeout = setTimeout(()=>{
                socket.emit('stop_typing', {actor: myPhone, target: contactPhone});
            }, 2000);
        });

        socket.on('typing', data=>{
            if(data.actor === contactPhone) typingDiv.textContent = 'Typing...';
        });

        socket.on('stop_typing', data=>{
            if(data.actor === contactPhone) typingDiv.textContent = '';
        });

        // ── Unified group manager ─────────────────────────────────────
        function ensureGroup(sender, target) {
            const isSent = sender === String(myPhone);
            const existingGroup = messageGroups[currentGroupKey];
            // Need a new group if: sender changed, no group exists, or existing
            // group is not inside the target (e.g. was built inside a fragment)
            const needsNewGroup = lastSender !== sender
                || !currentGroupKey
                || !existingGroup
                || (target !== document && !target.contains(existingGroup))
                || (target === chatDiv && !chatDiv.contains(existingGroup));
            if (needsNewGroup) {
                groupCounter++;
                currentGroupKey = `grp_${groupCounter}`;
                const g = document.createElement('div');
                g.className = `message-group ${isSent ? 'sent-group' : 'received-group'}`;
                messageGroups[currentGroupKey] = g;
                target.appendChild(g);
            }
            return messageGroups[currentGroupKey];
        }

        function addMessage(sender, msg, status, messageId = null, reactions = [], timestamp = null, frag = null) {
            const isSent = sender === String(myPhone);
            const target = frag || chatDiv;
            const group  = ensureGroup(sender, target);

            const bubble = document.createElement('div');
            bubble.className = `bubble ${isSent ? 'sent' : 'received'} message-appear`;
            bubble.dataset.messageId = (messageId && messageId !== 'null' && !String(messageId).startsWith('temp_'))
                ? messageId : ('temp_' + Date.now());

            const messageContent = document.createElement('div');
            messageContent.textContent = msg;
            bubble.appendChild(messageContent);

            if (reactions && reactions.length > 0) bubble.appendChild(createReactionsElement(reactions));
            if (isSent) bubble.appendChild(createStatusElement(status));

            const timeDiv = document.createElement('div');
            timeDiv.className = 'message-time';
            timeDiv.textContent = timestamp
                ? new Date(timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})
                : new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            bubble.appendChild(timeDiv);

            group.appendChild(bubble);
            lastSender = sender;

            if (!frag) {
                scrollToBottom(true);
                if (!isSent) setTimeout(markAllMessagesAsSeen, 500);
            }
        }

        // Track pending temp messages waiting for real DB ID
        const pendingTempMessages = {};

        function showToast(message, duration = 3000) {
            const existing = document.getElementById('toastNotif');
            if (existing) existing.remove();
            const toast = document.createElement('div');
            toast.id = 'toastNotif';
            toast.textContent = message;
            toast.style.cssText = `
                position: fixed; bottom: 90px; left: 50%; transform: translateX(-50%);
                background: rgba(14,73,80,0.88); color: white; padding: 10px 20px;
                border-radius: 22px; font-size: 13px; font-weight: 600; z-index: 9999;
                backdrop-filter: blur(8px); animation: fadeInOut ${duration}ms ease-in-out;
                pointer-events: none; white-space: nowrap;
            `;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), duration);
        }

        function sendMessage() {
            const msg = messageInput.value.trim();
            if(!msg) return;

            // Add temporary ID first
            const tempId = 'temp_' + Date.now();
            addMessage(String(myPhone), msg, 'sent', tempId, []);
            pendingTempMessages[tempId] = msg;

            messageInput.value = '';
            resetTextareaHeight();

            if(!isConnected) {
                showToast('Reconnecting… message will send shortly');
                // Retry once connected
                const retry = setInterval(() => {
                    if (isConnected) {
                        clearInterval(retry);
                        socket.emit('send_message', {
                            sender: String(myPhone),
                            receiver: String(contactPhone),
                            message: msg,
                            temp_id: tempId,
                            timestamp: new Date().toISOString()
                        });
                    }
                }, 500);
                setTimeout(() => clearInterval(retry), 15000);
                return;
            }

            try {
                socket.emit('send_message', {
                    sender: String(myPhone),
                    receiver: String(contactPhone),
                    message: msg,
                    temp_id: tempId,
                    timestamp: new Date().toISOString()
                });
            } catch(error) {
                console.error('Error sending message:', error);
                showToast('Failed to send message. Please try again.');
            }
        }

        messageInput.addEventListener('keydown', function(e) {
            if(e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });

        socket.on('receive_message', data => {
            console.log(' Received message via socket:', data);
            const dataSender   = String(data.sender   || '').trim();
            const dataReceiver = String(data.receiver || '').trim();
            const meStr        = String(myPhone).trim();
            const themStr      = String(contactPhone).trim();

            if (dataSender === meStr && data.temp_id && data.id) {
                // Our own sent message confirmed — swap temp bubble to real DB ID
                const tempBubble = document.querySelector(`[data-message-id="${data.temp_id}"]`);
                if (tempBubble) {
                    tempBubble.dataset.messageId = data.id;
                    // Update tick status to "sent"
                    const statusEl = tempBubble.querySelector('.message-status');
                    if (statusEl) statusEl.innerHTML = '<svg width="14" height="10" viewBox="0 0 16 11" fill="none"><path d="M1 5.5L5.5 10L15 1" stroke="#aecbcc" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
                }
                delete pendingTempMessages[data.temp_id];
                setTimeout(initializeContextMenuSystem, 100);

            } else if (dataSender === themStr && (dataReceiver === meStr || !dataReceiver)) {
                // Incoming message from the contact we're chatting with
                // Dedup: skip if we already have a bubble with this DB id
                if (data.id && document.querySelector(`[data-message-id="${data.id}"]`)) return;
                addMessage(dataSender, data.message, 'delivered', data.id, []);
                setTimeout(() => {
                    markAllMessagesAsSeen();
                    initializeContextMenuSystem();
                }, 100);
            }
        });

        socket.on('receive_file_message', data => {
            if(data.sender === String(contactPhone)) {
                addMediaMessage(data.sender, data.message_type, data.file_path, data.file_name, data.file_size, 'delivered', data.message_id, []);
                setTimeout(() => {
                    markAllMessagesAsSeen();
                    initializeContextMenuSystem();
                }, 100);
            }
        });

        // Handle reaction events from socket
        socket.on('reaction_updated', function(data) {
            // Reconstruct the DOM id: voice messages use a "vm-" prefix to avoid
            // colliding with SMS bubble data-message-id values (both share AUTOINCREMENT IDs).
            const domId = data.is_voice ? 'vm-' + String(data.message_id) : String(data.message_id);
            const el = document.querySelector('[data-message-id="' + domId + '"]');
            if (!el) return;
            const isVoiceWrap = el.classList.contains('vm-react-wrap');
            const container = el.querySelector('.message-reactions');
            if (container) container.remove();
            if (data.reactions && data.reactions.length > 0) {
                const rc = createReactionsElement(data.reactions);
                if (isVoiceWrap) {
                    el.appendChild(rc);
                } else {
                    const anchor = el.querySelector('.status') || el.querySelector('.message-time') || null;
                    if (anchor) el.insertBefore(rc, anchor);
                    else el.appendChild(rc);
                }
            }
        });

        socket.on('message_seen_confirmation', data => {
            if(data.receiver === String(myPhone)) {
                updateAllSentMessagesStatus('seen');
            }
        });

        function updateAllSentMessagesStatus(status) {
            const sentMessages = document.querySelectorAll('#chat .bubble.sent');
            sentMessages.forEach(bubble => {
                const statusDiv = bubble.querySelector('.status');
                if(statusDiv) {
                    if(status === 'seen') {
                        statusDiv.innerHTML = '<svg width="18" height="14" viewBox="0 0 28 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/><polyline points="26 6 15 17"/></svg>';
                    } else if(status === 'delivered') {
                        statusDiv.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
                    }
                }
            });
        }

        function openAvatarLightbox() {
            fetch('/api/profile?phone=' + encodeURIComponent(contactPhone))
                .then(r => r.json())
                .then(p => {
                    const lb = document.getElementById('avatarLightbox');
                    const inner = document.getElementById('avatarLightboxInner');
                    const bgColor = p.avatar_color || '#0E4950';
                    const initial = (p.display_name || p.phone || '?')[0].toUpperCase();
                    const avatarInner = p.avatar_emoji || initial;
                    if (p.avatar_photo) {
                        inner.innerHTML = `<img src="${p.avatar_photo}" style="width:88vw;height:88vw;border-radius:50%;object-fit:cover;display:block;box-shadow:0 8px 40px rgba(0,0,0,0.5);" alt="">`;
                    } else {
                        inner.innerHTML = `<div style="width:88vw;height:88vw;border-radius:50%;background:${bgColor};display:flex;align-items:center;justify-content:center;box-shadow:0 8px 40px rgba(0,0,0,0.5);"><span style="font-size:28vw;font-weight:800;color:white;line-height:1;">${avatarInner}</span></div>`;
                    }
                    lb.style.display = 'flex';
                    setTimeout(() => {
                        lb.style.opacity = '1';
                        inner.style.transform = 'scale(1)';
                    }, 10);
                });
        }

        function closeAvatarLightbox() {
            const lb = document.getElementById('avatarLightbox');
            const inner = document.getElementById('avatarLightboxInner');
            lb.style.opacity = '0';
            inner.style.transform = 'scale(0.82)';
            setTimeout(() => { lb.style.display = 'none'; }, 240);
        }

        function openSaveModal() {
            document.getElementById("saveModal").style.display = "flex";
        }

        function closeSaveModal() {
            document.getElementById("saveModal").style.display = "none";
        }

        // Contact save form handling
        document.getElementById('saveContactForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(this);
            const saveBtn = this.querySelector('.modal-btn.primary');
            const originalText = saveBtn.textContent;

            saveBtn.textContent = 'Saving...';
            saveBtn.disabled = true;

            fetch('/add_contact', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    closeSaveModal();
                    alert('Contact saved successfully!');
                    const newName = formData.get('contact_name');
                    updateContactNameInHeader(newName);
                } else {
                    throw new Error(data.error || 'Save failed');
                }
            })
            .catch(error => {
                console.error('Error saving contact:', error);
                alert('Error saving contact: ' + error.message);
            })
            .finally(() => {
                saveBtn.textContent = originalText;
                saveBtn.disabled = false;
            });
        });

        function updateContactNameInHeader(newName) {
            const contactNameElement = document.querySelector('.contact-name');
            const contactAvatar = document.querySelector('.contact-avatar');

            if (contactNameElement) {
                contactNameElement.textContent = newName;
            }

            if (contactAvatar) {
                contactAvatar.textContent = newName[0].toUpperCase();
            }

            const saveBtn = document.getElementById('saveBtn');
            if (saveBtn) {
                saveBtn.style.display = 'none';
            }
        }

        function markAllMessagesAsSeen() {
            const receivedMessages = document.querySelectorAll('#chat .bubble.received');
            if (receivedMessages.length > 0) {
                const now = Date.now();
                if (now - lastMarkedSeenTime > 1000) {
                    socket.emit('mark_seen', {
                        sender: contactPhone,
                        receiver: myPhone
                    });
                    lastMarkedSeenTime = now;
                }
            }
        }

        document.addEventListener('visibilitychange', function() {
            if (!document.hidden) {
                markAllMessagesAsSeen();
                // Re-announce presence when tab becomes visible again
                if (socket.connected) {
                    socket.emit('set_presence', { phone: String(myPhone), contact: String(contactPhone), status: 'online' });
                }
            } else {
                // Tab hidden — tell server we're away
                if (socket.connected) {
                    socket.emit('set_presence', { phone: String(myPhone), contact: String(contactPhone), status: 'away' });
                }
            }
        });

        chatDiv.addEventListener('scroll', function() {
            markAllMessagesAsSeen();
        });

        chatDiv.addEventListener('click', markAllMessagesAsSeen);

        // ==================== INITIALIZATION ====================
        // Disable browser scroll restoration so position is consistent across all browsers
        if ('scrollRestoration' in history) history.scrollRestoration = 'manual';

        window.addEventListener('load', function() {
            loadMessages();  // loadMessages calls setupInfiniteScroll internally
        });

        // On bfcache restore (back/forward navigation in all browsers), reload fresh
        window.addEventListener('pageshow', function(e) {
            if (e.persisted) {
                loadMessages();
            }
        });

        document.addEventListener('visibilitychange', function() {
            if (!document.hidden) {
                setTimeout(initializeContextMenuSystem, 100);
            }
        });

        setTimeout(autoResizeTextarea, 100);

        // ── Keyboard / viewport handling ──────────────────────────────────
        // On mobile, when the soft keyboard opens the visual viewport shrinks.
        // We use visualViewport API (supported in all modern browsers) to keep
        // the message-box anchored above the keyboard at all times.
        if (window.visualViewport) {
            function onViewportChange() {
                const vv = window.visualViewport;
                // Distance between the layout viewport bottom and visual viewport bottom
                const keyboardHeight = window.innerHeight - vv.height - vv.offsetTop;
                const offset = Math.max(0, keyboardHeight);
                document.body.style.setProperty('--keyboard-offset', offset + 'px');
            }
            window.visualViewport.addEventListener('resize', onViewportChange);
            window.visualViewport.addEventListener('scroll', onViewportChange);
        }

        // Scroll chat to bottom when input is focused (keyboard opens)
        messageInput.addEventListener('focus', function() {
            setTimeout(() => {
                scrollToBottom(false);
            }, 350);
        });

        // ── VOICE MESSAGING ──────────────────────────────────────────
        const VM = (() => {
            let mediaRecorder=null,audioChunks=[],audioCtx=null,analyser=null,
                liveSource=null,animFrame=null,startTime=0,timerInterval=null,
                isRec=false,ampHistory=[];
            const overlay  = () => document.getElementById('vm-overlay');
            const timerEl  = () => document.getElementById('vm-rec-timer');
            const cvs      = () => document.getElementById('vm-live-canvas');
            const micBtn   = () => document.getElementById('vm-mic-btn');

            function toggle(){ isRec ? stopAndSend() : start(); }

            async function start(){
                if(isRec) return;
                if(!window.MediaRecorder||!navigator.mediaDevices){
                    alert('Voice messages are not supported in this browser. Please use Chrome, Firefox, or Safari 14.1+.');
                    return;
                }
                try{
                    const stream = await navigator.mediaDevices.getUserMedia({audio:true});
                    audioCtx = new (window.AudioContext||window.webkitAudioContext)();
                    analyser = audioCtx.createAnalyser(); analyser.fftSize=256;
                    liveSource = audioCtx.createMediaStreamSource(stream);
                    liveSource.connect(analyser);
                    const mime = ['audio/mp4','audio/webm;codecs=opus','audio/webm','audio/ogg;codecs=opus']
                        .find(m=>MediaRecorder.isTypeSupported(m))||'';
                    mediaRecorder = new MediaRecorder(stream, mime?{mimeType:mime}:{});
                    audioChunks=[]; ampHistory=[];
                    mediaRecorder.ondataavailable=e=>{ if(e.data&&e.data.size>0) audioChunks.push(e.data); };
                    mediaRecorder.start(100);
                    isRec=true; startTime=Date.now();
                    overlay().classList.add('active');
                    micBtn()?.classList.add('vm-recording');
                    timerInterval=setInterval(()=>{
                        const s=Math.floor((Date.now()-startTime)/1000);
                        timerEl().textContent=Math.floor(s/60)+':'+String(s%60).padStart(2,'0');
                        if(s>=300) stopAndSend();
                    },500);
                    drawLive();
                }catch(e){ alert('Microphone access required for voice messages.'); }
            }

            function cancel(){
                if(!isRec) return;
                cleanup();
                overlay().classList.remove('active');
                micBtn()?.classList.remove('vm-recording');
            }

            function stopAndSend(){
                if(!isRec) return;
                const dur=Date.now()-startTime;
                mediaRecorder.onstop=async()=>{
                    const mt=mediaRecorder.mimeType||'audio/mp4';
                    const ext=mt.includes('ogg')?'ogg':mt.includes('mp4')||mt.includes('aac')?'m4a':'webm';
                    const blob=new Blob(audioChunks,{type:mt||'audio/mp4'});
                    await upload(blob,ext,dur,deriveWave());
                };
                // Flush final chunk before stopping so blob is complete immediately
                if(mediaRecorder.state==='recording') mediaRecorder.requestData();
                mediaRecorder.stop();
                cleanup();
                overlay().classList.remove('active');
                micBtn()?.classList.remove('vm-recording');
            }

            async function upload(blob,ext,durMs,waveform){
                const tempId='vmtmp_'+Date.now();
                const tempMsg={id:tempId,sender:String(myPhone),receiver:String(contactPhone),
                    file_name:null,duration_ms:durMs,waveform,timestamp:new Date().toISOString(),
                    status:'uploading',message_type:'voice'};
                const el=renderBubble(tempMsg);
                appendVoiceBubble(el);
                const fd=new FormData();
                fd.append('audio',blob,'voice.'+ext);
                fd.append('sender',String(myPhone));
                fd.append('receiver',String(contactPhone));
                fd.append('duration_ms',durMs);
                fd.append('waveform',JSON.stringify(waveform));
                try{
                    const res=await fetch('/api/voice/upload',{method:'POST',body:fd});
                    const data=await res.json();
                    // Don't wireAudio here — onVoiceMessage handles it via socket event
                    // Just remove temp bubble if upload failed
                    if(!data.success){ el.remove(); }
                }catch(e){ el.remove(); }
            }

            function renderBubble(msg){
                const isOut=String(msg.sender)===String(myPhone);
                const wave=msg.waveform&&msg.waveform.length?msg.waveform:Array(40).fill(0.5);
                const wrap=document.createElement('div');
                wrap.className='vm-bubble '+(isOut?'vm-out':'vm-in')+(msg.status==='uploading'?' vm-uploading':'');
                wrap.dataset.vmId=String(msg.id||'');
                wrap.dataset.file=msg.file_name||'';

                const play=document.createElement('button');
                play.className='vm-play'; play.innerHTML=playIcon();
                wrap.appendChild(play);

                const ww=document.createElement('div'); ww.className='vm-ww';
                const waveEl=document.createElement('div'); waveEl.className='vm-wave';
                wave.forEach((a,i)=>{
                    const b=document.createElement('div'); b.className='vm-bar';
                    b.style.height=Math.max(4,Math.round(a*28))+'px';
                    b.dataset.i=i; waveEl.appendChild(b);
                });
                ww.appendChild(waveEl);

                const meta=document.createElement('div'); meta.className='vm-meta';
                const dur=document.createElement('span'); dur.className='vm-dur';
                dur.textContent=fmtMs(msg.duration_ms||0); meta.appendChild(dur);
                if(isOut){
                    const tks=document.createElement('span');
                    tks.className='vm-ticks'+(msg.status==='listened'?' vm-heard':'');
                    tks.innerHTML='<span class="vm-tick vm-on"></span><span class="vm-tick'+(msg.status!=='sent'?' vm-on':'')+'"></span>';
                    meta.appendChild(tks);
                }
                ww.appendChild(meta); wrap.appendChild(ww);

                // Wrap in a column container so reactions appear below the bubble
                const outer=document.createElement('div');
                outer.className='vm-react-wrap '+(isOut?'vm-out':'vm-in');
                // Prefix voice IDs with "vm-" so they never collide with SMS data-message-id
                // values in the DOM (both tables share the same AUTOINCREMENT counter).
                if(msg.id){ outer.dataset.messageId='vm-'+String(msg.id); }
                outer.appendChild(wrap);
                if(msg.file_name&&msg.status!=='uploading') wireAudio(wrap,msg.file_name,msg.duration_ms||0,wave,isOut,msg);
                // Render reactions loaded from history
                if(msg.reactions&&msg.reactions.length){
                    outer.appendChild(createReactionsElement(msg.reactions));
                }
                // Prevent play button tap from triggering long-press context menu
                play.addEventListener('touchstart', e => e.stopPropagation(), {passive:true});
                play.addEventListener('touchend',   e => e.stopPropagation(), {passive:true});
                return outer;
            }

            function wireAudio(wrap,fileName,durMs,wave,isOut,msg){
                const audio=new Audio('/api/voice/file/'+fileName);
                audio.preload='metadata';
                let playing=false;
                const bars=wrap.querySelectorAll('.vm-bar');
                const durEl=wrap.querySelector('.vm-dur');
                const play=wrap.querySelector('.vm-play');
                const waveEl=wrap.querySelector('.vm-wave');

                waveEl.addEventListener('click',e=>{
                    const r=waveEl.getBoundingClientRect();
                    const ratio=(e.clientX-r.left)/r.width;
                    if(audio.duration){ audio.currentTime=ratio*audio.duration; updateProg(); }
                });
                waveEl.addEventListener('touchstart', e=>e.stopPropagation(), {passive:true});
                waveEl.addEventListener('touchend',   e=>e.stopPropagation(), {passive:true});
                audio.addEventListener('timeupdate',updateProg);
                audio.addEventListener('ended',()=>{
                    playing=false; play.innerHTML=playIcon();
                    bars.forEach(b=>b.classList.remove('vm-p'));
                    durEl.textContent=fmtMs(durMs);
                    if(!isOut&&msg&&msg.id&&msg.status!=='listened') markListened(msg.id,wrap);
                });
                play.addEventListener('click',()=>{
                    if(playing){ audio.pause(); playing=false; play.innerHTML=playIcon(); }
                    else{
                        document.querySelectorAll('.vm-audio-active,.gvm-audio-active').forEach(a=>{
                            a.pause(); a.dispatchEvent(new Event('ended')); a.classList.remove('vm-audio-active','gvm-audio-active');
                        });
                        audio.play().then(()=>{
                            audio.classList.add('vm-audio-active');
                            playing=true; play.innerHTML=pauseIcon();
                            if(!isOut&&msg&&msg.id) markListened(msg.id,wrap);
                        }).catch(err=>{
                            // NotAllowedError = browser blocked autoplay; show visual feedback
                            play.style.opacity='0.5';
                            setTimeout(()=>play.style.opacity='',600);
                        });
                    }
                });
                function updateProg(){
                    if(!audio.duration) return;
                    const pct=audio.currentTime/audio.duration;
                    const filled=Math.floor(pct*bars.length);
                    bars.forEach((b,i)=>i<filled?b.classList.add('vm-p'):b.classList.remove('vm-p'));
                    durEl.textContent=fmtMs(Math.max(0,(audio.duration-audio.currentTime)*1000));
                }
            }

            function markListened(id,wrap){
                fetch('/api/voice/listened',{method:'POST',headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({id,user_phone:String(myPhone)})}).catch(()=>{});
            }

            function onVoiceListened(data){
                const el=document.querySelector(`.vm-bubble[data-vm-id="${data.id}"]`);
                if(el){ const t=el.querySelector('.vm-ticks'); if(t) t.classList.add('vm-heard'); }
            }

            function onVoiceMessage(msg){
                if(String(msg.sender)===String(myPhone)){
                    const tmpEl=document.querySelector('.vm-bubble.vm-uploading');
                    if(tmpEl && !tmpEl.dataset.wired){
                        tmpEl.dataset.wired='1';
                        tmpEl.dataset.vmId=String(msg.id);
                        tmpEl.dataset.file=msg.file_name;
                        // Do NOT set data-message-id on the inner vm-bubble —
                        // only the outer vm-react-wrap carries it so querySelector is unambiguous.
                        tmpEl.classList.remove('vm-uploading');
                        // Set on outer vm-react-wrap only, with vm- prefix to avoid SMS ID collisions
                        if(tmpEl.parentElement && tmpEl.parentElement.classList.contains('vm-react-wrap')){
                            tmpEl.parentElement.dataset.messageId='vm-'+String(msg.id);
                        }
                        wireAudio(tmpEl,msg.file_name,msg.duration_ms||0,msg.waveform||[],true,msg);
                    }
                    return;
                }
                if(msg.id && document.querySelector(`.vm-bubble[data-vm-id="${msg.id}"]`)) return;
                appendVoiceBubble(renderBubble(msg));
            }

            function appendVoiceBubble(el){
                // Voice bubbles are standalone — don't mix with text ensureGroup state
                const wrapper = document.createElement('div');
                wrapper.className = 'message-group ' + (el.classList.contains('vm-out') ? 'sent-group' : 'received-group');
                wrapper.appendChild(el);
                chatDiv.appendChild(wrapper);
                // Reset text grouping so next text message starts a fresh group
                lastSender = null;
                currentGroupKey = null;
                scrollToBottom(true);
            }

            function drawLive(){
                const c=cvs(); if(!c) return;
                const ctx=c.getContext('2d'); const W=c.width,H=c.height;
                const buf=new Uint8Array(analyser.frequencyBinCount);
                (function frame(){
                    if(!isRec) return;
                    animFrame=requestAnimationFrame(frame);
                    analyser.getByteFrequencyData(buf);
                    const amp=buf.reduce((s,v)=>s+v,0)/(buf.length*255);
                    ampHistory.push(amp); if(ampHistory.length>200) ampHistory.shift();
                    ctx.clearRect(0,0,W,H);
                    const bars=56,barW=W/bars-2;
                    for(let i=0;i<bars;i++){
                        const idx=Math.min(Math.floor(i*ampHistory.length/bars),ampHistory.length-1);
                        const a=ampHistory[idx]||0,bH=Math.max(4,a*(H-8));
                        ctx.fillStyle=`rgba(255,255,255,${0.35+a*0.65})`;
                        ctx.beginPath(); ctx.roundRect(i*(barW+2),(H-bH)/2,barW,bH,2); ctx.fill();
                    }
                })();
            }

            function deriveWave(bars=40){
                if(!ampHistory.length) return Array(bars).fill(0.5);
                const out=[]; const step=ampHistory.length/bars;
                for(let i=0;i<bars;i++){
                    const s=Math.floor(i*step),e=Math.min(Math.floor((i+1)*step),ampHistory.length);
                    let sum=0; for(let j=s;j<e;j++) sum+=ampHistory[j];
                    out.push(Math.round(Math.min(1,(e>s?sum/(e-s):0)*2.5)*1000)/1000);
                }
                return out;
            }

            function cleanup(){
                isRec=false; clearInterval(timerInterval); cancelAnimationFrame(animFrame);
                if(mediaRecorder&&mediaRecorder.state!=='inactive') mediaRecorder.stop();
                mediaRecorder?.stream?.getTracks().forEach(t=>t.stop());
                if(audioCtx){ audioCtx.close(); audioCtx=null; }
                analyser=null; liveSource=null; timerEl().textContent='0:00';
            }

            function fmtMs(ms){ const s=Math.ceil(ms/1000); return Math.floor(s/60)+':'+String(s%60).padStart(2,'0'); }
            function playIcon(){ return '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>'; }
            function pauseIcon(){ return '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>'; }

            return { toggle, cancel, stopAndSend, renderBubble, appendVoiceBubble, onVoiceMessage, onVoiceListened };
        })();

        // Wire socket voice events
        socket.on('voice_message', data => VM.onVoiceMessage(data));
        socket.on('voice_listened', data => VM.onVoiceListened(data));
        socket.on('voice_deleted', data => {
            const el = document.querySelector('[data-message-id="' + String(data.id) + '"]');
            if (el) {
                const group = el.closest('.message-group');
                el.remove();
                if (group && group.children.length === 0) group.remove();
            }
        });

        socket.on('message_deleted', data => {
            // scope='everyone' → remove bubble for both sides
            // scope='me'       → only remove for the person who deleted (the sender)
            const iAm = String(myPhone);
            const shouldRemove = data.scope === 'everyone' || String(data.sender) === iAm;
            if (!shouldRemove) return;
            const el = document.querySelector('[data-message-id="' + String(data.id) + '"]');
            if (el) {
                const group = el.closest('.message-group');
                el.remove();
                if (group && group.children.length === 0) group.remove();
            }
        });

        // Close delete sheet on outside tap
        document.getElementById('deleteSheet').addEventListener('click', function(e) {
            if (e.target === this) closeDeleteSheet();
        });
        // ─────────────────────────────────────────────────────────────
    </script>
</body>
</html>"""

@app.route("/chat/<contact_phone>")
def chat_page(contact_phone):
    phone = request.args.get("phone")
    if not phone:
        return redirect(url_for('signin'))
    try:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT contact_name FROM contacts WHERE user_phone=%s AND contact_phone=%s", (phone, contact_phone))
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

            c.execute("UPDATE messages SET status='seen' WHERE receiver=%s AND sender=%s AND status!='seen'", (phone, contact_phone))
            # Ensure a contacts row exists so the chat is accessible from both sides
            c.execute("""INSERT INTO contacts(user_phone,contact_phone,contact_name,last_message,last_sender)
                         VALUES(%s,%s,'',(SELECT message FROM messages WHERE ((sender=%s AND receiver=%s) OR (sender=%s AND receiver=%s)) ORDER BY timestamp DESC LIMIT 1),'') ON CONFLICT(user_phone, contact_phone) DO NOTHING""",
                      (phone, contact_phone, phone, contact_phone, contact_phone, phone))
            conn.commit()
        finally:
            return_db_connection(conn)
        contact_name = row[0] if row and row[0] else contact_phone
        return render_template_string(chat_html, phone=phone, contact_phone=contact_phone, contact_name=contact_name, messages=messages)
    except Exception as e:
        print(f" Error in chat_page: {e}")
        return "An error occurred", 500

# ----------------- Enhanced Socket.IO Events -----------------
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

@socketio.on('join')
def on_join(data):
    try:
        user    = str(data['user'])
        contact = str(data['contact'])
        room    = get_room(user, contact)

        join_room(room)
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
            c.execute("UPDATE users SET last_online=%s WHERE phone=%s", (now_iso, user))
            conn.commit()
        finally:
            return_db_connection(conn)

        # Tell the contact this user is online
        _broadcast_presence(user, contact, 'online')

        # Tell this user whether their contact is currently online
        contact_online = _user_online(contact)
        if contact_online:
            emit('presence_update', {'phone': contact, 'status': 'online', 'last_online': None})
        else:
            # Fetch contact's last_online from DB
            conn2 = get_db_connection()
            try:
                c2 = conn2.cursor()
                c2.execute("SELECT last_online FROM users WHERE phone=%s", (contact,))
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
def on_disconnect():
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
                        c.execute("UPDATE users SET last_online=%s WHERE phone=%s", (now_iso, phone))
                        conn.commit()
                    finally:
                        return_db_connection(conn)
                    # Notify contact they went offline
                    if contact:
                        _broadcast_presence(phone, contact, 'offline', now_iso)

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
            c.execute("INSERT INTO messages(sender,receiver,message,encrypted_message,message_type,status,timestamp) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                      (sender, receiver, message, encrypted_message, "text", "sent", now_iso))
            message_id = c.fetchone()[0]
            c.execute("INSERT INTO users(phone,last_online) VALUES(%s,%s)", (receiver, now_iso))
            c.execute("INSERT INTO contacts(user_phone,contact_phone,contact_name,last_message,last_sender) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(user_phone, contact_phone) DO UPDATE SET last_message=EXCLUDED.last_message, last_sender=EXCLUDED.last_sender, timestamp=EXCLUDED.timestamp",
                      (sender, receiver, "", message, sender))
            c.execute("UPDATE contacts SET last_message=%s, last_sender=%s, timestamp=CURRENT_TIMESTAMP WHERE user_phone=%s AND contact_phone=%s",
                      (message, sender, sender, receiver))
            c.execute("INSERT INTO contacts(user_phone,contact_phone,contact_name,last_message,last_sender) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(user_phone, contact_phone) DO UPDATE SET last_message=EXCLUDED.last_message, last_sender=EXCLUDED.last_sender, timestamp=EXCLUDED.timestamp",
                      (receiver, sender, "", message, sender))
            c.execute("UPDATE contacts SET last_message=%s, last_sender=%s, timestamp=CURRENT_TIMESTAMP WHERE user_phone=%s AND contact_phone=%s",
                      (message, sender, receiver, sender))
            conn.commit()
        finally:
            return_db_connection(conn)
        temp_id = data.get('temp_id', None)
        room = get_room(sender, receiver)
        # Invalidate message cache so next page load fetches fresh messages
        cache.clear_pattern(f"msgs_{min(sender,receiver)}_{max(sender,receiver)}")
        emit('receive_message', {'id': message_id, 'sender': sender, 'receiver': receiver, 'message': message, 'temp_id': temp_id, 'timestamp': now_iso, 'status': 'sent'}, room=room)
        
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
            'message_type': message_type,
            'file_path': file_path,
            'file_name': file_name,
            'file_size': file_size
        }, room=room, broadcast=True)

        cache.clear_for_users(sender, receiver)
        cache.clear_pattern(f"msgs_{min(sender,receiver)}_{max(sender,receiver)}")

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
                c.execute("SELECT sender, receiver, group_id FROM voice_messages WHERE id=%s", (message_id,))
                vmsg = c.fetchone()
                if vmsg:
                    sender, receiver, group_id = vmsg
                else:
                    emit('error', {'message': 'Message not found'})
                    return
            else:
                c.execute("SELECT sender, receiver FROM messages WHERE id=%s", (message_id,))
                message = c.fetchone()
                if message:
                    sender, receiver = message
                else:
                    # Fallback: try voice_messages in case is_voice wasn't sent
                    c.execute("SELECT sender, receiver, group_id FROM voice_messages WHERE id=%s", (message_id,))
                    vmsg = c.fetchone()
                    if vmsg:
                        sender, receiver, group_id = vmsg
                    else:
                        emit('error', {'message': 'Message not found'})
                        return

            c.execute("SELECT emoji FROM message_reactions WHERE message_id=%s AND user_phone=%s",
                     (message_id, user_phone))
            existing_reaction = c.fetchone()

            if existing_reaction:
                if existing_reaction[0] == emoji:
                    c.execute("DELETE FROM message_reactions WHERE message_id=%s AND user_phone=%s",
                             (message_id, user_phone))
                    action = 'removed'
                else:
                    c.execute("UPDATE message_reactions SET emoji=%s WHERE message_id=%s AND user_phone=%s",
                             (emoji, message_id, user_phone))
                    action = 'updated'
            else:
                c.execute("INSERT INTO message_reactions (message_id, user_phone, emoji) VALUES (%s, %s, %s)",
                         (message_id, user_phone, emoji))
                action = 'added'

            conn.commit()
            c.execute("SELECT user_phone, emoji FROM message_reactions WHERE message_id=%s", (message_id,))
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
            c.execute("SELECT 1 FROM group_members WHERE group_id=%s AND user_phone=%s", (group_id, sender))
            if not c.fetchone():
                emit('error', {'message': 'Not a group member'})
                return

            now_iso = datetime.now().isoformat()
            c.execute("""
                INSERT INTO group_messages (group_id, sender, message, message_type, file_path, file_name, file_size, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (group_id, sender, message, message_type, file_path, file_name, file_size, now_iso))
            message_id = c.fetchone()[0]

            # Resolve sender display name for recipients
            c.execute("SELECT name FROM groups WHERE id=%s", (group_id,))
            group_row = c.fetchone()
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

        cache.clear_pattern(f"group_{group_id}")
        cache.clear_pattern(f"groups_")

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
            c.execute("SELECT id FROM group_messages WHERE id=%s AND group_id=%s", (message_id, group_id))
            is_voice = False
            if not c.fetchone():
                c.execute("SELECT id FROM voice_messages WHERE id=%s AND group_id=%s", (message_id, group_id))
                if not c.fetchone():
                    emit('error', {'message': 'Message not found in group'})
                    return
                is_voice = True

            c.execute("SELECT emoji FROM message_reactions WHERE message_id=%s AND user_phone=%s",
                      (message_id, user_phone))
            existing = c.fetchone()

            if existing:
                if existing[0] == emoji:
                    c.execute("DELETE FROM message_reactions WHERE message_id=%s AND user_phone=%s",
                              (message_id, user_phone))
                    action = 'removed'
                else:
                    c.execute("UPDATE message_reactions SET emoji=%s WHERE message_id=%s AND user_phone=%s",
                              (emoji, message_id, user_phone))
                    action = 'updated'
            else:
                c.execute("INSERT INTO message_reactions (message_id, user_phone, emoji) VALUES (%s,%s,%s)",
                          (message_id, user_phone, emoji))
                action = 'added'
            conn.commit()

            c.execute("SELECT user_phone, emoji FROM message_reactions WHERE message_id=%s", (message_id,))
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
            c.execute("UPDATE messages SET status='seen' WHERE sender=%s AND receiver=%s AND status!='seen'",
                     (sender, receiver))
            conn.commit()
        finally:
            return_db_connection(conn)

        room = get_room(sender, receiver)
        emit('message_seen_confirmation', {
            'receiver': sender,
            'status': 'seen'
        }, room=room)

        print(f"Messages seen by {receiver}, notifying {sender}")

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
                c.execute("UPDATE users SET last_online=%s WHERE phone=%s", (now_iso, phone))
                conn.commit()
            finally:
                return_db_connection(conn)
    except Exception as e:
        print(f"Error in heartbeat: {e}")

@socketio.on_error_default
def default_error_handler(e):
    print(f"SocketIO Error: {e}")
    emit('error', {'message': 'An error occurred'})


group_chat_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Group Chat</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, interactive-widget=resizes-content">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap" onload="this.onload=null;this.rel='stylesheet'">
    <noscript><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap"></noscript>
    <style>

        :root {
            --primary: #0E4950;
            --primary-light: #1a6b75;
            --accent: #2ec4b6;
            --bg: #eef6f6;
            --border: #d8e8e8;
            --text: #1a2e2f;
            --text-sec: #4a6567;
            --light: #8aa3a5;
        }

        * { margin:0; padding:0; box-sizing:border-box; -webkit-tap-highlight-color:transparent; }

        html { height:100%; height:-webkit-fill-available; }

        body {
            font-family:'DM Sans',-apple-system,BlinkMacSystemFont,sans-serif;
            display:flex; flex-direction:column;
            height:100vh; height:100dvh;
            min-height:-webkit-fill-available;
            background:#eef6f6; color:var(--text);
            overflow:hidden; position:fixed; width:100%; top:0; left:0;
        }

        /* ── Header ── */
        #grp-header {
            background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);
            color:#fff;
            padding:calc(14px + env(safe-area-inset-top,0px)) 16px 14px;
            display:flex; align-items:center; gap:12px;
            box-shadow:0 2px 16px rgba(14,73,80,0.25);
            z-index:10; position:relative; flex-shrink:0;
        }

        .grp-back {
            background:rgba(255,255,255,0.15); border:none; color:#fff;
            padding:7px 10px; border-radius:10px; cursor:pointer; font-size:18px;
            display:flex; align-items:center; justify-content:center;
            transition:background 0.2s;
        }
        .grp-back:hover { background:rgba(255,255,255,0.25); }

        .grp-avatar {
            width:42px; height:42px; border-radius:12px;
            background:linear-gradient(135deg,var(--accent),var(--primary-light));
            display:flex; align-items:center; justify-content:center;
            font-weight:700; font-size:17px; border:2px solid rgba(255,255,255,0.3);
            flex-shrink:0;
        }

        .grp-info { flex:1; min-width:0; }
        .grp-name { font-size:17px; font-weight:700; letter-spacing:-0.01em; }
        .grp-meta { font-size:12px; opacity:0.8; margin-top:1px; cursor:pointer; }

        .grp-info-btn {
            background:rgba(255,255,255,0.15); border:none; color:#fff;
            width:36px; height:36px; border-radius:50%; cursor:pointer;
            display:flex; align-items:center; justify-content:center;
            transition:background 0.2s; flex-shrink:0;
        }
        .grp-info-btn:hover { background:rgba(255,255,255,0.25); }

        /* ── Chat area ── */
        #grp-chat-container {
            flex:1; display:flex; flex-direction:column;
            overflow:hidden; min-height:0;
            background:#eef6f6;
            background-image:radial-gradient(circle,rgba(14,73,80,0.045) 1px,transparent 1px);
            background-size:22px 22px;
        }

        #grp-chat {
            flex:1; overflow-y:auto; padding:20px 16px 12px;
            display:flex; flex-direction:column; gap:4px;
            scroll-behavior:auto;
        }

        #grp-chat::-webkit-scrollbar { width:4px; }
        #grp-chat::-webkit-scrollbar-thumb { background:rgba(14,73,80,0.2); border-radius:4px; }

        #grp-typing {
            font-size:13px; color:var(--text-sec); margin:0 16px 8px;
            height:18px; font-style:italic; flex-shrink:0;
        }

        /* ── Message groups ── */
        .grp-msg-group {
            display:flex; flex-direction:column; margin-bottom:10px; max-width:82%;
        }
        .grp-sent-group { align-self:flex-end; align-items:flex-end; }
        .grp-recv-group { align-self:flex-start; align-items:flex-start; }

        .grp-sender-label {
            font-size:11px; font-weight:600; color:var(--accent);
            margin-bottom:2px; padding:0 4px;
        }

        .bubble {
            padding:11px 15px; border-radius:20px; margin:2px 0;
            font-size:15px; line-height:1.5; word-wrap:break-word;
            white-space:pre-wrap; word-break:break-word; max-width:100%;
            user-select:none; -webkit-user-select:none;
            transition:transform 0.1s, box-shadow 0.15s;
            will-change:transform;
            contain:content;
        }
        .bubble:active { transform:scale(0.985); }
        .sent { background:linear-gradient(135deg,#d4f5ef,#c8ede7); border-bottom-right-radius:5px; border:1px solid rgba(46,196,182,0.2); box-shadow:0 1px 4px rgba(14,73,80,0.08); }
        .received { background:#fff; border-bottom-left-radius:5px; border:1px solid #e8eeee; box-shadow:0 1px 4px rgba(0,0,0,0.05); }

        .msg-time { font-size:10px; color:var(--light); margin-top:2px; padding:0 2px; font-family:'DM Mono',monospace; }

        /* ── Input bar ── */
        #grp-message-box {
            display:flex; padding:10px 12px calc(14px + env(safe-area-inset-bottom,0px));
            background:#fff; border-top:1px solid var(--border);
            gap:8px; align-items:center; min-height:66px;
            box-shadow:0 -4px 20px rgba(14,73,80,0.06); flex-shrink:0;
        }

        #grp-message {
            flex:1; padding:11px 16px; font-size:15px;
            border:1.5px solid var(--border); border-radius:24px;
            outline:none; resize:none; max-height:120px;
            font-family:'DM Sans',inherit; background:#f8fafa;
            line-height:1.45; overflow-y:auto; min-height:44px;
            height:auto; white-space:pre-wrap; word-wrap:break-word;
            color:var(--text); transition:border-color 0.2s,box-shadow 0.2s;
        }
        #grp-message:focus { border-color:var(--accent); background:#fff; box-shadow:0 0 0 3px rgba(46,196,182,0.12); }
        #grp-message::placeholder { color:var(--light); }

        #grp-send-btn {
            width:48px; height:48px; border:none; border-radius:50%;
            background:linear-gradient(135deg,var(--primary),var(--primary-light));
            color:white; font-size:18px; cursor:pointer;
            display:flex; align-items:center; justify-content:center;
            transition:transform 0.15s,box-shadow 0.15s; flex-shrink:0;
            box-shadow:0 3px 14px rgba(14,73,80,0.35);
        }
        #grp-send-btn:hover { transform:scale(1.07); box-shadow:0 5px 18px rgba(14,73,80,0.45); }
        #grp-send-btn:active { transform:scale(0.93); }

        #grp-file-btn {
            width:40px; height:40px; border:none; border-radius:50%;
            background:#e8f6f5; color:var(--accent);
            display:flex; align-items:center; justify-content:center;
            cursor:pointer; flex-shrink:0; transition:background 0.18s,transform 0.15s;
        }
        #grp-file-btn:hover { background:#d0efed; transform:scale(1.07); }
        #grp-file-btn:active { transform:scale(0.93); }

        #grp-mic-btn {
            width:48px !important; height:48px !important; border-radius:50% !important;
            border:none !important;
            background:linear-gradient(135deg,var(--primary),var(--primary-light)) !important;
            color:#fff !important; display:flex !important; align-items:center !important;
            justify-content:center !important; cursor:pointer !important; flex-shrink:0 !important;
            transition:transform 0.15s,box-shadow 0.15s !important;
            box-shadow:0 3px 14px rgba(14,73,80,.35) !important;
        }
        #grp-mic-btn:hover  { transform:scale(1.07) !important; }
        #grp-mic-btn:active { transform:scale(0.93) !important; }
        #grp-mic-btn.grp-vm-rec { background:#e63946 !important; box-shadow:0 0 0 4px rgba(230,57,70,.25) !important; animation:gvmMicPulse 1s infinite !important; }

        /* ── Members panel ── */
        #members-panel {
            display:none; position:fixed; top:0; left:0; width:100%; height:100%;
            background:rgba(10,30,30,0.55); backdrop-filter:blur(6px);
            z-index:2000; align-items:flex-end; justify-content:center;
        }
        .members-sheet {
            background:#fff; border-radius:28px 28px 0 0;
            padding:22px 20px calc(28px + env(safe-area-inset-bottom,0px));
            width:100%; max-height:70vh; overflow-y:auto;
            animation:slideUpFromBottom 0.35s cubic-bezier(0.25,0.46,0.45,0.94);
        }
        .members-handle { width:36px; height:4px; background:#ccd8d8; border-radius:2px; margin:0 auto 18px; }

        @keyframes slideUpFromBottom {
            from { opacity:0; transform:translateY(100%); }
            to { opacity:1; transform:translateY(0); }
        }

        /* ── Media message ── */
        .media-message { max-width:280px; cursor:pointer; }
        .media-preview { border-radius:16px; overflow:hidden; margin-bottom:8px; box-shadow:0 4px 20px rgba(0,0,0,0.15); }
        .media-preview img { width:100%; height:auto; display:block; }

        .file-message { display:flex; align-items:center; gap:12px; padding:14px; background:#f8f9fa; border-radius:14px; border:1px solid #e9ecef; }
        .file-icon-box { width:44px; height:44px; border-radius:10px; display:flex; align-items:center; justify-content:center; background:#E3F2FD; color:#2196F3; flex-shrink:0; }
        .file-dl-btn { background:linear-gradient(135deg,var(--primary),var(--primary-light)); color:white; border:none; border-radius:8px; padding:8px 12px; font-size:12px; font-weight:600; cursor:pointer; white-space:nowrap; }

        /* Toast */
        .grp-toast { position:fixed; bottom:90px; left:50%; transform:translateX(-50%); background:rgba(14,73,80,0.88); color:white; padding:10px 20px; border-radius:22px; font-size:13px; font-weight:600; z-index:9999; pointer-events:none; white-space:nowrap; }

        /* ── Context menu ── */
        #grp-context-menu {
            position:fixed; z-index:9000; background:#fff;
            border-radius:18px; padding:8px 0;
            box-shadow:0 8px 32px rgba(14,73,80,0.18),0 2px 8px rgba(0,0,0,0.10);
            min-width:160px; display:none;
            border:1px solid rgba(14,73,80,0.08);
            animation:grpCtxFadeIn 0.15s ease;
        }
        @keyframes grpCtxFadeIn { from{opacity:0;transform:scale(0.92)} to{opacity:1;transform:scale(1)} }
        .grp-ctx-item {
            display:flex; align-items:center; gap:10px;
            padding:11px 18px; font-size:14px; font-weight:500;
            color:#1a2e2f; cursor:pointer; transition:background 0.15s;
        }
        .grp-ctx-item:hover { background:#f0faf9; }
        .grp-ctx-item svg { flex-shrink:0; }

        /* ── Emoji picker ── */
        #grp-emoji-bar {
            position:fixed; z-index:9001; background:#fff;
            border-radius:50px; padding:8px 14px;
            box-shadow:0 8px 28px rgba(14,73,80,0.18);
            display:none; gap:6px; align-items:center;
            border:1px solid rgba(14,73,80,0.08);
            animation:grpCtxFadeIn 0.15s ease;
        }
        .grp-emoji-btn {
            font-size:22px; cursor:pointer; padding:4px 6px;
            border-radius:50%; transition:all 0.15s; border:none; background:none;
            line-height:1;
        }
        .grp-emoji-btn:hover { background:#f0faf9; transform:scale(1.25); }

        /* ── Reactions display ── */
        .grp-msg-reactions {
            display:flex; flex-wrap:wrap; gap:4px;
            margin-top:4px;
        }
        .grp-reaction-pill {
            display:flex; align-items:center; gap:3px;
            background:rgba(46,196,182,0.12); border:1px solid rgba(46,196,182,0.25);
            border-radius:20px; padding:3px 8px;
            font-size:13px; cursor:pointer; transition:all 0.15s;
        }
        .grp-reaction-pill:hover { background:rgba(46,196,182,0.22); transform:scale(1.05); }
        .grp-reaction-pill .grp-r-count { font-size:11px; font-weight:700; color:var(--primary); }

        @media(max-width:480px) {
            .bubble { padding:10px 14px; font-size:14px; }
            .grp-msg-group { max-width:90%; }
        }

        /* ── Image viewer ── */
        #grp-img-viewer {
            display:none; position:fixed; inset:0; z-index:5000;
            background:rgba(0,0,0,0.92);
            align-items:center; justify-content:center;
        }
        #grp-img-viewer.open { display:flex; }
        #grp-img-viewer img {
            max-width:92vw; max-height:88vh;
            border-radius:10px; object-fit:contain;
            box-shadow:0 8px 40px rgba(0,0,0,0.5);
        }
        #grp-img-viewer-close {
            position:absolute; top:18px; right:18px;
            background:rgba(255,255,255,0.15); border:none; color:#fff;
            width:40px; height:40px; border-radius:50%; cursor:pointer;
            display:flex; align-items:center; justify-content:center;
            font-size:22px; transition:background 0.2s;
        }
        #grp-img-viewer-close:hover { background:rgba(255,255,255,0.28); }

        .media-preview { cursor:pointer; }
        .media-preview img { transition:opacity 0.15s; }
        .media-preview:active img { opacity:0.75; }

        /* ── Voice Message Styles (group) ── */
        #grp-vm-overlay{display:none;position:fixed;inset:0;z-index:9000;background:rgba(14,73,80,0.94);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);flex-direction:column;align-items:center;justify-content:center;gap:22px;}
        #grp-vm-overlay.active{display:flex;}
        #grp-vm-timer{font-size:54px;font-weight:700;color:#fff;letter-spacing:-2px;font-variant-numeric:tabular-nums;font-family:'DM Mono',monospace;}
        #grp-vm-label{font-size:11px;font-weight:600;color:rgba(255,255,255,.6);text-transform:uppercase;letter-spacing:3px;}
        #grp-vm-canvas{width:280px;height:60px;border-radius:12px;}
        .grp-vm-dot{width:10px;height:10px;border-radius:50%;background:#ff4d4d;animation:gvmPulse 1.1s ease-in-out infinite;}
        @keyframes gvmPulse{0%,100%{transform:scale(1);opacity:1;}50%{transform:scale(1.6);opacity:.4;}}
        .grp-vm-actions{display:flex;gap:28px;margin-top:6px;}
        .grp-vm-btn{width:62px;height:62px;border-radius:50%;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:transform .14s;}
        .grp-vm-btn:active{transform:scale(.9);}
        #grp-vm-cancel-btn{background:rgba(255,255,255,.14);color:#fff;}
        #grp-vm-send-btn{background:#fff;color:var(--primary);box-shadow:0 6px 22px rgba(0,0,0,.26);}
        #grp-mic-btn.grp-vm-rec{background:#e63946;animation:gvmMicPulse 1s infinite;}
        @keyframes gvmMicPulse{0%,100%{box-shadow:0 0 0 0 rgba(230,57,70,.55);}50%{box-shadow:0 0 0 10px rgba(230,57,70,0);}}
        .gvm-bubble{display:flex;align-items:center;gap:10px;padding:10px 13px;border-radius:20px;max-width:300px;min-width:210px;font-family:'DM Sans',sans-serif;user-select:none;position:relative;}
        .gvm-bubble.gvm-out{background:linear-gradient(135deg,#d4f5ef,#c8ede7);border-bottom-right-radius:5px;border:1px solid rgba(46,196,182,.2);box-shadow:0 1px 4px rgba(14,73,80,.08);margin-left:auto;}
        .gvm-bubble.gvm-in{background:#fff;border-bottom-left-radius:5px;border:1px solid #e8eeee;box-shadow:0 1px 4px rgba(0,0,0,.05);}
        .gvm-bubble.gvm-uploading::after{content:'';position:absolute;inset:0;border-radius:inherit;background:linear-gradient(90deg,transparent,rgba(255,255,255,.3),transparent);background-size:200% 100%;animation:gvmShimmer 1.3s infinite;}
        @keyframes gvmShimmer{0%{background-position:-200% 0;}100%{background-position:200% 0;}}
        .gvm-play{width:38px;height:38px;border-radius:50%;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:transform .14s;}
        .gvm-play:active{transform:scale(.9);}
        .gvm-bubble.gvm-out .gvm-play{background:rgba(14,73,80,.13);color:var(--primary);}
        .gvm-bubble.gvm-in .gvm-play{background:#e0f2f4;color:var(--primary);}
        .gvm-ww{flex:1;display:flex;flex-direction:column;gap:4px;min-width:0;}
        .gvm-wave{display:flex;align-items:center;gap:2px;height:30px;cursor:pointer;}
        .gvm-bar{flex:1;border-radius:2px;min-width:2px;transition:background .1s;}
        .gvm-bubble.gvm-out .gvm-bar{background:rgba(14,73,80,.22);}
        .gvm-bubble.gvm-out .gvm-bar.gvm-p{background:var(--primary);}
        .gvm-bubble.gvm-in .gvm-bar{background:rgba(14,73,80,.18);}
        .gvm-bubble.gvm-in .gvm-bar.gvm-p{background:var(--primary);}
        .gvm-meta{display:flex;justify-content:space-between;align-items:center;font-size:10px;opacity:.7;}
        .gvm-dur{font-variant-numeric:tabular-nums;font-weight:500;}
        /* Group voice message reaction wrapper */
        .gvm-react-wrap{display:flex;flex-direction:column;max-width:300px;}
        .gvm-react-wrap.gvm-out{align-items:flex-end;margin-left:auto;}
        .gvm-react-wrap.gvm-in{align-items:flex-start;}
        .gvm-react-wrap .grp-msg-reactions,.gvm-react-wrap .message-reactions{margin-top:3px;margin-left:4px;margin-right:4px;}
    </style>
</head>
<body>

<div id="grp-header">
    <button class="grp-back" onclick="goBack()">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <div class="grp-avatar" id="grpAvatar">{{ avatar_letter }}</div>
    <div class="grp-info">
        <div class="grp-name">{{ group_name }}</div>
        <div class="grp-meta" onclick="openMembersPanel()" id="grpMeta">Loading members…</div>
    </div>
    <button class="grp-info-btn" onclick="openMembersPanel()" title="Group info">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    </button>
</div>

<div id="grp-chat-container">
    <div id="grp-chat">
        <div id="grpLoadingIndicator" style="text-align:center;padding:12px;color:var(--light);font-size:13px;font-style:italic;">Loading messages…</div>
    </div>
    <div id="grp-typing"></div>
</div>

<!-- Image viewer -->
<div id="grp-img-viewer" onclick="closeGrpImgViewer()">
    <button id="grp-img-viewer-close" onclick="closeGrpImgViewer()">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
    <img id="grp-img-viewer-img" src="" alt="">
</div>

<!-- Group Voice Recording Overlay -->
<div id="grp-vm-overlay">
    <div style="display:flex;align-items:center;gap:10px;">
        <div class="grp-vm-dot"></div>
        <span id="grp-vm-label">RECORDING</span>
    </div>
    <canvas id="grp-vm-canvas" width="560" height="120"></canvas>
    <div id="grp-vm-timer">0:00</div>
    <div class="grp-vm-actions">
        <button class="grp-vm-btn" id="grp-vm-cancel-btn" onclick="GVM.cancel()">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
        <button class="grp-vm-btn" id="grp-vm-send-btn" onclick="GVM.stopAndSend()">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
        </button>
    </div>
</div>

<div id="grp-message-box">
    <button id="grp-file-btn" onclick="openGrpFileModal()" title="Send file">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14,2 14,8 20,8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
    </button>
    <textarea id="grp-message" placeholder="Message group…" rows="1"></textarea>
    <button id="grp-mic-btn" onclick="GVM.toggle()" title="Voice message">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
            <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
            <line x1="12" y1="19" x2="12" y2="23"/>
            <line x1="8" y1="23" x2="16" y2="23"/>
        </svg>
    </button>
    <button id="grp-send-btn" onclick="sendGroupMessage()">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" fill="white"/></svg>
    </button>
</div>

<!-- File upload modal (reuses same pattern as 1:1 chat) -->
<div id="grpFileModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,30,30,0.55);backdrop-filter:blur(4px);z-index:2000;align-items:flex-end;justify-content:center;">
    <div style="background:#fff;border-radius:28px 28px 0 0;padding:28px 22px calc(32px + env(safe-area-inset-bottom,0px));width:100%;">
        <div style="width:36px;height:4px;background:#ccd8d8;border-radius:2px;margin:0 auto 18px;"></div>
        <h3 style="color:var(--primary);font-size:20px;font-weight:700;margin-bottom:6px;">Share File</h3>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0;">
            <div onclick="triggerGrpFile('image')" style="display:flex;flex-direction:column;align-items:center;gap:10px;padding:18px 10px;border:1.5px solid var(--border);border-radius:18px;cursor:pointer;background:#f7fafa;">
                <div style="width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,#d4edda,#a8d8b0);display:flex;align-items:center;justify-content:center;">
                    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#4CAF50" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                </div>
                <span style="font-size:13px;font-weight:600;">Photos</span>
            </div>
            <div onclick="triggerGrpFile('video')" style="display:flex;flex-direction:column;align-items:center;gap:10px;padding:18px 10px;border:1.5px solid var(--border);border-radius:18px;cursor:pointer;background:#f7fafa;">
                <div style="width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,#fde8c8,#f9c784);display:flex;align-items:center;justify-content:center;">
                    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#FF9800" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>
                </div>
                <span style="font-size:13px;font-weight:600;">Videos</span>
            </div>
            <div onclick="triggerGrpFile('document')" style="display:flex;flex-direction:column;align-items:center;gap:10px;padding:18px 10px;border:1.5px solid var(--border);border-radius:18px;cursor:pointer;background:#f7fafa;">
                <div style="width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,#dbeafe,#93c5fd);display:flex;align-items:center;justify-content:center;">
                    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#2196F3" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                </div>
                <span style="font-size:13px;font-weight:600;">Docs</span>
            </div>
        </div>
        <input type="file" id="grpFileInput" style="display:none">
        <button onclick="closeGrpFileModal()" style="width:100%;padding:13px;border:none;border-radius:12px;background:#eef2f2;color:#4a6567;font-weight:600;cursor:pointer;font-size:14px;">Cancel</button>
    </div>
</div>

<!-- Members panel -->
<div id="members-panel">
    <div class="members-sheet">
        <div class="members-handle"></div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
            <h3 style="font-size:17px;font-weight:700;color:var(--primary);margin:0;">Group Members</h3>
            <button id="addMemberBtn" onclick="openAddMemberModal()" style="display:none;align-items:center;gap:6px;background:linear-gradient(135deg,#0E4950,#1a6b75);color:white;border:none;padding:8px 14px;border-radius:20px;font-size:13px;font-weight:600;cursor:pointer;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                Add
            </button>
        </div>
        <div id="membersList" style="display:flex;flex-direction:column;gap:0;"></div>
    </div>
</div>

<!-- Add Member modal -->
<div id="addMemberModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,30,30,0.55);z-index:3000;align-items:flex-end;justify-content:center;">
    <div style="background:#fff;border-radius:28px 28px 0 0;padding:24px 20px calc(28px + env(safe-area-inset-bottom,0px));width:100%;max-height:75vh;display:flex;flex-direction:column;">
        <div style="width:36px;height:4px;background:#ccd8d8;border-radius:2px;margin:0 auto 18px;"></div>
        <h3 style="font-size:17px;font-weight:700;color:var(--primary);margin-bottom:4px;">Add Members</h3>
        <p style="font-size:13px;color:#8aa3a5;margin-bottom:16px;">Select contacts to add to this group.</p>
        <div id="addMemberPicker" style="flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:8px;margin-bottom:16px;"></div>
        <div style="display:flex;gap:10px;flex-shrink:0;">
            <button onclick="closeAddMemberModal()" style="flex:1;padding:13px;border:none;border-radius:12px;background:#eef2f2;color:#4a6567;font-weight:600;font-size:14px;cursor:pointer;">Cancel</button>
            <button id="addMemberConfirmBtn" onclick="submitAddMembers()" style="flex:2;padding:13px;border:none;border-radius:12px;background:linear-gradient(135deg,#0E4950,#1a6b75);color:white;font-weight:700;font-size:14px;cursor:pointer;">Add</button>
        </div>
    </div>
</div>

<!-- Remove Member confirmation modal -->
<div id="removeMemberModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,30,30,0.55);backdrop-filter:blur(6px);z-index:4000;align-items:flex-end;justify-content:center;">
    <div style="background:#fff;border-radius:28px 28px 0 0;padding:28px 22px calc(32px + env(safe-area-inset-bottom,0px));width:100%;">
        <div style="width:36px;height:4px;background:#ccd8d8;border-radius:2px;margin:0 auto 20px;"></div>
        <p id="removeMemberLabel" style="font-size:16px;font-weight:600;color:#1a2e2f;text-align:center;margin-bottom:6px;"></p>
        <p style="font-size:13px;color:#8aa3a5;text-align:center;margin-bottom:24px;">This person will be removed from the group and can no longer see messages.</p>
        <div style="display:flex;gap:10px;">
            <button onclick="closeRemoveMemberModal()" style="flex:1;padding:13px;border:none;border-radius:12px;background:#eef2f2;color:#4a6567;font-weight:600;font-size:14px;cursor:pointer;font-family:inherit;">Cancel</button>
            <button id="removeMemberConfirmBtn" style="flex:2;padding:13px;border:none;border-radius:12px;background:#e53935;color:white;font-weight:700;font-size:14px;cursor:pointer;font-family:inherit;">Remove</button>
        </div>
    </div>
</div>

<!-- Context menu -->
<div id="grp-context-menu">
    <div class="grp-ctx-item" id="grpCtxReact">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2ec4b6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>
        React
    </div>
    <div class="grp-ctx-item" id="grpCtxCopy">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#0E4950" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        Copy
    </div>
    <div class="grp-ctx-item" id="grpCtxDelete" style="color:#e53935;display:none;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#e53935" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
        Delete
    </div>
</div>

<!-- Emoji reaction bar -->
<div id="grp-emoji-bar">
    <button class="grp-emoji-btn" data-emoji="👍">👍</button>
    <button class="grp-emoji-btn" data-emoji="❤️">❤️</button>
    <button class="grp-emoji-btn" data-emoji="😂">😂</button>
    <button class="grp-emoji-btn" data-emoji="😮">😮</button>
    <button class="grp-emoji-btn" data-emoji="😢">😢</button>
    <button class="grp-emoji-btn" data-emoji="🔥">🔥</button>
</div>

<script src="https://cdn.socket.io/4.7.2/socket.io.min.js" crossorigin="anonymous"></script>
<script>
    const myPhone = {{ phone|tojson }};
    const groupId = {{ group_id }};
    const groupName = {{ group_name|tojson }};

    const grpChat = document.getElementById('grp-chat');
    const grpInput = document.getElementById('grp-message');
    const grpTyping = document.getElementById('grp-typing');
    const grpFileInput = document.getElementById('grpFileInput');
    let isConnected = false;
    let typingTimer;
    let groupMembers = [];

    // ── Helpers ──────────────────────────────────────────────────
    function goBack() { window.history.back(); }

    function showGrpToast(msg, dur=3000) {
        const t = document.createElement('div');
        t.className = 'grp-toast'; t.textContent = msg;
        document.body.appendChild(t);
        setTimeout(() => t.remove(), dur);
    }

    function formatTime(ts) {
        const d = ts ? new Date(ts) : new Date();
        return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    }

    function formatFileSize(b) {
        if (!b) return '';
        if (b < 1024) return b + ' B';
        if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
        return (b/(1024*1024)).toFixed(1) + ' MB';
    }

    function resizeTextarea() {
        grpInput.style.height = 'auto';
        grpInput.style.height = Math.min(grpInput.scrollHeight, 120) + 'px';
    }
    grpInput.addEventListener('input', resizeTextarea);

    // ── Members panel ─────────────────────────────────────────────
    let isAdmin = false;

    function loadGroupInfo() {
        fetch('/api/group_info?group_id=' + groupId + '&user_phone=' + encodeURIComponent(myPhone))
        .then(r => r.json())
        .then(info => {
            groupMembers = info.members || [];
            document.getElementById('grpMeta').textContent = groupMembers.length + ' member' + (groupMembers.length !== 1 ? 's' : '');

            // Check if current user is admin
            const me = groupMembers.find(m => String(m.phone) === String(myPhone));
            isAdmin = me && me.role === 'admin';

            const list = document.getElementById('membersList');
            const frag = document.createDocumentFragment();
            groupMembers.forEach(m => {
                const isMe = String(m.phone) === String(myPhone);
                const displayName = m.name || m.phone || 'Unknown';
                const initial = displayName[0].toUpperCase();
                const row = document.createElement('div');
                row.dataset.memberPhone = m.phone;
                row.style.cssText = 'display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #f0f4f4;';
                row.innerHTML = `
                  <div style="width:42px;height:42px;border-radius:50%;background:linear-gradient(135deg,#0E4950,#2ec4b6);display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:16px;flex-shrink:0;">${initial}</div>
                  <div style="flex:1;min-width:0;">
                    <div style="font-weight:600;color:#1a2e2f;font-size:14px;">${displayName}${isMe ? ' <span style="color:#8aa3a5;font-weight:400;">(You)</span>' : ''}</div>
                    <div style="color:#8aa3a5;font-size:11px;">${m.phone}</div>
                  </div>
                  ${m.role === 'admin' ? '<span style="font-size:10px;font-weight:700;color:#2ec4b6;background:#f0faf9;padding:3px 8px;border-radius:8px;flex-shrink:0;">Admin</span>' : ''}
                  ${isAdmin && !isMe ? `<button data-phone="${m.phone}" data-name="${displayName.replace(/"/g,'&quot;')}" class="remove-member-btn" style="flex-shrink:0;background:none;border:1.5px solid #f44336;color:#f44336;border-radius:8px;padding:4px 10px;font-size:12px;font-weight:600;cursor:pointer;">Remove</button>` : ''}
                `;
                frag.appendChild(row);
            });

            list.innerHTML = '';
            list.appendChild(frag);

            // Wire remove buttons
            list.querySelectorAll('.remove-member-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const phone = this.dataset.phone;
                    const name  = this.dataset.name;
                    openRemoveMemberModal(phone, name);
                });
            });

            // Show Add Member button for admins
            const addBtn = document.getElementById('addMemberBtn');
            if (addBtn) addBtn.style.display = isAdmin ? 'flex' : 'none';
        })
        .catch(() => {
            document.getElementById('grpMeta').textContent = 'Members';
        });
    }

    // ── Remove Member ─────────────────────────────────────────────
    let _removeTargetPhone = null;

    function openRemoveMemberModal(phone, name) {
        _removeTargetPhone = phone;
        document.getElementById('removeMemberLabel').textContent = 'Remove ' + name + ' from group?';
        document.getElementById('removeMemberModal').style.display = 'flex';
    }

    function closeRemoveMemberModal() {
        document.getElementById('removeMemberModal').style.display = 'none';
        _removeTargetPhone = null;
    }

    document.getElementById('removeMemberModal').addEventListener('click', function(e) {
        if (e.target === this) closeRemoveMemberModal();
    });

    document.getElementById('removeMemberConfirmBtn').addEventListener('click', async function() {
        if (!_removeTargetPhone) return;
        const btn = this;
        btn.disabled = true;
        btn.textContent = 'Removing…';
        try {
            const res = await fetch('/api/remove_group_member', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ group_id: groupId, removed_by: String(myPhone), target_phone: _removeTargetPhone })
            });
            const data = await res.json();
            if (data.success) {
                closeRemoveMemberModal();
                loadGroupInfo(); // refresh member list
            } else {
                alert(data.error || 'Could not remove member.');
                btn.disabled = false;
                btn.textContent = 'Remove';
            }
        } catch(e) {
            alert('Network error. Please try again.');
            btn.disabled = false;
            btn.textContent = 'Remove';
        }
    });

    // ── Add Member ────────────────────────────────────────────────
    function openAddMemberModal() {
        // Load contacts and show picker
        fetch('/api/contacts?phone=' + encodeURIComponent(myPhone))
        .then(r => r.json())
        .then(contacts => {
            const existingPhones = new Set(groupMembers.map(m => String(m.phone)));
            const eligible = contacts.filter(c => !existingPhones.has(String(c.contact_phone)));

            const modal = document.getElementById('addMemberModal');
            const picker = document.getElementById('addMemberPicker');
            picker.innerHTML = '';

            if (eligible.length === 0) {
                picker.innerHTML = '<p style="color:#8aa3a5;font-size:13px;text-align:center;padding:20px 0;">All your contacts are already in this group.</p>';
            } else {
                eligible.forEach(c => {
                    const name = c.contact_name || c.contact_phone;
                    const initial = name[0].toUpperCase();
                    const row = document.createElement('div');
                    row.style.cssText = 'display:flex;align-items:center;gap:12px;padding:11px 12px;border-radius:12px;border:1.5px solid #d8e8e8;cursor:pointer;background:#f8fafa;transition:all 0.15s;';
                    row.dataset.phone = c.contact_phone;
                    row.dataset.selected = 'false';
                    row.innerHTML = `
                      <div style="width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#0E4950,#2ec4b6);display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:15px;flex-shrink:0;">${initial}</div>
                      <div style="flex:1;min-width:0;">
                        <div style="font-weight:600;color:#1a2e2f;font-size:14px;">${name}</div>
                        <div style="color:#8aa3a5;font-size:11px;">${c.contact_phone}</div>
                      </div>
                      <div class="add-check" style="width:22px;height:22px;border-radius:50%;border:2px solid #d8e8e8;flex-shrink:0;display:flex;align-items:center;justify-content:center;transition:all 0.15s;"></div>
                    `;
                    row.addEventListener('click', () => {
                        const sel = row.dataset.selected === 'true';
                        row.dataset.selected = sel ? 'false' : 'true';
                        const check = row.querySelector('.add-check');
                        if (!sel) {
                            row.style.borderColor = '#2ec4b6';
                            row.style.background = '#f0faf9';
                            check.style.background = '#2ec4b6';
                            check.style.borderColor = '#2ec4b6';
                            check.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';
                        } else {
                            row.style.borderColor = '#d8e8e8';
                            row.style.background = '#f8fafa';
                            check.style.background = 'transparent';
                            check.style.borderColor = '#d8e8e8';
                            check.innerHTML = '';
                        }
                    });
                    picker.appendChild(row);
                });
            }
            modal.style.display = 'flex';
        })
        .catch(() => showGrpToast('Could not load contacts'));
    }

    function closeAddMemberModal() {
        document.getElementById('addMemberModal').style.display = 'none';
    }

    function submitAddMembers() {
        const selected = [...document.querySelectorAll('#addMemberPicker [data-selected="true"]')]
            .map(r => r.dataset.phone);
        if (selected.length === 0) { showGrpToast('Select at least one person'); return; }

        const btn = document.getElementById('addMemberConfirmBtn');
        btn.disabled = true; btn.textContent = 'Adding…';

        fetch('/api/add_group_members', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({group_id: groupId, added_by: String(myPhone), members: selected})
        })
        .then(r => r.json())
        .then(data => {
            btn.disabled = false; btn.textContent = 'Add';
            if (data.success) {
                closeAddMemberModal();
                closeMembersPanel();
                loadGroupInfo();
                showGrpToast('Members added!');
            } else {
                showGrpToast(data.error || 'Failed to add members');
            }
        })
        .catch(() => { btn.disabled = false; btn.textContent = 'Add'; showGrpToast('Network error'); });
    }

    document.getElementById('addMemberModal').addEventListener('click', function(e) {
        if (e.target === this) closeAddMemberModal();
    });

    function openMembersPanel() {
        document.getElementById('members-panel').style.display = 'flex';
    }
    function closeMembersPanel() {
        document.getElementById('members-panel').style.display = 'none';
    }
    document.getElementById('members-panel').addEventListener('click', function(e) {
        if (e.target === this) closeMembersPanel();
    });

    // ── Render messages ───────────────────────────────────────────
    function getSenderName(senderPhone) {
        if (String(senderPhone) === String(myPhone)) return 'You';
        const m = groupMembers.find(x => x.phone === String(senderPhone));
        return m ? m.name : senderPhone;
    }

    function createBubble(msg) {
        const isSent = String(msg.sender) === String(myPhone);
        const group = document.createElement('div');
        group.className = 'grp-msg-group ' + (isSent ? 'grp-sent-group' : 'grp-recv-group');

        if (!isSent) {
            const label = document.createElement('div');
            label.className = 'grp-sender-label';
            label.textContent = getSenderName(msg.sender);
            group.appendChild(label);
        }

        const bubble = document.createElement('div');
        bubble.className = 'bubble ' + (isSent ? 'sent' : 'received');
        bubble.dataset.msgType = 'text';
        if (msg.id) bubble.dataset.messageId = msg.id;
        else bubble.dataset.tempId = msg.temp_id || ('temp_' + Date.now());

        if (msg.message_type === 'image' && msg.file_path) {
            const img = document.createElement('img');
            img.src = '/uploads/' + msg.file_path;
            img.alt = '';
            img.loading = 'lazy';
            bubble.className += ' media-message';
            const preview = document.createElement('div');
            preview.className = 'media-preview';
            preview.appendChild(img);
            preview.onclick = () => openGrpImgViewer('/uploads/' + msg.file_path);
            bubble.appendChild(preview);
        } else if (msg.message_type === 'video' && msg.file_path) {
            const fm = document.createElement('div');
            fm.className = 'file-message';
            fm.innerHTML = `<div class="file-icon-box"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg></div><div style="flex:1;min-width:0;"><div style="font-weight:600;font-size:13px;margin-bottom:4px;">${msg.file_name||'Video'}</div><div style="font-size:11px;color:#666;">${formatFileSize(msg.file_size)}</div></div><button class="file-dl-btn" onclick="window.open('/uploads/${msg.file_path}')">Open</button>`;
            bubble.appendChild(fm);
        } else if (msg.message_type !== 'text' && msg.file_path) {
            const fm = document.createElement('div');
            fm.className = 'file-message';
            fm.innerHTML = `<div class="file-icon-box"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></div><div style="flex:1;min-width:0;"><div style="font-weight:600;font-size:13px;margin-bottom:4px;">${msg.file_name||'File'}</div><div style="font-size:11px;color:#666;">${formatFileSize(msg.file_size)}</div></div><button class="file-dl-btn" onclick="window.location='/uploads/${msg.file_path}'">Download</button>`;
            bubble.appendChild(fm);
        } else {
            const txt = document.createElement('div');
            txt.textContent = msg.message;
            bubble.appendChild(txt);
        }

        const time = document.createElement('div');
        time.className = 'msg-time';
        time.textContent = formatTime(msg.timestamp);
        bubble.appendChild(time);

        // Render persisted reactions (loaded from DB)
        if (msg.reactions && msg.reactions.length > 0) {
            renderGroupReactions(bubble, msg.reactions);
        }

        group.appendChild(bubble);
        return group;
    }

    function scrollGrpToBottom(smooth = false) {
        requestAnimationFrame(() => {
            grpChat.scrollTop = grpChat.scrollHeight;
        });
    }

    function appendMessage(msg, scroll=true) {
        const indicator = document.getElementById('grpLoadingIndicator');
        if (indicator) indicator.remove();
        const el = createBubble(msg);
        grpChat.appendChild(el);
        attachBubbleEvents(el);
        if (scroll) scrollGrpToBottom(true);
    }

    // ── Load messages ─────────────────────────────────────────────
    function loadMessages() {
        const textUrl  = '/api/group_messages?group_id=' + groupId + '&user_phone=' + encodeURIComponent(myPhone) + '&page=1&limit=50';
        const voiceUrl = '/api/voice/history?group_id=' + groupId + '&user_phone=' + encodeURIComponent(myPhone);

        Promise.all([
            fetch(textUrl).then(r => r.json()).catch(() => []),
            fetch(voiceUrl).then(r => r.json()).catch(() => [])
        ]).then(([textMsgs, voiceMsgs]) => {
            voiceMsgs.forEach(m => { m.message_type = 'voice'; });
            const all = [...textMsgs, ...voiceMsgs].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            const frag = document.createDocumentFragment();
            all.forEach(m => {
                const el = m.message_type === 'voice' ? GVM_renderBubble(m) : createBubble(m);
                attachBubbleEvents(el);
                frag.appendChild(el);
            });
            grpChat.innerHTML = '';
            grpChat.appendChild(frag);
            grpChat.querySelectorAll('.message-appear').forEach(el => el.classList.remove('message-appear'));
            scrollGrpToBottom(false);
        }).catch(() => showGrpToast('Failed to load messages'));
    }

    // ── Send message ──────────────────────────────────────────────
    function sendGroupMessage() {
        const msg = grpInput.value.trim();
        if (!msg) return;

        const tempId = 'temp_' + Date.now();
        appendMessage({ sender: myPhone, message: msg, message_type: 'text', temp_id: tempId });
        grpInput.value = '';
        grpInput.style.height = 'auto';

        if (!isConnected) {
            showGrpToast('Reconnecting… message will send shortly');
            const retry = setInterval(() => {
                if (isConnected) {
                    clearInterval(retry);
                    socket.emit('send_group_message', { group_id: groupId, sender: String(myPhone), message: msg, temp_id: tempId });
                }
            }, 500);
            setTimeout(() => clearInterval(retry), 15000);
            return;
        }
        socket.emit('send_group_message', { group_id: groupId, sender: String(myPhone), message: msg, temp_id: tempId });
    }

    grpInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendGroupMessage(); }
    });

    grpInput.addEventListener('input', function() {
        if (!isConnected) return;
        socket.emit('group_typing', { group_id: groupId, user: String(myPhone) });
        clearTimeout(typingTimer);
        typingTimer = setTimeout(() => socket.emit('group_stop_typing', { group_id: groupId, user: String(myPhone) }), 2000);
    });

    // ── File upload ───────────────────────────────────────────────
    function openGrpFileModal() { document.getElementById('grpFileModal').style.display = 'flex'; }
    function closeGrpFileModal() { document.getElementById('grpFileModal').style.display = 'none'; grpFileInput.value = ''; }

    function triggerGrpFile(type) {
        const accepts = { image:'image/*', video:'video/*', document:'*/*' };
        grpFileInput.accept = accepts[type] || '*/*';
        grpFileInput.onchange = function() {
            if (this.files.length > 0) uploadGroupFile(this.files[0], type);
        };
        grpFileInput.click();
        closeGrpFileModal();
    }

    // Tracks temp_ids for in-flight file uploads so socket won't double-render them
    const pendingFileTempIds = new Set();

    function uploadGroupFile(file, fileType) {
        if (file.size > 16*1024*1024) { showGrpToast('File too large (max 16MB)'); return; }

        // Create and track a temp bubble element directly
        const tempId = 'temp_' + Date.now();
        pendingFileTempIds.add(tempId);
        const tempEl = createBubble({ sender: myPhone, message: 'Uploading ' + file.name + '…', message_type: 'text', temp_id: tempId });
        grpChat.appendChild(tempEl);
        scrollGrpToBottom(false);

        const fd = new FormData();
        fd.append('file', file);
        fd.append('sender', String(myPhone));
        fd.append('receiver', 'group_' + groupId);

        fetch('/upload_file', { method:'POST', body:fd })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                // Remove the temp bubble group element directly
                if (tempEl.parentNode) tempEl.remove();
                const newTempId = 'temp_' + Date.now();
                pendingFileTempIds.add(newTempId);
                const filePayload = {
                    group_id: groupId, sender: String(myPhone),
                    message: file.name, message_type: data.file_type,
                    file_path: data.file_path, file_name: data.file_name,
                    file_size: data.file_size, temp_id: newTempId
                };
                if (!isConnected) {
                    showGrpToast('Reconnecting… file will send shortly');
                    const retry = setInterval(() => {
                        if (isConnected) {
                            clearInterval(retry);
                            socket.emit('send_group_message', filePayload);
                        }
                    }, 500);
                    setTimeout(() => { clearInterval(retry); pendingFileTempIds.delete(newTempId); showGrpToast('Could not send file. Please try again.'); }, 15000);
                    return;
                }
                socket.emit('send_group_message', filePayload);
            } else {
                if (tempEl.parentNode) tempEl.remove();
                pendingFileTempIds.delete(tempId);
                showGrpToast('Upload failed: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(() => {
            if (tempEl.parentNode) tempEl.remove();
            pendingFileTempIds.delete(tempId);
            showGrpToast('Upload error. Please try again.');
        });
    }

    // ── Image viewer ──────────────────────────────────────────────
    function openGrpImgViewer(src) {
        const viewer = document.getElementById('grp-img-viewer');
        document.getElementById('grp-img-viewer-img').src = src;
        viewer.classList.add('open');
    }
    function closeGrpImgViewer() {
        const viewer = document.getElementById('grp-img-viewer');
        viewer.classList.remove('open');
        document.getElementById('grp-img-viewer-img').src = '';
    }
    // Prevent close when tapping the image itself
    document.getElementById('grp-img-viewer-img').addEventListener('click', e => e.stopPropagation());

    document.getElementById('grpFileModal').addEventListener('click', function(e) {
        if (e.target === this) closeGrpFileModal();
    });

    // ── Socket ────────────────────────────────────────────────────
    const socket = io({
        reconnection:true, reconnectionDelay:1000,
        reconnectionDelayMax:5000, reconnectionAttempts:Infinity,
        timeout:20000, transports:['websocket','polling']
    });

    socket.on('connect', () => {
        isConnected = true;
        socket.emit('join_group', { group_id: groupId, user: String(myPhone) });
    });

    socket.on('disconnect', () => { isConnected = false; });

    socket.on('receive_group_message', function(data) {
        if (String(data.group_id) !== String(groupId)) return;

        if (String(data.sender) === String(myPhone) && data.temp_id) {
            // Own message confirmed — remove from pending set and render the real bubble
            pendingFileTempIds.delete(data.temp_id);
            // Update temp text bubble ID if present (text messages)
            const t = document.querySelector('[data-temp-id="' + data.temp_id + '"]');
            if (t) { t.dataset.messageId = data.id; delete t.dataset.tempId; return; }
            // For file messages the temp element was already removed; render the real bubble now
            appendMessage(data);
            return;
        }

        appendMessage(data);
    });

    socket.on('group_typing', function(data) {
        if (String(data.group_id) !== String(groupId) || String(data.user) === String(myPhone)) return;
        const name = getSenderName(data.user);
        grpTyping.textContent = name + ' is typing…';
    });

    socket.on('group_stop_typing', function(data) {
        if (String(data.group_id) !== String(groupId)) return;
        grpTyping.textContent = '';
    });

    // ── Keyboard / visualViewport ─────────────────────────────────
    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', () => {
            const offset = Math.max(0, window.innerHeight - window.visualViewport.height);
            document.getElementById('grp-message-box').style.paddingBottom = 'calc(16px + env(safe-area-inset-bottom,0px) + ' + offset + 'px)';
        });
    }
    grpInput.addEventListener('focus', () => setTimeout(() => { scrollGrpToBottom(false); }, 350));

    // ── Context menu & reactions ──────────────────────────────────
    let ctxTargetBubble = null;
    let ctxTargetMsg = null;
    let suppressNextClick = false;
    const ctxMenu = document.getElementById('grp-context-menu');
    const emojiBar = document.getElementById('grp-emoji-bar');

    function closeCtx() {
        ctxMenu.style.display = 'none';
        emojiBar.style.display = 'none';
        ctxTargetBubble = null;
        ctxTargetMsg = null;
    }

    function positionPopup(el, x, y) {
        el.style.display = 'flex';
        const r = el.getBoundingClientRect();
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        let left = x, top = y + 10;
        if (left + r.width > vw - 8) left = vw - r.width - 8;
        if (top + r.height > vh - 8) top = y - r.height - 10;
        el.style.left = Math.max(8, left) + 'px';
        el.style.top = Math.max(8, top) + 'px';
    }

    function openCtxMenu(el, msgId, msgText, clientX, clientY) {
        ctxTargetBubble = el;
        ctxTargetMsg = { id: msgId, text: msgText };
        emojiBar.style.display = 'none';

        // Determine if this is a voice message and if it's the user's own
        const isVoice = el.classList.contains('gvm-react-wrap') ||
                        el.classList.contains('gvm-bubble') ||
                        !!el.querySelector('.gvm-bubble');
        const senderWrap = el.classList.contains('gvm-react-wrap') ? el : el.closest('.gvm-react-wrap');
        const isOwn = senderWrap && senderWrap.dataset.sender
            ? String(senderWrap.dataset.sender) === String(myPhone)
            : (el.classList.contains('gvm-out') || !!el.querySelector('.gvm-out'));

        const grpCtxCopy = document.getElementById('grpCtxCopy');
        const grpCtxDelete = document.getElementById('grpCtxDelete');
        if (grpCtxCopy) grpCtxCopy.style.display = isVoice ? 'none' : '';
        if (grpCtxDelete) grpCtxDelete.style.display = (isVoice && isOwn) ? '' : 'none';

        ctxMenu.style.display = 'block';
        positionPopup(ctxMenu, clientX, clientY);
    }

    // Long-press & right-click on bubbles
    let longPressTimer = null;
    let longPressActive = false;

    // Document-level touch handlers (capture phase) — identical to the proven DM chat approach.
    // Using document-level capture means stopPropagation on child elements (waveform, play
    // button inside the voice bubble) cannot block the long-press from firing on any message.
    document.addEventListener('touchstart', function(e) {
        const wrap = e.target.closest('.gvm-react-wrap, .bubble');
        if (!wrap) return;
        const msgId = wrap.dataset.messageId ||
            (wrap.parentElement && wrap.parentElement.dataset.messageId) || null;
        if (!msgId) return;
        longPressActive = true;
        const savedTouches = { clientX: e.touches[0].clientX, clientY: e.touches[0].clientY };
        longPressTimer = setTimeout(() => {
            if (!longPressActive) return;
            suppressNextClick = true;
            const el = wrap.classList.contains('gvm-react-wrap') ? wrap :
                (wrap.closest('.gvm-react-wrap') || wrap);
            const msgText = el.classList.contains('gvm-react-wrap') ? '🎤 Voice message' :
                (el.querySelector('div:not(.msg-time):not(.grp-msg-reactions)')?.textContent || '');
            openCtxMenu(el, msgId, msgText, savedTouches.clientX, savedTouches.clientY);
            longPressActive = false;
        }, 500);
    }, { passive: true, capture: true });

    document.addEventListener('touchend', function() {
        clearTimeout(longPressTimer);
        longPressActive = false;
    }, { passive: true, capture: true });

    document.addEventListener('touchmove', function() {
        clearTimeout(longPressTimer);
        longPressActive = false;
    }, { passive: true, capture: true });

    function attachBubbleEvents(el) {
        // el may be a gvm-react-wrap (new), old-style outer div, or a .bubble
        const gvmWrap = el.classList.contains('gvm-react-wrap') ? el : null;
        const bubble = gvmWrap ? (el.querySelector('.gvm-bubble') || el)
            : el.classList.contains('gvm-bubble') ? el
            : el.querySelector('.gvm-bubble') || el.querySelector('.bubble') || el;

        const getMsgId = () => el.dataset.messageId || bubble.dataset.messageId || null;
        const getMsgText = () => {
            if (bubble.classList.contains('gvm-bubble')) return '🎤 Voice message';
            const txt = bubble.querySelector('div:not(.msg-time):not(.grp-msg-reactions)');
            return txt ? txt.textContent : '';
        };

        // Attach events to the gvm-bubble (audio player) or text .bubble
        const target = bubble.classList.contains('gvm-bubble') ? bubble : (el.querySelector('.bubble') || el);

        target.addEventListener('contextmenu', function(e) {
            e.preventDefault();
            const id = getMsgId();
            if (id) openCtxMenu(el, id, getMsgText(), e.clientX, e.clientY);
        });

        // Long-press is handled by the document-level touchstart listener above,
        // which uses capture:true and fires before any child stopPropagation.
    }

    document.addEventListener('click', function(e) {
        if (!ctxMenu.contains(e.target) && !emojiBar.contains(e.target)) closeCtx();
    });

    // Copy action
    document.getElementById('grpCtxCopy').addEventListener('click', function() {
        if (suppressNextClick) { suppressNextClick = false; return; }
        if (!ctxTargetMsg) return;
        const text = ctxTargetMsg.text;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => showGrpToast('Copied!'));
        } else {
            const ta = document.createElement('textarea');
            ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
            document.body.appendChild(ta); ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            showGrpToast('Copied!');
        }
        closeCtx();
    });

    // Delete voice message action
    document.getElementById('grpCtxDelete').addEventListener('click', function() {
        if (suppressNextClick) { suppressNextClick = false; return; }
        if (!ctxTargetMsg || !ctxTargetMsg.id) { closeCtx(); return; }
        const msgId = ctxTargetMsg.id;
        const el = ctxTargetBubble;
        closeCtx();
        // Optimistically remove from DOM
        if (el) {
            const wrapper = el.closest('.message-group') || el;
            wrapper.remove();
        }
        fetch('/api/voice/delete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ id: msgId, user_phone: String(myPhone) })
        }).then(r => r.json()).then(data => {
            if (!data.success) showGrpToast('Could not delete message.');
        }).catch(() => showGrpToast('Could not delete message.'));
    });

    // React action — show emoji bar
    document.getElementById('grpCtxReact').addEventListener('click', function() {
        if (!ctxTargetMsg) return;
        suppressNextClick = false; // emoji bar is safe — ghost-click window is closed
        const rect = ctxMenu.getBoundingClientRect();
        ctxMenu.style.display = 'none';
        emojiBar.style.display = 'flex';
        positionPopup(emojiBar, rect.left, rect.top);
    });

    // Emoji buttons
    document.querySelectorAll('.grp-emoji-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            if (!ctxTargetMsg || !ctxTargetMsg.id) { closeCtx(); return; }
            const msgId    = ctxTargetMsg.id;
            const emoji    = this.dataset.emoji;
            const targetEl = ctxTargetBubble; // inner .bubble or gvm-react-wrap
            closeCtx();

            // Immediate local update using renderGroupReactions so the UI responds
            // in the same frame — no waiting for the socket round-trip.
            if (targetEl) {
                const existing = [];
                targetEl.querySelectorAll('.grp-reaction-pill').forEach(pill => {
                    const e = pill.querySelector('span:first-child')?.textContent;
                    if (!e) return;
                    // Read real reactors stored on the pill, fall back to count-based placeholder
                    let reactors;
                    try { reactors = JSON.parse(pill.dataset.reactors || '[]'); } catch { reactors = []; }
                    if (reactors.length) {
                        reactors.forEach(p => existing.push({ emoji: e, user_phone: p }));
                    } else {
                        const n = parseInt(pill.querySelector('.grp-r-count')?.textContent || '1');
                        for (let i = 0; i < n; i++) existing.push({ emoji: e, user_phone: '__unknown__' });
                    }
                });
                const alreadyReacted = existing.some(r => r.emoji === emoji && r.user_phone === String(myPhone));
                let synthetic;
                if (alreadyReacted) {
                    let removed = false;
                    synthetic = existing.filter(r => {
                        if (!removed && r.emoji === emoji && r.user_phone === String(myPhone)) { removed = true; return false; }
                        return true;
                    });
                } else {
                    synthetic = [...existing, { emoji, user_phone: String(myPhone) }];
                }
                renderGroupReactions(targetEl, synthetic);
            }

            // Then fire the socket to persist and broadcast to others
            socket.emit('add_group_reaction', {
                message_id: msgId,
                emoji,
                user_phone: String(myPhone),
                group_id: groupId
            });
        });
    });

    // Render reactions on a bubble (el may be gvm-react-wrap, text bubble, or old-style outer)
    function renderGroupReactions(el, reactions) {
        let container = el.querySelector('.grp-msg-reactions');
        if (container) container.remove();
        if (!reactions || reactions.length === 0) return;
        const counts = {};
        reactions.forEach(r => { counts[r.emoji] = (counts[r.emoji] || 0) + 1; });
        container = document.createElement('div');
        container.className = 'grp-msg-reactions';
        Object.entries(counts).forEach(([emoji, count]) => {
            const pill = document.createElement('div');
            pill.className = 'grp-reaction-pill';
            // Store which users reacted so optimistic toggle works correctly
            const reactors = reactions.filter(r => r.emoji === emoji).map(r => r.user_phone);
            pill.dataset.reactors = JSON.stringify(reactors);
            pill.innerHTML = `<span>${emoji}</span><span class="grp-r-count">${count}</span>`;
            pill.addEventListener('click', function() {
                const msgId = el.dataset.messageId;
                if (!msgId) return;
                socket.emit('add_group_reaction', {
                    message_id: msgId, emoji, user_phone: String(myPhone), group_id: groupId
                });
            });
            container.appendChild(pill);
        });
        // For gvm-react-wrap: append below the audio bubble
        if (el.classList.contains('gvm-react-wrap')) {
            el.appendChild(container);
        } else {
            // text bubble: insert before time stamp
            const anchor = el.querySelector('.msg-time') || el.querySelector('.gvm-meta') || null;
            if (anchor) el.insertBefore(container, anchor);
            else el.appendChild(container);
        }
    }

    // Socket: receive group reaction updates
    socket.on('group_reaction_updated', function(data) {
        if (String(data.group_id) !== String(groupId)) return;
        const mid = String(data.message_id);
        // Use msg-type to distinguish text vs voice IDs (they can collide across tables)
        const isVoiceReaction = data.is_voice === true;
        const selector = isVoiceReaction
            ? '[data-msg-type="voice"][data-message-id="' + mid + '"]'
            : '[data-message-id="' + mid + '"]:not([data-msg-type="voice"])';
        const bubble = document.querySelector(selector)
            || document.querySelector('[data-message-id="' + mid + '"]');
        if (bubble) renderGroupReactions(bubble, data.reactions);
    });

    // ── Init ──────────────────────────────────────────────────────
    loadGroupInfo();

    // ── GROUP VOICE MESSAGING ─────────────────────────────────────
    const GVM = (() => {
        let mediaRecorder=null,audioChunks=[],audioCtx=null,analyser=null,
            liveSource=null,animFrame=null,startTime=0,timerInterval=null,
            isRec=false,ampHistory=[];
        const overlay  = ()=>document.getElementById('grp-vm-overlay');
        const timerEl  = ()=>document.getElementById('grp-vm-timer');
        const cvs      = ()=>document.getElementById('grp-vm-canvas');
        const micBtn   = ()=>document.getElementById('grp-mic-btn');

        function toggle(){ isRec?stopAndSend():start(); }

        async function start(){
            if(isRec) return;
            if(!window.MediaRecorder||!navigator.mediaDevices){
                alert('Voice messages are not supported in this browser. Please use Chrome, Firefox, or Safari 14.1+.');
                return;
            }
            try{
                const stream=await navigator.mediaDevices.getUserMedia({audio:true});
                audioCtx=new(window.AudioContext||window.webkitAudioContext)();
                analyser=audioCtx.createAnalyser(); analyser.fftSize=256;
                liveSource=audioCtx.createMediaStreamSource(stream); liveSource.connect(analyser);
                const mime=['audio/mp4','audio/webm;codecs=opus','audio/webm','audio/ogg;codecs=opus']
                    .find(m=>MediaRecorder.isTypeSupported(m))||'';
                mediaRecorder=new MediaRecorder(stream,mime?{mimeType:mime}:{});
                audioChunks=[]; ampHistory=[];
                mediaRecorder.ondataavailable=e=>{ if(e.data&&e.data.size>0) audioChunks.push(e.data); };
                mediaRecorder.start(100);
                isRec=true; startTime=Date.now();
                overlay().classList.add('active'); micBtn()?.classList.add('grp-vm-rec');
                timerInterval=setInterval(()=>{
                    const s=Math.floor((Date.now()-startTime)/1000);
                    timerEl().textContent=Math.floor(s/60)+':'+String(s%60).padStart(2,'0');
                    if(s>=300) stopAndSend();
                },500);
                drawLive();
            }catch(e){ alert('Microphone access required for voice messages.'); }
        }

        function cancel(){
            if(!isRec) return;
            cleanup(); overlay().classList.remove('active'); micBtn()?.classList.remove('grp-vm-rec');
        }

        function stopAndSend(){
            if(!isRec) return;
            const dur=Date.now()-startTime;
            mediaRecorder.onstop=async()=>{
                const mt=mediaRecorder.mimeType||'audio/mp4';
                const ext=mt.includes('ogg')?'ogg':mt.includes('mp4')||mt.includes('aac')?'m4a':'webm';
                const blob=new Blob(audioChunks,{type:mt||'audio/mp4'});
                await upload(blob,ext,dur,deriveWave());
            };
            // Request final chunk before stopping so blob is complete immediately
            if(mediaRecorder.state==='recording') mediaRecorder.requestData();
            mediaRecorder.stop(); cleanup();
            overlay().classList.remove('active'); micBtn()?.classList.remove('grp-vm-rec');
        }

        async function upload(blob,ext,durMs,waveform){
            const tempEl=document.createElement('div');
            tempEl.className='gvm-temp-marker'; // marker to find this specific upload
            const tempMsg={id:'gvmtmp_'+Date.now(),sender:String(myPhone),group_id:groupId,
                file_name:null,duration_ms:durMs,waveform,timestamp:new Date().toISOString(),
                status:'uploading',message_type:'voice'};
            const el=renderBubble(tempMsg);
            el.appendChild(tempEl);
            grpChat.appendChild(el); scrollGrpToBottom(true);
            const fd=new FormData();
            fd.append('audio',blob,'voice.'+ext);
            fd.append('sender',String(myPhone));
            fd.append('group_id',groupId);
            fd.append('duration_ms',durMs);
            fd.append('waveform',JSON.stringify(waveform));
            try{
                const res=await fetch('/api/voice/upload',{method:'POST',body:fd});
                const data=await res.json();
                // Don't wireAudio here — socket onVoiceMessage handles it
                // If socket already confirmed it (fast path), bubble is already wired
                if(!data.success){ el.remove(); }
            }catch(e){ el.remove(); }
        }

        function renderBubble(msg){
            const isOut=String(msg.sender)===String(myPhone);
            const wave=msg.waveform&&msg.waveform.length?msg.waveform:Array(40).fill(0.5);
            const wrap=document.createElement('div');
            wrap.className='gvm-bubble '+(isOut?'gvm-out':'gvm-in')+(msg.status==='uploading'?' gvm-uploading':'');
            wrap.dataset.vmId=msg.id||'';
            wrap.dataset.file=msg.file_name||'';
            const play=document.createElement('button'); play.className='gvm-play'; play.innerHTML=pi();
            wrap.appendChild(play);
            const ww=document.createElement('div'); ww.className='gvm-ww';
            const waveEl=document.createElement('div'); waveEl.className='gvm-wave';
            wave.forEach((a)=>{
                const b=document.createElement('div'); b.className='gvm-bar';
                b.style.height=Math.max(4,Math.round(a*28))+'px'; waveEl.appendChild(b);
            });
            ww.appendChild(waveEl);
            const meta=document.createElement('div'); meta.className='gvm-meta';
            const dur=document.createElement('span'); dur.className='gvm-dur';
            dur.textContent=fmtMs(msg.duration_ms||0); meta.appendChild(dur);
            ww.appendChild(meta); wrap.appendChild(ww);

            // Wrap in gvm-react-wrap so reactions appear below the audio bubble
            const outer=document.createElement('div');
            outer.className='gvm-react-wrap '+(isOut?'gvm-out':'gvm-in');
            outer.dataset.msgType='voice';
            if(msg.id){ outer.dataset.messageId=String(msg.id); wrap.dataset.messageId=String(msg.id); }
            if(msg.sender){ outer.dataset.sender=String(msg.sender); }

            if(!isOut){
                const lbl=document.createElement('div');
                lbl.style.cssText='font-size:11px;font-weight:600;color:var(--accent);margin-bottom:3px;';
                lbl.textContent=getSenderName(msg.sender);
                outer.appendChild(lbl);
            }
            outer.appendChild(wrap);
            if(msg.file_name&&msg.status!=='uploading') wireAudio(wrap,msg.file_name,msg.duration_ms||0,wave,isOut,msg);
            // Render reactions loaded from history
            if(msg.reactions&&msg.reactions.length){
                const rc=document.createElement('div');
                rc.className='grp-msg-reactions';
                const counts={};
                msg.reactions.forEach(r=>{ counts[r.emoji]=(counts[r.emoji]||0)+1; });
                Object.entries(counts).forEach(([emoji,count])=>{
                    const pill=document.createElement('div'); pill.className='grp-reaction-pill';
                    pill.innerHTML=`<span>${emoji}</span><span class="grp-r-count">${count}</span>`;
                    rc.appendChild(pill);
                });
                outer.appendChild(rc);
            }
            // Prevent play button tap from triggering long-press context menu
            play.addEventListener('touchstart', e => e.stopPropagation(), {passive:true});
            play.addEventListener('touchend',   e => e.stopPropagation(), {passive:true});
            return outer;
        }

        function wireAudio(wrap,fileName,durMs,wave,isOut,msg){
            const audio=new Audio('/api/voice/file/'+fileName);
            audio.preload='metadata';
            let playing=false;
            const bars=wrap.querySelectorAll('.gvm-bar');
            const durEl=wrap.querySelector('.gvm-dur');
            const play=wrap.querySelector('.gvm-play');
            const waveEl=wrap.querySelector('.gvm-wave');
            waveEl.addEventListener('click',e=>{
                const r=waveEl.getBoundingClientRect();
                const ratio=(e.clientX-r.left)/r.width;
                if(audio.duration){ audio.currentTime=ratio*audio.duration; upd(); }
            });
            waveEl.addEventListener('touchstart', e=>e.stopPropagation(), {passive:true});
            waveEl.addEventListener('touchend',   e=>e.stopPropagation(), {passive:true});
            audio.addEventListener('timeupdate',upd);
            audio.addEventListener('ended',()=>{
                playing=false; play.innerHTML=pi();
                bars.forEach(b=>b.classList.remove('gvm-p'));
                durEl.textContent=fmtMs(durMs);
            });
            play.addEventListener('click',()=>{
                if(playing){ audio.pause(); playing=false; play.innerHTML=pi(); }
                else{
                    document.querySelectorAll('.gvm-audio-active,.vm-audio-active').forEach(a=>{
                        a.pause(); a.dispatchEvent(new Event('ended')); a.classList.remove('gvm-audio-active','vm-audio-active');
                    });
                    audio.play().then(()=>{
                        audio.classList.add('gvm-audio-active'); playing=true; play.innerHTML=pauseI();
                    }).catch(err=>{
                        play.style.opacity='0.5';
                        setTimeout(()=>play.style.opacity='',600);
                    });
                }
            });
            function upd(){
                if(!audio.duration) return;
                const pct=audio.currentTime/audio.duration,filled=Math.floor(pct*bars.length);
                bars.forEach((b,i)=>i<filled?b.classList.add('gvm-p'):b.classList.remove('gvm-p'));
                durEl.textContent=fmtMs(Math.max(0,(audio.duration-audio.currentTime)*1000));
            }
        }

        socket.on('voice_deleted', data => {
            // Remove the bubble for everyone in the group
            // Require group_id to match — ignore DM deletions (data.group_id=null) on this page
            if (!data.group_id || String(data.group_id) !== String(groupId)) return;
            const el = document.querySelector('[data-message-id="' + String(data.id) + '"]');
            if (el) {
                const wrapper = el.closest('.message-group') || el;
                wrapper.remove();
            }
        });

        // Socket: a member was removed from the group
        socket.on('group_member_removed', function(data) {
            if (String(data.group_id) !== String(groupId)) return;
            if (String(data.removed_phone) === String(myPhone)) {
                alert('You have been removed from this group.');
                window.location.href = '/?phone=' + encodeURIComponent(myPhone);
                return;
            }
            loadGroupInfo();
        });

        socket.on('voice_message',msg=>{
            if(String(msg.group_id)!==String(groupId)) return;
            if(String(msg.sender)===String(myPhone)){
                // Find the uploading temp bubble (may have marker or uploading class)
                const tmpEl=document.querySelector('.gvm-bubble.gvm-uploading');
                if(tmpEl){
                    // Only wireAudio once — check it hasn't been wired already
                    if(!tmpEl.dataset.wired){
                        tmpEl.dataset.wired='1';
                        tmpEl.dataset.vmId=String(msg.id);
                        tmpEl.dataset.file=msg.file_name;
                        tmpEl.dataset.messageId=String(msg.id);
                        tmpEl.classList.remove('gvm-uploading');
                        if(tmpEl.parentElement) tmpEl.parentElement.dataset.messageId=String(msg.id);
                        wireAudio(tmpEl,msg.file_name,msg.duration_ms||0,msg.waveform||[],true,msg);
                    }
                }
                return;
            }
            if(msg.id && document.querySelector('[data-message-id="'+msg.id+'"]')) return;
            const el=renderBubble(msg);
            attachBubbleEvents(el);
            grpChat.appendChild(el); scrollGrpToBottom(true);
        });

        function drawLive(){
            const c=cvs(); if(!c) return;
            const ctx=c.getContext('2d'); const W=c.width,H=c.height;
            const buf=new Uint8Array(analyser.frequencyBinCount);
            (function frame(){
                if(!isRec) return; animFrame=requestAnimationFrame(frame);
                analyser.getByteFrequencyData(buf);
                const amp=buf.reduce((s,v)=>s+v,0)/(buf.length*255);
                ampHistory.push(amp); if(ampHistory.length>200) ampHistory.shift();
                ctx.clearRect(0,0,W,H);
                const bars=56,barW=W/bars-2;
                for(let i=0;i<bars;i++){
                    const idx=Math.min(Math.floor(i*ampHistory.length/bars),ampHistory.length-1);
                    const a=ampHistory[idx]||0,bH=Math.max(4,a*(H-8));
                    ctx.fillStyle=`rgba(255,255,255,${0.35+a*0.65})`;
                    ctx.beginPath(); ctx.roundRect(i*(barW+2),(H-bH)/2,barW,bH,2); ctx.fill();
                }
            })();
        }

        function deriveWave(bars=40){
            if(!ampHistory.length) return Array(bars).fill(0.5);
            const out=[],step=ampHistory.length/bars;
            for(let i=0;i<bars;i++){
                const s=Math.floor(i*step),e=Math.min(Math.floor((i+1)*step),ampHistory.length);
                let sum=0; for(let j=s;j<e;j++) sum+=ampHistory[j];
                out.push(Math.round(Math.min(1,(e>s?sum/(e-s):0)*2.5)*1000)/1000);
            }
            return out;
        }

        function cleanup(){
            isRec=false; clearInterval(timerInterval); cancelAnimationFrame(animFrame);
            if(mediaRecorder&&mediaRecorder.state!=='inactive') mediaRecorder.stop();
            mediaRecorder?.stream?.getTracks().forEach(t=>t.stop());
            if(audioCtx){ audioCtx.close(); audioCtx=null; }
            analyser=null; liveSource=null; timerEl().textContent='0:00';
        }

        function fmtMs(ms){ const s=Math.ceil(ms/1000); return Math.floor(s/60)+':'+String(s%60).padStart(2,'0'); }
        function pi(){ return '<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>'; }
        function pauseI(){ return '<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>'; }

        return { toggle, cancel, stopAndSend, renderBubble };
    })();
    // Expose GVM renderBubble for loadMessages (must be after GVM is defined)
    function GVM_renderBubble(msg){ return GVM.renderBubble(msg); }
    // Now safe to load messages — GVM_renderBubble is available
    loadMessages();
    // ─────────────────────────────────────────────────────────────
</script>
</body>
</html>"""


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
                        WHERE gm3.group_id = g.id ORDER BY gm3.timestamp DESC LIMIT 1) as last_message
                FROM groups g
                JOIN group_members gm ON g.id = gm.group_id AND gm.user_phone = ?
                LEFT JOIN group_members gm2 ON g.id = gm2.group_id
                GROUP BY g.id
                ORDER BY g.created_at DESC
            """, (phone,))
            rows = c.fetchall()
        finally:
            return_db_connection(conn)
        groups = [{"id": r[0], "name": r[1], "avatar_letter": r[2],
                   "created_by": r[3], "member_count": r[4], "last_message": r[5]} for r in rows]
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
            c.execute("DELETE FROM contacts WHERE user_phone=%s AND contact_phone=%s",
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
            c.execute("SELECT created_by FROM groups WHERE id=%s", (group_id,))
            row = c.fetchone()
            if not row:
                return jsonify({"success": False, "error": "Group not found"}), 404
            if str(row[0]) != user_phone:
                # Non-creators just leave the group instead
                c.execute("DELETE FROM group_members WHERE group_id=%s AND user_phone=%s",
                          (group_id, user_phone))
                conn.commit()
                action = "left"
                affected_members = [user_phone]
            else:
                # Fetch all members before deleting so we can bust their caches
                c.execute("SELECT user_phone FROM group_members WHERE group_id=%s", (group_id,))
                affected_members = [r[0] for r in c.fetchall()]
                # Creator deletes the group entirely
                c.execute("DELETE FROM message_reactions WHERE message_id IN "
                          "(SELECT id FROM group_messages WHERE group_id=?)", (group_id,))
                c.execute("DELETE FROM group_messages WHERE group_id=%s", (group_id,))
                c.execute("DELETE FROM group_members WHERE group_id=%s", (group_id,))
                c.execute("DELETE FROM groups WHERE id=%s", (group_id,))
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
                WHERE g.name=%s AND g.created_by=%s
                AND g.created_at >= NOW() - INTERVAL '10 seconds'
            """, (name, created_by))
            existing = c.fetchone()
            if existing:
                group_id = existing[0]
            else:
                c.execute("INSERT INTO groups (name, created_by, avatar_letter) VALUES (%s, %s, %s) RETURNING id",
                          (name, created_by, avatar_letter))
                group_id = c.fetchone()[0]

                # Add creator as admin
                c.execute("INSERT INTO group_members (group_id, user_phone, role) VALUES (%s, %s, 'admin')",
                          (group_id, created_by))
                # Add members
                for m in members:
                    m = str(m).strip()
                    if m and m != created_by:
                        c.execute("INSERT INTO users(phone, last_online) VALUES(%s, %s) ON CONFLICT (phone) DO NOTHING",
                                  (m, datetime.now().isoformat()))
                        c.execute("INSERT INTO group_members (group_id, user_phone) VALUES (%s, %s)",
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
            c.execute("SELECT 1 FROM group_members WHERE group_id=%s AND user_phone=%s", (group_id, user_phone))
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
                c.execute("""
                    SELECT message_id, user_phone, emoji
                    FROM message_reactions
                    WHERE message_id = ANY(%s)
                """, (list(msg_ids),))
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
            c.execute("SELECT id, name, avatar_letter, created_by FROM groups WHERE id=%s", (group_id,))
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
            c.execute("SELECT role FROM group_members WHERE group_id=%s AND user_phone=%s",
                      (group_id, removed_by))
            row = c.fetchone()
            if not row or row[0] != 'admin':
                return jsonify({"success": False, "error": "Only the group admin can remove members"}), 403
            # Cannot remove yourself through this endpoint (use leave/delete instead)
            if removed_by == target:
                return jsonify({"success": False, "error": "Cannot remove yourself"}), 400
            c.execute("DELETE FROM group_members WHERE group_id=%s AND user_phone=%s",
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
            c.execute("SELECT role FROM group_members WHERE group_id=%s AND user_phone=%s", (group_id, added_by))
            row = c.fetchone()
            if not row or row[0] != 'admin':
                return jsonify({"success": False, "error": "Only admins can add members"}), 403

            now_iso = datetime.now().isoformat()
            added = 0
            for phone in members:
                phone = str(phone).strip()
                if not phone:
                    continue
                c.execute("INSERT INTO users(phone, last_online) VALUES(%s,%s)", (phone, now_iso))
                result = c.execute(
                    "INSERT INTO group_members (group_id, user_phone, role) VALUES (%s,%s,'member') ON CONFLICT DO NOTHING",
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
            c.execute("SELECT 1 FROM group_members WHERE group_id=%s AND user_phone=%s", (group_id, phone))
            if not c.fetchone():
                return "Access denied", 403
            c.execute("SELECT name, avatar_letter FROM groups WHERE id=%s", (group_id,))
            g = c.fetchone()
            if not g:
                return "Group not found", 404
            group_name = g[0]
            avatar_letter = g[1] or g[0][0].upper()
        finally:
            return_db_connection(conn)
        return render_template_string(group_chat_html,
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
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'sent',%s) RETURNING id
        """, (sender, receiver or None, group_id, file_path, unique_name,
              len(audio_data), duration_ms, waveform_json, timestamp))
        conn.commit()
        voice_id = c.fetchone()[0]
    finally:
        return_db_connection(conn)

    # Update contacts last_message for DM voice messages
    if not group_id and receiver:
        try:
            conn2 = get_db_connection()
            try:
                c2 = conn2.cursor()
                c2.execute("INSERT INTO contacts(user_phone,contact_phone,contact_name,last_message,last_sender) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(user_phone, contact_phone) DO UPDATE SET last_message=EXCLUDED.last_message, last_sender=EXCLUDED.last_sender, timestamp=EXCLUDED.timestamp",
                           (sender, receiver, "", "🎤 Voice message", sender))
                c2.execute("UPDATE contacts SET last_message='🎤 Voice message', last_sender=%s, timestamp=%s WHERE user_phone=%s AND contact_phone=%s",
                           (sender, timestamp, sender, receiver))
                c2.execute("INSERT INTO contacts(user_phone,contact_phone,contact_name,last_message,last_sender) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(user_phone, contact_phone) DO UPDATE SET last_message=EXCLUDED.last_message, last_sender=EXCLUDED.last_sender, timestamp=EXCLUDED.timestamp",
                           (receiver, sender, "", "🎤 Voice message", sender))
                c2.execute("UPDATE contacts SET last_message='🎤 Voice message', last_sender=%s, timestamp=%s WHERE user_phone=%s AND contact_phone=%s",
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
            c.execute("SELECT 1 FROM group_members WHERE group_id=%s AND user_phone=%s", (group_id, user_phone))
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
            c2.execute("SELECT message_id, user_phone, emoji FROM message_reactions WHERE message_id = ANY(%s)", (list(ids),))
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
        c.execute("UPDATE voice_messages SET status='listened',listened_at=%s WHERE id=%s AND receiver=%s",
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
        c.execute("SELECT sender, receiver, message_type FROM messages WHERE id=%s", (message_id,))
        row = c.fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'Not found'}), 404
        sender, receiver, message_type = row
        if sender != user_phone:
            return jsonify({'success': False, 'error': 'Forbidden'}), 403

        if scope == 'everyone':
            # Delete file from disk if media
            if message_type in ('image', 'video', 'audio', 'file'):
                c.execute("SELECT file_path FROM messages WHERE id=%s", (message_id,))
                fp = c.fetchone()
                if fp and fp[0]:
                    try: os.remove(fp[0])
                    except OSError: pass
            c.execute("DELETE FROM message_reactions WHERE message_id=%s", (message_id,))
            c.execute("DELETE FROM messages WHERE id=%s", (message_id,))
        else:
            # Delete only for me — mark deleted
            c.execute("UPDATE messages SET deleted_for=COALESCE(deleted_for||',','') || %s WHERE id=%s",
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
        c.execute("SELECT file_path,sender,receiver,group_id FROM voice_messages WHERE id=%s", (voice_id,))
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
        c.execute("DELETE FROM message_reactions WHERE message_id=%s", (voice_id,))
        c.execute("DELETE FROM voice_messages WHERE id=%s", (voice_id,))
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
        c.execute("SELECT last_online FROM users WHERE phone=%s", (phone,))
        row = c.fetchone()
        last_online = row[0] if row else None
    finally:
        return_db_connection(conn)
    return jsonify({'phone': phone, 'status': 'offline', 'last_online': last_online})

# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# SOCIAL NETWORK ROUTES
# ─────────────────────────────────────────────────────────────────────────────

SOCIAL_IMAGE_FOLDER = os.path.join('uploads', 'social')
os.makedirs(SOCIAL_IMAGE_FOLDER, exist_ok=True)

def _social_user_info(phone, conn):
    """Fetch display info for a user (name, avatar, headline, bio)."""
    c = conn.cursor()
    c.execute("SELECT phone, display_name, avatar_color, avatar_emoji, avatar_photo, bio, headline, location, website, username FROM users WHERE phone=%s", (phone,))
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
            c.execute("SELECT following_phone FROM social_connections WHERE follower_phone=%s AND status='accepted'", (phone,))
            following = [r[0] for r in c.fetchall()] + [phone]
            c.execute("""
                SELECT sp.id, sp.author_phone, sp.content, sp.image_path, sp.likes, sp.timestamp
                FROM social_posts sp
                WHERE sp.author_phone = ANY(%s)
                ORDER BY sp.timestamp DESC LIMIT 50
            """, (list(following),))
            posts = c.fetchall()
            result = []
            for row in posts:
                post_id, author, content, image_path, likes, ts = row
                info = _social_user_info(author, conn)
                c.execute("SELECT user_phone FROM social_post_likes WHERE post_id=%s", (post_id,))
                liked_by = [r[0] for r in c.fetchall()]
                c.execute("SELECT COUNT(*) FROM social_comments WHERE post_id=%s", (post_id,))
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
            c.execute("INSERT INTO social_posts(author_phone, content, image_path) VALUES(%s,%s,%s) RETURNING id",
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
        c.execute("SELECT id, author_phone, content, image_path, likes, timestamp FROM social_posts WHERE id=%s", (post_id,))
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
        c.execute("SELECT author_phone, image_path FROM social_posts WHERE id=%s", (post_id,))
        row = c.fetchone()
        if not row or row[0] != phone:
            return jsonify({'success': False, 'error': 'Forbidden'}), 403
        if row[1]:
            try: os.remove(os.path.join(SOCIAL_IMAGE_FOLDER, row[1]))
            except OSError: pass
        c.execute("DELETE FROM social_comments WHERE post_id=%s", (post_id,))
        c.execute("DELETE FROM social_post_likes WHERE post_id=%s", (post_id,))
        c.execute("DELETE FROM social_posts WHERE id=%s", (post_id,))
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
        c.execute("SELECT 1 FROM social_post_likes WHERE post_id=%s AND user_phone=%s", (post_id, phone))
        if c.fetchone():
            c.execute("DELETE FROM social_post_likes WHERE post_id=%s AND user_phone=%s", (post_id, phone))
            c.execute("UPDATE social_posts SET likes=MAX(0,likes-1) WHERE id=%s", (post_id,))
            action = 'unliked'
        else:
            c.execute("INSERT INTO social_post_likes(post_id, user_phone) VALUES(%s,%s)", (post_id, phone))
            c.execute("UPDATE social_posts SET likes=likes+1 WHERE id=%s", (post_id,))
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
        c.execute("SELECT id, author_phone, content, timestamp FROM social_comments WHERE post_id=%s ORDER BY timestamp ASC LIMIT 100", (post_id,))
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
        c.execute("INSERT INTO social_comments(post_id, author_phone, content) VALUES(%s,%s,%s)", (post_id, phone, content))
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
        c.execute("SELECT status FROM social_connections WHERE follower_phone=%s AND following_phone=%s", (from_phone, to_phone))
        existing = c.fetchone()
        if existing:
            return jsonify({'success': False, 'error': 'Already requested or connected'})
        # Check if the other person already sent a request — auto-accept
        c.execute("SELECT status FROM social_connections WHERE follower_phone=%s AND following_phone=%s", (to_phone, from_phone))
        reverse = c.fetchone()
        if reverse and reverse[0] == 'pending':
            c.execute("UPDATE social_connections SET status='accepted' WHERE follower_phone=%s AND following_phone=%s", (to_phone, from_phone))
            c.execute("INSERT INTO social_connections(follower_phone, following_phone, status) VALUES(%s,%s,'accepted')", (from_phone, to_phone))
        else:
            c.execute("INSERT INTO social_connections(follower_phone, following_phone, status) VALUES(%s,%s,'pending')", (from_phone, to_phone))
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
            c.execute("UPDATE social_connections SET status='accepted' WHERE follower_phone=%s AND following_phone=%s AND status='pending'", (from_phone, to_phone))
            c.execute("INSERT INTO social_connections(follower_phone, following_phone, status) VALUES(%s,%s,'accepted')", (to_phone, from_phone))
        else:
            c.execute("DELETE FROM social_connections WHERE follower_phone=%s AND following_phone=%s", (from_phone, to_phone))
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
        c.execute("SELECT following_phone, status FROM social_connections WHERE follower_phone=%s", (phone,))
        outgoing = {r[0]: r[1] for r in c.fetchall()}  # phone -> status
        c.execute("SELECT follower_phone, status FROM social_connections WHERE following_phone=%s", (phone,))
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
        c.execute("DELETE FROM social_connections WHERE (follower_phone=%s AND following_phone=%s) OR (follower_phone=%s AND following_phone=%s)",
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
        c.execute("SELECT following_phone FROM social_connections WHERE follower_phone=%s AND status='accepted'", (phone,))
        following = [r[0] for r in c.fetchall()]
        c.execute("SELECT follower_phone FROM social_connections WHERE following_phone=%s AND status='accepted'", (phone,))
        followers = [r[0] for r in c.fetchall()]
        c.execute("SELECT following_phone FROM social_connections WHERE follower_phone=%s AND status='pending'", (phone,))
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
        c.execute("SELECT follower_phone FROM social_connections WHERE following_phone=%s AND status='pending'", (phone,))
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
        c.execute("SELECT following_phone FROM social_connections WHERE follower_phone=%s", (phone,))
        already = {r[0] for r in c.fetchall()} | {phone}
        c.execute("SELECT phone, display_name, avatar_color, avatar_emoji, avatar_photo, bio, headline FROM users WHERE phone != %s ORDER BY last_online DESC LIMIT 60", (phone,))
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
        c.execute("SELECT id, content, image_path, likes, timestamp FROM social_posts WHERE author_phone=%s ORDER BY timestamp DESC LIMIT 30", (phone,))
        rows = c.fetchall()
        result = []
        for row in rows:
            post_id, content, image_path, likes, ts = row
            c.execute("SELECT user_phone FROM social_post_likes WHERE post_id=%s", (post_id,))
            liked_by = [r[0] for r in c.fetchall()]
            c.execute("SELECT COUNT(*) FROM social_comments WHERE post_id=%s", (post_id,))
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
        c.execute("SELECT COUNT(*) FROM social_posts WHERE author_phone=%s", (phone,))
        posts = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM social_connections WHERE following_phone=%s AND status='accepted'", (phone,))
        followers = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM social_connections WHERE follower_phone=%s AND status='accepted'", (phone,))
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
        c.execute("UPDATE users SET headline=%s, location=%s, website=%s WHERE phone=%s", (headline, location, website, phone))
        conn.commit()
    finally:
        return_db_connection(conn)
    cache.delete(f"profile_{phone}")
    return jsonify({'success': True})

# ─────────────────────────────────────────────────────────────────────────────

# ----------------- Security Information -----------------
@app.route("/security")
def security_info():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Exomnia Security</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            h1 { color: #0E4950; }
            .feature { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Exomnia Security Features</h1>

            <div class="feature">
                <h3>End-to-End Encryption</h3>
                <p>All messages are encrypted with AES-256-GCM before being stored or transmitted.</p>
            </div>

            <div class="feature">
                <h3>Secure Key Derivation</h3>
                <p>Unique encryption keys are derived for each user using PBKDF2 with 100,000 iterations.</p>
            </div>

            <div class="feature">
                <h3>Forward Secrecy</h3>
                <p>Each conversation uses a unique key combination from both participants.</p>
            </div>

            <div class="feature">
                <h3>Message Integrity</h3>
                <p>AES-GCM provides authentication ensuring messages cannot be tampered with.</p>
            </div>

            <div class="feature">
                <h3>Message Reactions</h3>
                <p>React to messages with emojis that are synced across all users in real-time.</p>
            </div>

            <div class="feature">
                <h3>File Sharing</h3>
                <p>Securely share images, videos, and documents with end-to-end encryption.</p>
            </div>

            <div class="feature">
                <h3>Enhanced Performance</h3>
                <p>Connection pooling, caching, and infinite scroll for optimal user experience.</p>
            </div>
        </div>
    </body>
    </html>
    """

# ----------------- Database Init (always runs, even under Gunicorn) -----------------
init_db()
_opt_conn = get_db_connection()
try:
    _opt_conn.commit()  # No PRAGMA optimize needed for Postgres
finally:
    return_db_connection(_opt_conn)

# ----------------- Server Run -----------------
if __name__=="__main__":
    print("Exomnia Super App on http://0.0.0.0:5000")
    print("Main App: http://0.0.0.0:5000/main")
    print("Chat Login: http://0.0.0.0:5000/")
    print("Security Info: http://0.0.0.0:5000/security")
    print("All systems integrated")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
