"""
SQLite connection pooling and schema initialization.
"""
import os
import sqlite3
import threading

# DATA_DIR lets you point the database at a persistent disk in production
# (e.g. Render's "Persistent Disk" mounted at /var/data) so it survives
# restarts/redeploys. Locally, if DATA_DIR isn't set, this behaves exactly
# as before (chat.db in the project folder).
DATA_DIR = os.environ.get("DATA_DIR", "")
if DATA_DIR:
    os.makedirs(DATA_DIR, exist_ok=True)
DB_NAME = os.path.join(DATA_DIR, "chat.db") if DATA_DIR else "chat.db"

# Connection pool for database
def _configure_conn(conn):
    """Apply performance PRAGMAs to a new SQLite connection."""
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-16000")       # 16 MB page cache
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA mmap_size=134217728")     # 128 MB memory-mapped I/O
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

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
                return _configure_conn(
                    sqlite3.connect(DB_NAME, timeout=20, check_same_thread=False)
                )
    
    def return_connection(self, conn):
        with self.lock:
            if len(self.connections) < self.max_connections:
                self.connections.append(conn)
            else:
                conn.close()

connection_pool = ConnectionPool()

def get_db_connection():
    return connection_pool.get_connection()

def return_db_connection(conn):
    connection_pool.return_connection(conn)


# ----------------- Database Setup -----------------
def init_db():
    conn = get_db_connection()
    try:
        c = conn.cursor()
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
                c.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT {default}")
            except Exception:
                pass
        c.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                user_phone TEXT,
                contact_phone TEXT,
                contact_name TEXT,
                last_message TEXT,
                last_sender TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(user_phone, contact_phone)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                receiver TEXT,
                message TEXT,
                encrypted_message TEXT,
                status TEXT DEFAULT 'sent',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
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
            c.execute("ALTER TABLE messages ADD COLUMN deleted_for TEXT DEFAULT NULL")
        except Exception:
            pass  # column already exists
        c.execute("""
            CREATE TABLE IF NOT EXISTS message_reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER,
                user_phone TEXT,
                emoji TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(message_id, user_phone)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_by TEXT NOT NULL,
                avatar_letter TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER,
                user_phone TEXT,
                role TEXT DEFAULT 'member',
                joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(group_id, user_phone),
                FOREIGN KEY(group_id) REFERENCES groups(id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER,
                sender TEXT,
                message TEXT,
                message_type TEXT DEFAULT 'text',
                file_path TEXT,
                file_name TEXT,
                file_size INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
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
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                sender        TEXT    NOT NULL,
                receiver      TEXT,
                group_id      INTEGER,
                file_path     TEXT    NOT NULL,
                file_name     TEXT    NOT NULL,
                file_size     INTEGER NOT NULL,
                duration_ms   INTEGER DEFAULT 0,
                waveform_data TEXT,
                status        TEXT    DEFAULT 'sent',
                timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
                listened_at   DATETIME,
                FOREIGN KEY(group_id) REFERENCES groups(id)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_voice_dm ON voice_messages(sender, receiver, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_voice_group ON voice_messages(group_id, timestamp)")

        # ── Social Network Tables ──────────────────────────────────────────────
        # Migration: if social_posts exists with wrong schema, rebuild it
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='social_posts'")
        if c.fetchone():
            c.execute("PRAGMA table_info(social_posts)")
            existing_cols = [row[1] for row in c.fetchall()]
            if 'author_phone' not in existing_cols:
                c.execute("DROP TABLE IF EXISTS social_comments")
                c.execute("DROP TABLE IF EXISTS social_post_likes")
                c.execute("DROP TABLE IF EXISTS social_posts")

        c.execute("""
            CREATE TABLE IF NOT EXISTS social_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author_phone TEXT NOT NULL,
                content TEXT NOT NULL,
                image_path TEXT DEFAULT \'\',
                likes INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(author_phone) REFERENCES users(phone)
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
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(follower_phone, following_phone),
                FOREIGN KEY(follower_phone) REFERENCES users(phone),
                FOREIGN KEY(following_phone) REFERENCES users(phone)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_social_conn_follower ON social_connections(follower_phone)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_social_conn_following ON social_connections(following_phone)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS social_post_likes (
                post_id INTEGER NOT NULL,
                user_phone TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(post_id, user_phone)
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS social_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                author_phone TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(post_id) REFERENCES social_posts(id),
                FOREIGN KEY(author_phone) REFERENCES users(phone)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_social_comments_post ON social_comments(post_id, timestamp)")

        # Migration: add headline/location columns to users for social profiles
        for col, default in [('headline', "''"), ('location', "''"), ('website', "''")]:
            try:
                c.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT {default}")
            except Exception:
                pass

        # Migration: add email column (required at signup going forward, so
        # existing users can add a password-reset method via their profile)
        try:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
        except Exception:
            pass

        c.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT NOT NULL,
                code TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY(phone) REFERENCES users(phone)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_password_resets_phone ON password_resets(phone, used, expires_at)")

        conn.commit()
    finally:
        return_db_connection(conn)

