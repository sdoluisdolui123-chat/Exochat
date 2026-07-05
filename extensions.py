"""
Core Flask + SocketIO instances shared across the whole app.
Every other module imports `app` / `socketio` from here instead of
creating its own — this avoids circular imports.
"""
import os
import logging
import secrets

from flask import Flask
from flask_socketio import SocketIO

# Performance optimization
logging.basicConfig(level=logging.WARNING)

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = secrets.token_hex(32)
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
    async_mode='gevent',
    ping_timeout=20,
    ping_interval=10,
    max_http_buffer_size=16 * 1024 * 1024,
    logger=False,
    engineio_logger=False,
    compression_threshold=1024,
)
