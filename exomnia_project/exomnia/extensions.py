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
from flask_compress import Compress

# Performance optimization
logging.basicConfig(level=logging.WARNING)

app = Flask(__name__, template_folder='templates')
# In production, set SECRET_KEY as an environment variable to a fixed,
# random value (e.g. `python -c "import secrets; print(secrets.token_hex(32))"`).
# Without it, a new random key is generated every restart/redeploy, which
# silently invalidates every logged-in user's session each time.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['COMPRESS_MIMETYPES'] = [
    'text/html', 'text/css', 'text/xml',
    'application/json', 'application/javascript', 'text/javascript',
]
app.config['COMPRESS_LEVEL'] = 6
app.config['COMPRESS_MIN_SIZE'] = 500
Compress(app)
# NOTE: must be an ABSOLUTE path. Flask's send_from_directory() resolves a
# relative directory against the app's root_path (the `exomnia` package
# folder), while os.makedirs()/file.save() below resolve relative paths
# against the process's current working directory. Those two are not the
# same folder, which silently broke every uploaded file (upload looked
# successful, but the file could never be found again to serve it).
#
# DATA_DIR lets you point uploads at a persistent disk in production (e.g.
# Render's "Persistent Disk"), the same as the database (see db.py), so
# uploaded photos/files survive restarts/redeploys. Falls back to the
# project-local 'uploads' folder if DATA_DIR isn't set (unchanged local
# behavior).
_data_dir = os.environ.get('DATA_DIR', '')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(_data_dir), 'uploads') if _data_dir else os.path.abspath('uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
VOICE_UPLOAD_FOLDER = os.path.join(app.config['UPLOAD_FOLDER'], 'voice')
os.makedirs(VOICE_UPLOAD_FOLDER, exist_ok=True)
ALLOWED_AUDIO_EXTENSIONS = {'webm', 'ogg', 'wav', 'mp3', 'm4a', 'aac'}
MAX_VOICE_FILE_SIZE = 10 * 1024 * 1024

# Performance optimizations for SocketIO
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='gevent',
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=16 * 1024 * 1024,
    logger=False,
    engineio_logger=False,
    compression_threshold=1024,
)
