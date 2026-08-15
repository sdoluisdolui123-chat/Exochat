"""
Small shared helpers: rate limiting, file-extension checks, phone validation.
"""
import re
import time
from datetime import datetime, timezone
from functools import wraps
from collections import defaultdict

from flask import request, jsonify


def utc_now_iso():
    """Current time as a UTC ISO-8601 string with an explicit 'Z' suffix.

    Presence/"last seen" timestamps must be timezone-unambiguous: the
    frontend does `new Date(isoStr)` in the user's browser, and a naive
    string with no 'Z'/offset (e.g. from `datetime.now().isoformat()`) gets
    interpreted as *local browser time* instead of the server's time. For a
    user several hours off from the server's clock, that silently shifts
    "last seen" by that same number of hours (e.g. showing "last seen 6
    hours ago" for someone who just went offline). Always stamping presence
    times in UTC with 'Z' keeps the frontend's diff-from-now math correct
    regardless of either side's timezone.
    """
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


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


def validate_phone(phone):
    pattern = r'^\+\d{1,4}\d{6,14}$'
    return re.match(pattern, phone) is not None


def validate_email(email):
    pattern = r'^[^@\s]+@[^@\s]+\.[^@\s]+$'
    return re.match(pattern, email) is not None


def generate_reset_code():
    """6-digit numeric code for password-reset emails."""
    import secrets
    return f"{secrets.randbelow(1000000):06d}"
