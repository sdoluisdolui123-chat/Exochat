"""
Small shared helpers: rate limiting, file-extension checks, phone validation.
"""
import re
import time
from functools import wraps
from collections import defaultdict

from flask import request, jsonify


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

