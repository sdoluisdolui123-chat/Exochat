import os
import sys

# Add project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import app for both local and gunicorn
from App import app, socketio

if __name__ == '__main__':
    from config import get_config
    config = get_config()
    socketio.run(
        app,
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        allow_unsafe_werkzeug=True
    )
