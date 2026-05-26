#!/usr/bin/env python
"""Entry point for the application - Gunicorn compatible"""
import sys
import os

# Add the project directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import for gunicorn
from App import app, socketio
from config import get_config

# For local development
if __name__ == '__main__':
    config = get_config()
    socketio.run(
        app,
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        allow_unsafe_werkzeug=True
    )
