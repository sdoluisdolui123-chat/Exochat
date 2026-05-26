#!/usr/bin/env python
"""Entry point for the application"""
import sys
import os

# Add the project directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == '__main__':
    # Import after adding to path
    from main9 import app, socketio
    from config import get_config
else:
    # For gunicorn
    from main9 import app, socketio
    from config import get_config

# Expose app for gunicorn
if __name__ != '__main__':
    config = get_config()
