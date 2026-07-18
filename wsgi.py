"""
Production entry point for gunicorn (Render, Railway, etc.).

Locally, keep using `python run.py`. For a production host, point
the start command at this file instead, e.g.:

    gunicorn --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 1 wsgi:app

The gevent monkey-patch MUST happen before any other import (including
Flask/Flask-SocketIO), which is why it's the very first thing here.
"""
from gevent import monkey
monkey.patch_all()

from exomnia.app import create_app

app = create_app()
