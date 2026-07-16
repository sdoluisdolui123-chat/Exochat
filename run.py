"""
Entry point. Run with:  python run.py

Keeps the gevent monkey-patch as the very first thing that happens,
before any other import — this must stay at the top of this file.
"""
from gevent import monkey
monkey.patch_all()

from exomnia.app import create_app
from exomnia.extensions import socketio

if __name__ == "__main__":
    app = create_app()
    print("Exomnia Super App on http://0.0.0.0:5000")
    print("Main App: http://0.0.0.0:5000/main")
    print("Chat Login: http://0.0.0.0:5000/")
    print("Security Info: http://0.0.0.0:5000/security")
    print("All systems integrated (gevent WSGI server)")

    from gevent.pywsgi import WSGIServer
    from geventwebsocket.handler import WebSocketHandler

    http_server = WSGIServer(("0.0.0.0", 5000), app, handler_class=WebSocketHandler)
    http_server.serve_forever()
