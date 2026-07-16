"""
App factory: pulls together the Flask app, the DB, and every route /
socket module. Importing route/socket modules is what actually
registers their @app.route and @socketio.on decorators.
"""
from .extensions import app, socketio
from .db import init_db, get_db_connection, return_db_connection

# Side-effecting imports: these register routes & socket handlers.
from . import routes  # noqa: F401
from . import sockets  # noqa: F401


def create_app():
    """Initialize the database (schema + one-time PRAGMA optimize) and
    return the shared Flask app instance, ready to be run."""
    init_db()
    conn = get_db_connection()
    try:
        conn.execute("PRAGMA optimize")
        conn.commit()
    finally:
        return_db_connection(conn)
    return app
