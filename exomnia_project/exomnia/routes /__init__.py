
"""
Importing this package registers every route module's @app.route
decorators onto the shared Flask `app` instance (see extensions.py).
Order doesn't matter for Flask routing, but we keep it roughly the
same as the original monolith for readability.
"""
from . import auth
from . import main
from . import files
from . import contacts
from . import profile
from . import messages
from . import chat
from . import groups
from . import voice
from . import social

__all__ = [
    "auth", "main", "files", "contacts", "profile",
    "messages", "chat", "groups", "voice", "social",
]
