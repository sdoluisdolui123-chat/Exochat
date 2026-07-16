# Exomnia — split project layout

This is `main110.py` (13,331 lines, one file) split into normal modules
so it's actually reviewable and diffable in git. **No logic was changed**
— every route, socket handler, SQL query, and line of HTML/JS was moved
as-is; only three `render_template_string(...)` calls were switched to
`render_template(...)` now that their HTML lives in `templates/*.html`
files instead of Python string variables.

## Layout

```
run.py                      # entry point — gevent monkey-patch, then starts the server
exomnia/
  extensions.py             # the shared Flask `app` + SocketIO instance
  db.py                     # SQLite connection pool + init_db() schema
  cache.py                  # in-memory TTL cache (EnhancedCache)
  crypto.py                 # AES-256-GCM message encryption (MessageEncryptor)
  utils.py                  # rate limiting, file-extension checks, phone validation
  chat_utils.py             # shared realtime helpers (room naming, presence, etc.)
  sockets.py                # all @socketio.on(...) handlers
  app.py                    # create_app(): wires init_db() + routes + sockets together
  templates/
    main_app.html           # the /main dashboard shell
    signup.html / signin.html
    chat.html                # 1:1 chat page
    group_chat.html          # group chat page
  routes/
    auth.py                 # signup / signin
    main.py                 # /main dashboard route + /security info page
    files.py                # generic chat file upload/serving
    contacts.py              # contacts list + add contact
    profile.py                # profile read/update + avatar/banner upload
    messages.py                # paginated message history API
    chat.py                    # /chat/<contact_phone> page
    groups.py                   # group CRUD + membership + group chat page
    voice.py                    # voice messages + message delete + presence
    social.py                    # feed, posts, likes, comments, follow/connections
```

## Running it

```bash
pip install -r requirements.txt
python run.py
```

Same URLs as before:
- `/` — sign up
- `/signin` — sign in
- `/main` — dashboard
- `/chat/<contact_phone>` — 1:1 chat
- `/group/<group_id>` — group chat
- `/security` — security info page

## Why split this way

Each file maps to one contiguous section of the original file, so you
can diff any module against the corresponding line range of `main110.py`
and see they're identical (aside from the `render_template` swap and
added `import` lines at the top of each file). This makes it easy to
`git init`, commit this as a clean baseline, and then keep normal
per-file commits going forward instead of one enormous file.
