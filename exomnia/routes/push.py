"""
Web Push notifications — lets the app show real OS/home-screen
notifications (via the browser's push service) even when the app/tab
is fully closed, not just in-app socket toasts.

Flow:
  1. Frontend asks for Notification permission, subscribes via the
     service worker's PushManager, and POSTs the subscription here.
  2. We store it in `push_subscriptions`.
  3. When a message/notification event happens elsewhere (sockets.py),
     it calls send_push_to_phone(...) for any recipient who currently
     has no live socket connection (i.e. app is closed/backgrounded),
     which delivers a real push via the browser's push service.
  4. service-worker.js's 'push' listener shows the notification and
     'notificationclick' focuses/opens the app.
"""
from flask import request, jsonify

from ..extensions import app
from ..db import get_db_connection, return_db_connection

try:
    from pywebpush import webpush, WebPushException
    _PUSH_AVAILABLE = True
except Exception:
    _PUSH_AVAILABLE = False

# VAPID key pair for this app (identifies the server to push services).
# Public key is exposed to the frontend to create the subscription;
# private key is used server-side to sign push requests. Not secret in
# the sense of user data, but keep it stable — rotating it invalidates
# every existing subscription.
VAPID_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNiA4mVOHyx91qXC4
B6AuWAmq/kReb3jietU4Jq5gg1mhRANCAAT/R+BmoQ2bbPBGUqMKANYyCDJ3IUuQ
+HtMpYF6dteN6yzfbf4xwHfwDnq5/wFYeNWsNmNHdT9BJLRdujehGHpl
-----END PRIVATE KEY-----
"""
VAPID_PUBLIC_KEY_B64URL = "BP9H4GahDZts8EZSowoA1jIIMnchS5D4e0ylgXp2143rLN9t_jHAd_AOern_AVh41aw2Y0d1P0EktF26N6EYemU"
VAPID_CLAIMS = {"sub": "mailto:support@exochat.onrender.com"}


@app.route('/api/push/vapid_public_key')
def push_vapid_public_key():
    return jsonify({"key": VAPID_PUBLIC_KEY_B64URL})


@app.route('/api/push/subscribe', methods=['POST'])
def push_subscribe():
    data = request.get_json() or {}
    phone = str(data.get('phone', '')).strip()
    sub = data.get('subscription') or {}
    endpoint = sub.get('endpoint')
    keys = sub.get('keys') or {}
    p256dh = keys.get('p256dh')
    auth = keys.get('auth')

    if not phone or not endpoint or not p256dh or not auth:
        return jsonify({"success": False, "error": "Missing subscription data"}), 400

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO push_subscriptions (phone, endpoint, p256dh, auth)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(phone, endpoint) DO UPDATE SET p256dh=excluded.p256dh, auth=excluded.auth
        """, (phone, endpoint, p256dh, auth))
        conn.commit()
    finally:
        return_db_connection(conn)
    return jsonify({"success": True})


@app.route('/api/push/unsubscribe', methods=['POST'])
def push_unsubscribe():
    data = request.get_json() or {}
    phone = str(data.get('phone', '')).strip()
    endpoint = data.get('endpoint')
    if not phone or not endpoint:
        return jsonify({"success": False}), 400

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM push_subscriptions WHERE phone=? AND endpoint=?", (phone, endpoint))
        conn.commit()
    finally:
        return_db_connection(conn)
    return jsonify({"success": True})


def send_push_to_phone(phone, title, body, url='/main', tag=None):
    """Deliver a real OS/home-screen push notification to every device
    `phone` has subscribed from. Safe to call liberally — failures for
    individual (e.g. expired) subscriptions are swallowed and those
    subscriptions are cleaned up; it never raises to the caller."""
    if not _PUSH_AVAILABLE:
        return

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE phone=?", (phone,))
        subs = c.fetchall()
        if not subs:
            return

        import json
        payload = json.dumps({"title": title, "body": body, "url": url, "tag": tag})

        dead_endpoints = []
        for endpoint, p256dh, auth in subs:
            subscription_info = {
                "endpoint": endpoint,
                "keys": {"p256dh": p256dh, "auth": auth}
            }
            try:
                webpush(
                    subscription_info=subscription_info,
                    data=payload,
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims=dict(VAPID_CLAIMS),
                )
            except WebPushException as e:
                status = getattr(e.response, 'status_code', None)
                if status in (404, 410):  # gone / expired subscription
                    dead_endpoints.append(endpoint)
                else:
                    print(f"Web push error for {phone}: {e}")
            except Exception as e:
                print(f"Web push error for {phone}: {e}")

        if dead_endpoints:
            placeholders = ','.join('?' * len(dead_endpoints))
            c.execute(f"DELETE FROM push_subscriptions WHERE phone=? AND endpoint IN ({placeholders})",
                      [phone] + dead_endpoints)
            conn.commit()
    finally:
        return_db_connection(conn)
