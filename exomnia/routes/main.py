"""
Top-level pages: the /main dashboard shell and the /security info page.
"""
from flask import render_template, request

from ..extensions import app


@app.route("/main")
def main_app():
    logged_in_phone = request.args.get('logged_in_phone')
    return render_template("main_app.html")


# ----------------- Security Information -----------------
@app.route("/security")
def security_info():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Exomnia Security</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            h1 { color: #0E4950; }
            .feature { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Exomnia Security Features</h1>

            <div class="feature">
                <h3>End-to-End Encryption</h3>
                <p>All messages are encrypted with AES-256-GCM before being stored or transmitted.</p>
            </div>

            <div class="feature">
                <h3>Secure Key Derivation</h3>
                <p>Unique encryption keys are derived for each user using PBKDF2 with 100,000 iterations.</p>
            </div>

            <div class="feature">
                <h3>Forward Secrecy</h3>
                <p>Each conversation uses a unique key combination from both participants.</p>
            </div>

            <div class="feature">
                <h3>Message Integrity</h3>
                <p>AES-GCM provides authentication ensuring messages cannot be tampered with.</p>
            </div>

            <div class="feature">
                <h3>Message Reactions</h3>
                <p>React to messages with emojis that are synced across all users in real-time.</p>
            </div>

            <div class="feature">
                <h3>File Sharing</h3>
                <p>Securely share images, videos, and documents with end-to-end encryption.</p>
            </div>

            <div class="feature">
                <h3>Enhanced Performance</h3>
                <p>Connection pooling, caching, and infinite scroll for optimal user experience.</p>
            </div>
        </div>
    </body>
    </html>
    """
