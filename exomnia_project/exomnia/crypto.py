"""
AES-256-GCM message encryption, keyed off SECRET_KEY + per-user PBKDF2 derivation.
"""
import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .extensions import app


# ----------------- Encryption Setup -----------------
class MessageEncryptor:
    def __init__(self):
        self.master_key = self._derive_master_key()
        self._key_cache = {}  # cache derived keys — PBKDF2 is slow

    def _derive_master_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'exomnia_salt_2024',
            iterations=100000,
        )
        return kdf.derive(app.config['SECRET_KEY'].encode())

    def generate_user_key(self, phone_number):
        if phone_number in self._key_cache:
            return self._key_cache[phone_number]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=phone_number.encode(),
            iterations=100000,
        )
        key = kdf.derive(self.master_key)
        self._key_cache[phone_number] = key
        return key

    def _conversation_key(self, phone_a, phone_b):
        """Always produce the same key regardless of who is sender/receiver."""
        p1, p2 = sorted([phone_a, phone_b])
        k1 = self.generate_user_key(p1)
        k2 = self.generate_user_key(p2)
        return hashlib.sha256(k1 + k2).digest()

    def encrypt_message(self, message, sender_phone, receiver_phone):
        try:
            conversation_key = self._conversation_key(sender_phone, receiver_phone)
            nonce = os.urandom(12)
            aesgcm = AESGCM(conversation_key)
            encrypted_data = aesgcm.encrypt(nonce, message.encode(), None)
            return base64.b64encode(nonce + encrypted_data).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_message(self, encrypted_message, sender_phone, receiver_phone):
        # Attempt 1: current sorted key (correct method)
        try:
            conversation_key = self._conversation_key(sender_phone, receiver_phone)
            raw = base64.b64decode(encrypted_message.encode('utf-8'))
            nonce, ciphertext = raw[:12], raw[12:]
            return AESGCM(conversation_key).decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            pass
        # Attempt 2: old key order — sender first (pre-fix messages)
        try:
            k1 = self.generate_user_key(sender_phone)
            k2 = self.generate_user_key(receiver_phone)
            old_key = hashlib.sha256(k1 + k2).digest()
            raw = base64.b64decode(encrypted_message.encode('utf-8'))
            nonce, ciphertext = raw[:12], raw[12:]
            return AESGCM(old_key).decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            pass
        # Attempt 3: old key order — receiver first (pre-fix messages, flipped)
        try:
            k1 = self.generate_user_key(receiver_phone)
            k2 = self.generate_user_key(sender_phone)
            old_key = hashlib.sha256(k1 + k2).digest()
            raw = base64.b64decode(encrypted_message.encode('utf-8'))
            nonce, ciphertext = raw[:12], raw[12:]
            return AESGCM(old_key).decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            pass
        # All attempts failed — return None so caller can fall back to stored plaintext
        return None

# Initialize encryptor
encryptor = MessageEncryptor()

