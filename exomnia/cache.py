"""
Simple in-memory TTL cache used to avoid re-hitting SQLite on hot reads.
"""
import threading
import time


# ----------------- Enhanced Cache System -----------------
class EnhancedCache:
    def __init__(self, ttl=300):
        self.cache = {}
        self.ttl = ttl
        self.lock = threading.Lock()
    
    def get(self, key):
        with self.lock:
            if key in self.cache:
                data, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    return data
                else:
                    del self.cache[key]
        return None
    
    def set(self, key, value):
        with self.lock:
            self.cache[key] = (value, time.time())
    
    def delete(self, key):
        with self.lock:
            if key in self.cache:
                del self.cache[key]
    
    def clear_pattern(self, pattern):
        """Clear all keys matching pattern"""
        with self.lock:
            keys_to_delete = [key for key in self.cache if pattern in key]
            for key in keys_to_delete:
                del self.cache[key]
    
    def clear_for_users(self, user1, user2):
        """Clear all cache for two users"""
        with self.lock:
            keys_to_delete = []
            for key in self.cache:
                if (user1 in key) or (user2 in key):
                    keys_to_delete.append(key)
            for key in keys_to_delete:
                del self.cache[key]

cache = EnhancedCache(ttl=60)  # 60-second cache — safe since we invalidate on every write
