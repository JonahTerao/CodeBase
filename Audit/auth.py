import config
from functools import wraps
from flask import session, request
import hashlib

# SECURITY FLAW 10: Weak password hashing
def hash_password(password):
    """Weak MD5 hashing - deprecated and insecure"""
    return hashlib.md5(password.encode()).hexdigest()

# SECURITY FLAW 11: Insecure session management
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # SECURITY FLAW 12: Redirect without validation
            return "Please login first"
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # SECURITY FLAW 13: Weak API key check (timing attack vulnerable)
        api_key = request.headers.get('X-API-Key')
        if api_key == config.ADMIN_API_KEY:  # String comparison timing issue
            return f(*args, **kwargs)
        return "Admin access required", 403
    return decorated_function

# SECURITY FLAW 14: Predictable session token generation
def generate_session_token(user_id):
    import time
    token = hashlib.md5(f"{user_id}{time.time()}{config.SECRET_KEY}".encode()).hexdigest()
    return token
