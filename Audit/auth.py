import config
from functools import wraps
from flask import session, request
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return "Please login first"
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key == config.ADMIN_API_KEY:
            return f(*args, **kwargs)
        return "Admin access required", 403
    return decorated_function

def generate_session_token(user_id):
    import time
    token = hashlib.md5(f"{user_id}{time.time()}{config.SECRET_KEY}".encode()).hexdigest()
    return token
