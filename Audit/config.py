# SECURITY FLAW 1: Hardcoded secrets in source code
SECRET_KEY = 'super_secret_key_12345_change_in_production!'
ADMIN_API_KEY = 'vulnnote_admin_2024_never_change'
DATABASE_PASSWORD = 'password123'

# SECURITY FLAW 2: Debug mode enabled in "production-like" config
DEBUG = True

# SECURITY FLAW 3: Weak cryptographic configuration
CRYPTO_ALGO = 'DES'  # Weak, deprecated algorithm

# SECURITY FLAW 4: Insecure CORS settings (wildcard)
ALLOWED_ORIGINS = ['*']

# SECURITY FLAW 5: Excessive file upload settings
MAX_FILE_SIZE = 1024 * 1024 * 100  # 100MB - too large
ALLOWED_EXTENSIONS = ['txt', 'pdf', 'jpg', 'png', 'exe']  # .exe allowed!
