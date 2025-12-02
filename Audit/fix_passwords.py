import sqlite3
import hashlib

print("Fixing password hashes...")

def hash_pw(password):
    return hashlib.md5(password.encode()).hexdigest()

# Connect to database
conn = sqlite3.connect('vulnnote.db')
c = conn.cursor()

# Update admin password
c.execute("UPDATE users SET password = ? WHERE username = 'admin'", 
          (hash_pw('admin123'),))
print("✓ Updated admin password")

# Update user1 password  
c.execute("UPDATE users SET password = ? WHERE username = 'user1'",
          (hash_pw('password1'),))
print("✓ Updated user1 password")

# Save changes
conn.commit()

# Verify
c.execute("SELECT username, password FROM users")
print("\nUpdated passwords:")
for username, password in c.fetchall():
    print(f"  {username}: {password} (length: {len(password)})")

conn.close()
print("\n✅ Passwords are now MD5 hashed!")
print("Try login again with username: admin, password: admin123")
