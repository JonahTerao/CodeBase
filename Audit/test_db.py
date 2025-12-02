import sqlite3

print("=== Checking Database ===\n")

# Connect to database
conn = sqlite3.connect('vulnnote.db')
cursor = conn.cursor()

# Check if users table exists
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
if cursor.fetchone():
    print("✓ Users table exists")
    
    # Get all users
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    
    print(f"\nFound {len(users)} users:")
    for user in users:
        print(f"  ID: {user[0]}, Username: {user[1]}, Password: {user[2]}, Admin: {user[3]}")
else:
    print("✗ Users table doesn't exist!")
    print("Creating database...")
    
    # Import and initialize
    import database
    database.init_db()
    
    # Check again
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    print(f"\nNow have {len(users)} users:")
    for user in users:
        print(f"  ID: {user[0]}, Username: {user[1]}, Password: {user[2]}, Admin: {user[3]}")

conn.close()
print("\n=== Done ===")
