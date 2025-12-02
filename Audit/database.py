import sqlite3
import config

def init_db():
    conn = sqlite3.connect('vulnnote.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            is_private INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # SECURITY FLAW 6: Hardcoded admin credentials in database initialization
    try:
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'admin123', 1)")
        cursor.execute("INSERT INTO users (username, password) VALUES ('user1', 'password1')")
    except:
        pass
    
    conn.commit()
    conn.close()

def get_db_connection():
    return sqlite3.connect('vulnnote.db')

# SECURITY FLAW 7: SQL Injection vulnerable function
def search_notes(user_id, search_term):
    """Search notes for a user - VULNERABLE TO SQL INJECTION"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM notes WHERE user_id = {user_id} AND content LIKE '%{search_term}%'"
    
    print(f"[DEBUG] Executing query: {query}")  # SECURITY FLAW 8: Information disclosure
    
    cursor.execute(query)  # SQL Injection point
    results = cursor.fetchall()
    conn.close()
    return results

# SECURITY FLAW 9: IDOR vulnerability (no authorization check)
def get_note_by_id(note_id):
    """Get any note by ID without checking ownership"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
    note = cursor.fetchone()
    conn.close()
    return note  # Returns any note, regardless of user
