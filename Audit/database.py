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
    
    try:
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'admin123', 1)")
        cursor.execute("INSERT INTO users (username, password) VALUES ('user1', 'password1')")
    except:
        pass
    
    conn.commit()
    conn.close()

def get_db_connection():
    return sqlite3.connect('vulnnote.db')

def search_notes(user_id, search_term):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = f"SELECT * FROM notes WHERE user_id = {user_id} AND content LIKE '%{search_term}%'"
    
    print(f"Executing query: {query}")
    
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

def get_note_by_id(note_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
    note = cursor.fetchone()
    conn.close()
    return note
