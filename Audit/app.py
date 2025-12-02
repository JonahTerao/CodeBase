from flask import Flask, request, jsonify, session, render_template, send_file
import os
import database
import auth
import config
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = './uploads'

# Initialize database with vulnerable setup
database.init_db()

# SECURITY FLAW 15: No rate limiting on login endpoint
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = database.get_db_connection()
    cursor = conn.cursor()
    
    # SECURITY FLAW 16: SQL Injection in login
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{auth.hash_password(password)}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['is_admin'] = user[3]
        session['token'] = auth.generate_session_token(user[0])
        return jsonify({"message": "Login successful", "user_id": user[0]})
    
    return jsonify({"error": "Invalid credentials"}), 401

# SECURITY FLAW 17: Information disclosure in error handling
@app.route('/notes/<int:note_id>')
@auth.login_required
def get_note(note_id):
    try:
        note = database.get_note_by_id(note_id)
        if note:
            return jsonify({
                "id": note[0],
                "user_id": note[1],  # SECURITY FLAW 18: Exposing user_id
                "title": note[2],
                "content": note[3],
                "private": bool(note[4])
            })
        return jsonify({"error": "Note not found"}), 404
    except Exception as e:
        # SECURITY FLAW 19: Detailed error messages
        return jsonify({"error": f"Database error: {str(e)}"}), 500

# SECURITY FLAW 20: XSS vulnerability
@app.route('/notes/create', methods=['POST'])
@auth.login_required
def create_note():
    title = request.form.get('title', '')
    content = request.form.get('content', '')
    
    # VULNERABLE: No input sanitization for XSS
    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (session['user_id'], title, content)
    )
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Note created", "title": title})  # Reflected XSS potential

# SECURITY FLAW 21: Path traversal in file download
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    # VULNERABLE: No path traversal prevention
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return "File not found", 404

# SECURITY FLAW 22: Insecure file upload
@app.route('/upload', methods=['POST'])
@auth.login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    # SECURITY FLAW: Only checks extension, not content type
    if file and file.filename.split('.')[-1].lower() in config.ALLOWED_EXTENSIONS:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({"message": "File uploaded", "filename": filename})
    
    return jsonify({"error": "File type not allowed"}), 400

# SECURITY FLAW 23: Admin endpoint with IDOR
@app.route('/admin/user_notes/<int:user_id>')
@auth.admin_required
def get_user_notes(user_id):
    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notes WHERE user_id = ?", (user_id,))
    notes = cursor.fetchall()
    conn.close()
    
    # SECURITY FLAW: Returns all notes without checking if admin should see them
    return jsonify({"notes": notes})

# SECURITY FLAW 24: Debug endpoint exposed
@app.route('/debug/users')
def debug_users():
    if config.DEBUG:  # Should be False in production
        conn = database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, is_admin FROM users")
        users = cursor.fetchall()
        conn.close()
        return jsonify({"users": users})
    return "Not found", 404

# SECURITY FLAW 25: Search with SQL Injection
@app.route('/search')
@auth.login_required
def search():
    query = request.args.get('q', '')
    user_id = session['user_id']
    
    # Calls the vulnerable search_notes function
    results = database.search_notes(user_id, query)
    return jsonify({"results": results})

# Vulnerable frontend endpoint
@app.route('/')
def index():
    # SECURITY FLAW 26: Basic reflected XSS in template
    search_query = request.args.get('search', '')
    return render_template('index.html', search_query=search_query)

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(host='0.0.0.0', port=5000, debug=config.DEBUG)  # SECURITY FLAW 27: Debug mode, binds to all interfaces
