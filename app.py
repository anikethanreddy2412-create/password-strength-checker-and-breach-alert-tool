import hashlib
import sqlite3
from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)
DB_FILE = "database.db"

def init_db():
    """Initializes the SQLite database for logging anonymized check stats."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS check_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            password_length INTEGER,
            strength_score TEXT,
            is_breached INTEGER,
            breach_count INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def check_hibp_api(password):
    """Checks the HIBP API using SHA-1 k-anonymity."""
    # 1. Generate full SHA-1 hash and uppercase it
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return 0  # Treat API errors gracefully
            
        # 2. Parse the lines of suffixes returned by the API
        # Response format is SUFFIX:COUNT
        lines = response.text.splitlines()
        for line in lines:
            target_suffix, count = line.split(':')
            if target_suffix == suffix:
                return int(count) # Found a match!
                
        return 0 # No breach found
    except requests.RequestException:
        return 0

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check-breach', ZIP_METHODS=['POST'])
@app.route('/check-breach', methods=['POST'])
def check_breach():
    data = request.json
    password = data.get('password', '')
    strength_score = data.get('score', 'Unknown')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
        
    # Check HIBP API safely
    breach_count = check_hibp_api(password)
    is_breached = 1 if breach_count > 0 else 0
    
    # Log the anonymized metadata to SQLite
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO check_logs (password_length, strength_score, is_breached, breach_count)
        VALUES (?, ?, ?, ?)
    ''', (len(password), strength_score, is_breached, breach_count))
    conn.commit()
    conn.close()
    
    return jsonify({
        'is_breached': bool(is_breached),
        'breach_count': breach_count
    })

if __name__ == '__main__':
    init_db()
    app.run(debug=True)