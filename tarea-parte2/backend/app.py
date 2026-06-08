from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import json
import os
import time

app = Flask(__name__)
CORS(app)

DB_PATH = 'db.sqlite3'
UPLOAD_FOLDER = 'uploads'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS historical_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            upload_date TEXT,
            total_events INTEGER,
            total_alerts INTEGER,
            observations TEXT,
            filepath TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Initialize DB on startup
init_db()

@app.route('/api/history', methods=['GET'])
def get_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, filename, upload_date, total_events, total_alerts, observations, filepath FROM historical_analysis ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            'id': row[0],
            'filename': row[1],
            'upload_date': row[2],
            'total_events': row[3],
            'total_alerts': row[4],
            'observations': row[5],
            'filepath': row[6]
        })
    return jsonify(history)

@app.route('/api/history/<int:id>', methods=['GET'])
def get_history_detail(id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT filepath, observations FROM historical_analysis WHERE id = ?', (id,))
    row = cursor.fetchone()
    conn.close()
    
    if row and row[0]:
        filepath = row[0]
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)
            return jsonify({
                'observations': row[1],
                'data': data
            })
    return jsonify({'error': 'Not found or file missing'}), 404

@app.route('/api/history', methods=['POST'])
def save_history():
    data = request.json
    filename = data.get('filename', f'analysis_{int(time.time())}.json')
    upload_date = data.get('upload_date', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    total_events = data.get('total_events', 0)
    total_alerts = data.get('total_alerts', 0)
    observations = data.get('observations', '')
    raw_json = data.get('raw_json', [])
    
    filepath = os.path.join(UPLOAD_FOLDER, f'{int(time.time())}_{filename}')
    
    # Save JSON to file
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(raw_json, f)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO historical_analysis (filename, upload_date, total_events, total_alerts, observations, filepath)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (filename, upload_date, total_events, total_alerts, observations, filepath))
    conn.commit()
    inserted_id = cursor.lastrowid
    conn.close()
    
    return jsonify({'id': inserted_id, 'status': 'success', 'filepath': filepath})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
