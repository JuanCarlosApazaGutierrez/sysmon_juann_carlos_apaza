import sqlite3
import json
import os
import time

DB_PATH = 'db.sqlite3'
SAMPLE_JSON_PATH = r'c:\Asignacion-Sysmon\sample-events.json'
UPLOAD_FOLDER = 'uploads'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def init_sample():
    if not os.path.exists(SAMPLE_JSON_PATH):
        print(f"Sample file not found at {SAMPLE_JSON_PATH}")
        return

    with open(SAMPLE_JSON_PATH, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)
    
    # data might be a dict with Events or an array directly
    events_array = data.get('Events', []) if isinstance(data, dict) and 'Events' in data else data
    total_events = len(events_array) if isinstance(events_array, list) else 0
    
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
    
    # Check if already inserted
    cursor.execute('SELECT count(*) FROM historical_analysis WHERE filename = ?', ('sample-events.json',))
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO historical_analysis (filename, upload_date, total_events, total_alerts, observations, filepath)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('sample-events.json', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), total_events, 0, 'Análisis de muestra inicial (carga por defecto)', SAMPLE_JSON_PATH))
        print("Sample data inserted successfully.")
    else:
        print("Sample data already exists.")
        
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_sample()
