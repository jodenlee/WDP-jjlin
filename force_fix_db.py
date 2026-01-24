import sqlite3
import os
import sys

print("STARTING DB FIX...", flush=True)

# 1. Determine DB Path
# Assuming app.db is in the same directory as this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'app.db')

print(f"Target DB Path: {DB_PATH}", flush=True)

if not os.path.exists(DB_PATH):
    print("ERROR: app.db does not exist in this directory!", flush=True)
    sys.exit(1)

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    print("Connected to SQLite.", flush=True)
    
    # 2. Check Columns
    cursor.execute("PRAGMA table_info(users)")
    cols_info = cursor.fetchall()
    current_columns = [r[1] for r in cols_info]
    print(f"Existing columns: {current_columns}", flush=True)
    
    columns_to_add = [
        ('notify_messages', 'INTEGER DEFAULT 1'),
        ('notify_activities', 'INTEGER DEFAULT 1'),
        ('notify_stories', 'INTEGER DEFAULT 1'),
        ('notify_groups', 'INTEGER DEFAULT 1')
    ]
    
    for col_name, col_type in columns_to_add:
        if col_name not in current_columns:
            print(f"Attempting to add column: {col_name}...", flush=True)
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
                print(f"SUCCESS: Added {col_name}", flush=True)
            except Exception as e:
                print(f"FAILED to add {col_name}: {e}", flush=True)
        else:
            print(f"Column {col_name} already exists. Skipping.", flush=True)
            
    conn.commit()
    conn.close()
    print("DB connection closed. Fix attempt finished.", flush=True)

except Exception as e:
    print(f"CRITICAL ERROR: {e}", flush=True)
