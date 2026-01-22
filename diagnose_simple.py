import sqlite3
import os

print("--- STARTING DIAGNOSTIC ---")
db_path = "app.db"
if not os.path.exists(db_path):
    print("app.db NOT FOUND in current directory!")
else:
    print(f"app.db found, size: {os.path.getsize(db_path)} bytes")

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    print("Connected to DB.")
    
    cursor.execute("SELECT id, username, email, role, is_admin FROM users")
    rows = cursor.fetchall()
    
    print(f"Found {len(rows)} users:")
    for row in rows:
        print(row)
        
    conn.close()
    print("Connection closed.")
except Exception as e:
    print(f"Error: {e}")

print("--- END DIAGNOSTIC ---")
