import sqlite3
import os

db_path = 'app.db'
if not os.path.exists(db_path):
    print(f"Error: {db_path} not found")
    exit(1)

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("--- Users Table Schema ---")
cursor.execute("PRAGMA table_info(users)")
columns = cursor.fetchall()
for col in columns:
    print(f"{col['cid']}: {col['name']} ({col['type']}) default: {col['dflt_value']}")

print("\n--- Current User Values ---")
# Get the first few users to check values
cursor.execute("SELECT id, username, notify_messages, notify_activities, notify_stories, notify_groups FROM users LIMIT 5")
users = cursor.fetchall()
for user in users:
    print(dict(user))

conn.close()
