from database import Database
import sqlite3

def fix_schema():
    print("--- Fixing Database Schema ---")
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Check existing columns
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    print(f"Current columns in users: {columns}")
    
    required_cols = ['notify_messages', 'notify_activities', 'notify_stories', 'notify_groups']
    
    for col in required_cols:
        if col not in columns:
            print(f"Adding missing column: {col}")
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col} INTEGER DEFAULT 1")
                print(f"Successfully added {col}")
            except Exception as e:
                print(f"Error adding {col}: {e}")
        else:
            print(f"Column {col} already exists.")
            
    conn.commit()
    conn.close()
    print("Schema fix complete.")

if __name__ == "__main__":
    fix_schema()
