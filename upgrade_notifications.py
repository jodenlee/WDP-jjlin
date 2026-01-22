from database import Database
import sqlite3

def upgrade_db():
    print("--- Upgrading Database for Notifications ---")
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # 1. Create Notifications Table
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL, 
                content TEXT NOT NULL,
                link TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        print("Created notifications table.")
    except Exception as e:
        print(f"Error creating notifications table: {e}")

    # 2. Add Notification Settings to Users
    # We will add columns: notify_messages, notify_activities, notify_stories, notify_groups
    cols = ['notify_messages', 'notify_activities', 'notify_stories', 'notify_groups']
    
    for col in cols:
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col} INTEGER DEFAULT 1")
            print(f"Added column {col} to users.")
        except sqlite3.OperationalError:
            print(f"Column {col} already exists in users.")
            
    conn.commit()
    conn.close()
    print("Database upgrade complete.")

if __name__ == "__main__":
    upgrade_db()
