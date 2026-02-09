"""
Fix script to add the notifications table to the database.
Run this once: python fix_notifications.py
"""

import sqlite3

def fix_notifications_table():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # Create notifications table
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
    
    conn.commit()
    conn.close()
    print("Notifications table created successfully!")

if __name__ == "__main__":
    fix_notifications_table()
