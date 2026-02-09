"""
Fix script to ensure all notification-related database columns exist.
Run this once: python fix_all_notifications.py
"""

import sqlite3

def fix_all_notifications():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    print("Checking notification setup...")
    
    # 1. Ensure notifications table exists
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
    print("[OK] notifications table exists")
    
    # 2. Ensure user preference columns exist
    columns_to_add = [
        ('notify_messages', 'INTEGER DEFAULT 1'),
        ('notify_activities', 'INTEGER DEFAULT 1'),
        ('notify_stories', 'INTEGER DEFAULT 1'),
        ('notify_groups', 'INTEGER DEFAULT 1'),
    ]
    
    for col_name, col_def in columns_to_add:
        try:
            cursor.execute(f"SELECT {col_name} FROM users LIMIT 1")
            print(f"[OK] Column {col_name} exists")
        except sqlite3.OperationalError:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
            print(f"[ADDED] Column {col_name}")
    
    # 3. Set default notification preferences to ON for existing users
    cursor.execute("""
        UPDATE users 
        SET notify_messages = 1, 
            notify_activities = 1, 
            notify_stories = 1, 
            notify_groups = 1
        WHERE notify_messages IS NULL 
           OR notify_activities IS NULL 
           OR notify_stories IS NULL 
           OR notify_groups IS NULL
    """)
    
    conn.commit()
    conn.close()
    
    print("\n=== All notification features are ready! ===")
    print("\nNotification triggers:")
    print("  - New Messages: Someone sends you a message")
    print("  - Activity Reminders: You join an activity")
    print("  - Story Interactions: Someone likes/comments your story")
    print("  - Group Updates: Someone joins your group")

if __name__ == "__main__":
    fix_all_notifications()
