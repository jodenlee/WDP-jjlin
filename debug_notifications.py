"""
Debug script to check notifications in the database.
Run: python debug_notifications.py
"""

import sqlite3

def debug_notifications():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    print("=== ALL USERS AND THEIR NOTIFICATION PREFERENCES ===\n")
    users = cursor.execute("""
        SELECT id, username, email, notify_messages, notify_activities, notify_stories, notify_groups 
        FROM users
    """).fetchall()
    
    for u in users:
        print(f"User {u['id']}: {u['username']} ({u['email']})")
        print(f"   Messages: {u['notify_messages']}, Activities: {u['notify_activities']}, Stories: {u['notify_stories']}, Groups: {u['notify_groups']}")
    
    print("\n=== ALL NOTIFICATIONS (Last 20) ===\n")
    notifications = cursor.execute("""
        SELECT n.id, n.user_id, u.username, n.type, n.content, n.is_read, n.created_at
        FROM notifications n
        JOIN users u ON n.user_id = u.id
        ORDER BY n.created_at DESC
        LIMIT 20
    """).fetchall()
    
    if notifications:
        for n in notifications:
            status = "READ" if n['is_read'] else "UNREAD"
            print(f"[{status}] To: {n['username']} (ID:{n['user_id']})")
            print(f"   Type: {n['type']}")
            print(f"   Content: {n['content']}")
            print(f"   Time: {n['created_at']}")
            print()
    else:
        print("No notifications found in database.")
    
    conn.close()

if __name__ == "__main__":
    debug_notifications()
