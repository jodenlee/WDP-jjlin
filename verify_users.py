from database import Database

def verify_users():
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, username, email, is_admin FROM users")
    users = cursor.fetchall()
    
    print("--- User List ---")
    for user in users:
        print(f"ID: {user['id']} | Username: {user['username']} | Email: {user['email']} | Admin: {user['is_admin']}")
        
    conn.close()

if __name__ == '__main__':
    verify_users()
