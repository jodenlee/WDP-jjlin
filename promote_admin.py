from database import Database

def promote_admin():
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    email = 'admin@togethersg.com'
    
    # Check if user exists
    cursor.execute("SELECT id, username, is_admin FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    
    if user:
        print(f"Found user: {user['username']} (ID: {user['id']}, Is Admin: {user['is_admin']})")
        # Promote
        cursor.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user['id'],))
        conn.commit()
        print("User promoted to Admin successfully.")
    else:
        print("User admin@togethersg.com not found. Please register the account first.")
        
    conn.close()

if __name__ == '__main__':
    promote_admin()
