from database import Database
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

def fix_admin():
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    email = "admin@gmail.com"
    password = "admin123"
    
    print(f"--- Fixing Admin Account: {email} ---")
    
    # 1. Delete existing
    cursor.execute("DELETE FROM users WHERE email = ?", (email,))
    print("Deleted existing admin user (if any).")
    
    # 2. Create new
    hashed_pw = generate_password_hash(password)
    
    try:
        cursor.execute('''
            INSERT INTO users (username, full_name, email, password_hash, role, is_admin, bio)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ('admin_user', 'Admin User', email, hashed_pw, 'senior', 1, 'Official Administrator'))
        print("Inserted new admin user.")
    except sqlite3.Error as e:
        print(f"Error inserting user: {e}")
        return

    conn.commit()
    
    # 3. Verify
    user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
    if user:
        print(f"User retrieved from DB: ID={user['id']}, Role={user['role']}, IsAdmin={user['is_admin']}")
        if check_password_hash(user['password_hash'], password):
            print("SUCCESS: Password verified correctly.")
        else:
            print("FAILURE: Password hash mismatch.")
            
    conn.close()

if __name__ == "__main__":
    fix_admin()
