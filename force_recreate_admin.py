from database import Database
from werkzeug.security import generate_password_hash
import sqlite3

def force_recreate_admin():
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    email = "admin@gmail.com"
    password = "admin123"
    
    print(f"--- Recreating Admin Account: {email} ---")
    
    # 1. Delete ALL users with this email to be safe
    cursor.execute("DELETE FROM users WHERE email = ?", (email,))
    print("Deleted existing admin user.")
    
    # 2. Insert fresh
    hashed_pw = generate_password_hash(password)
    
    # Use 'senior' role as it satisfies the CHECK constraint, but set is_admin=1
    cursor.execute('''
        INSERT INTO users (username, full_name, email, password_hash, role, is_admin, bio)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', ('admin_user', 'System Administrator', email, hashed_pw, 'senior', 1, 'Official Administrator'))
    
    conn.commit()
    print("Admin account created successfully.")
    
    # 3. Verify immediately
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    if user:
        print(f"VERIFIED: ID={user['id']}, Email={user['email']}, IsAdmin={user['is_admin']}")
    else:
        print("VERIFICATION FAILED: User not found in DB.")
        
    conn.close()

if __name__ == "__main__":
    force_recreate_admin()
