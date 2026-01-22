from database import Database
from werkzeug.security import generate_password_hash

def create_requested_admin():
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    email = 'admin@gmail.com'
    password = 'admin123'
    
    # Check if admin exists
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    
    if user:
        print(f"Admin account {email} already exists.")
        # Ensure password matches and is_admin is 1
        password_hash = generate_password_hash(password)
        cursor.execute("UPDATE users SET is_admin = 1, password_hash = ? WHERE email = ?", (password_hash, email))
        print("Updated existing admin privileges and password.")
    else:
        # Create new admin
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (username, full_name, email, password_hash, role, is_admin)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin_user', 'System Administrator', email, password_hash, 'senior', 1))
        print(f"Admin account created: {email} / {password}")
        
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_requested_admin()
