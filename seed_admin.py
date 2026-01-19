from database import Database
from werkzeug.security import generate_password_hash

def create_admin():
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Check if admin exists
    cursor.execute("SELECT * FROM users WHERE email = 'admin@togethersg.com'")
    user = cursor.fetchone()
    
    if user:
        print("Admin account already exists.")
        # Ensure it has admin rights
        cursor.execute("UPDATE users SET is_admin = 1 WHERE email = 'admin@togethersg.com'")
        print("Updated existing admin privileges.")
    else:
        # Create new admin
        password_hash = generate_password_hash('admin123')
        cursor.execute('''
            INSERT INTO users (username, full_name, email, password_hash, role, is_admin)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', 'System Administrator', 'admin@togethersg.com', password_hash, 'senior', 1))
        print("Admin account created: admin@togethersg.com / admin123")
        
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_admin()
