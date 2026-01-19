from database import Database
from werkzeug.security import generate_password_hash

def hard_reset_admin():
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Delete existing admin
    cursor.execute("DELETE FROM users WHERE email = 'admin@togethersg.com'")
    print("Deleted old admin account.")
    
    # Create new admin
    password = 'admin123'
    password_hash = generate_password_hash(password)
    
    # Insert (using 1 for confirmed id or letting autoincrement)
    cursor.execute('''
        INSERT INTO users (username, full_name, email, password_hash, role, is_admin)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', ('admin', 'System Administrator', 'admin@togethersg.com', password_hash, 'senior', 1))
    
    print(f"Created admin: admin@togethersg.com / {password}")
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    hard_reset_admin()
