from database import Database
from werkzeug.security import check_password_hash

db = Database()
admin = db.query("SELECT * FROM users WHERE email='admin@gmail.com'", one=True)

if admin:
    print(f"Admin found: {admin['email']}")
    print(f"Is Admin: {admin['is_admin']}")
    if check_password_hash(admin['password_hash'], 'admin123'):
        print("Password is correct.")
    else:
        print("Password mismatch!")
else:
    print("Admin NOT found!")
