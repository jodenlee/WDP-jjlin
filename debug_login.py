from database import Database
from werkzeug.security import check_password_hash, generate_password_hash

def debug_login():
    print("--- Debugging Login Logic ---")
    
    email = 'admin@gmail.com'
    password = 'admin123'
    
    print(f"Attempting login for: {email} with password: {password}")
    
    db = Database()
    
    # 1. Check if user exists
    print("Querying database...")
    user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
    
    if not user:
        print("ERROR: User not found in database!")
        
        # List all users to see what's there
        print("Listing all users found in DB:")
        users = db.query("SELECT id, username, email FROM users")
        for u in users:
            print(f" - {u['username']} ({u['email']})")
        return

    print(f"User FOUND: ID={user['id']}, Role={user['role']}, IsAdmin={user['is_admin']}")
    print(f"Stored Hash: {user['password_hash']}")
    
    # 2. Check password
    is_valid = check_password_hash(user['password_hash'], password)
    
    if is_valid:
        print("SUCCESS: check_password_hash returned True. Credentials are correct.")
    else:
        print("FAILURE: check_password_hash returned False. Password mismatch.")
        
        # Test generation
        new_hash = generate_password_hash(password)
        print(f"New hash for '{password}' would be: {new_hash}")
        
    # 3. Double check input sanitization used in app.py
    input_email = email.lower().strip()
    print(f"App uses sanitized email: '{input_email}'")
    if input_email != user['email']:
        print(f"WARNING: Email case/whitespace mismatch? DB has '{user['email']}'")

if __name__ == "__main__":
    debug_login()
