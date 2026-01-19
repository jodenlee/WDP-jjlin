from database import Database
from werkzeug.security import generate_password_hash

def fix_admin_and_paths():
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # 1. Reset Admin Password
    password_hash = generate_password_hash('admin123')
    # Update if exists
    cursor.execute("UPDATE users SET password_hash = ? WHERE email = 'admin@togethersg.com'", (password_hash,))
    # Ensure is_admin is 1
    cursor.execute("UPDATE users SET is_admin = 1 WHERE email = 'admin@togethersg.com'")
    
    print("Admin password reset to 'admin123'.")

    # 2. Fix Story Image Paths (Convert absolute to relative if possible, or just leave them if we change template)
    # Actually, let's just wipe the current story_images for a clean slate if easy, OR try to fix strings.
    # The bug was: INSERT INTO story_images ... VALUES (..., full_url)
    # We want: uploads/filename.png
    # Let's clean up bad entries that start with http
    
    # Fetch all
    cursor.execute("SELECT id, image_path FROM story_images")
    rows = cursor.fetchall()
    
    for row in rows:
        path = row['image_path']
        if 'static/' in path:
            # Extract relative path after static/
            relative_path = path.split('static/')[-1]
            cursor.execute("UPDATE story_images SET image_path = ? WHERE id = ?", (relative_path, row['id']))
            print(f"Fixed path: {path} -> {relative_path}")
            
    conn.commit()
    conn.close()

if __name__ == '__main__':
    fix_admin_and_paths()
