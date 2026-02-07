import sqlite3

class Database:
    def __init__(self, db_file="app.db"):
        self.db_file = db_file
        self.init_db()

    def get_connection(self):
        """Returns a connection to the SQLite database."""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn

    def init_db(self):
        """Initializes the database with necessary tables."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # User table with authentication
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('senior', 'youth')),
                full_name TEXT,
                bio TEXT,
                profile_pic TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Story table (Seniors share stories)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                likes INTEGER DEFAULT 0,
                location TEXT,
                image_url TEXT,
                FOREIGN KEY (author_id) REFERENCES users (id)
            )
        ''')
        
        # Check if new columns exist (for manual migration in this session)
        try:
            cursor.execute("SELECT likes FROM stories LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE stories ADD COLUMN likes INTEGER DEFAULT 0")
            cursor.execute("ALTER TABLE stories ADD COLUMN location TEXT")
            cursor.execute("ALTER TABLE stories ADD COLUMN image_url TEXT")

        # Bookmarks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                story_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (story_id) REFERENCES stories (id),
                UNIQUE(user_id, story_id)
            )
        ''')

        # Story Likes Table (New)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS story_likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                story_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (story_id) REFERENCES stories (id),
                UNIQUE(user_id, story_id)
            )
        ''')
        
        # Activity table (Shared activities)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                type TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Comments Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                story_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (story_id) REFERENCES stories (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Groups Table (Community)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                image_url TEXT,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        ''')

        # Group Members Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(group_id, user_id)
            )
        ''')

        # Messages Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id)
            )
        ''')

        # Activity RSVPs Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_rsvps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                activity_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (activity_id) REFERENCES activities (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(activity_id, user_id)
            )
        ''')

        # Reports Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_id INTEGER NOT NULL,
                target_type TEXT NOT NULL CHECK(target_type IN ('story', 'group', 'activity', 'comment')),
                target_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reporter_id) REFERENCES users (id)
            )
        ''')

        # Story Images Table (Multi-image support)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS story_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                story_id INTEGER NOT NULL,
                image_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (story_id) REFERENCES stories (id)
            )
        ''')

        # Add location and event_date to activities if not exists
        try:
            cursor.execute("SELECT location FROM activities LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE activities ADD COLUMN location TEXT")
            cursor.execute("ALTER TABLE activities ADD COLUMN event_date TEXT")
            cursor.execute("ALTER TABLE activities ADD COLUMN organizer_id INTEGER")

        # Add profile fields to users if not exists
        try:
            cursor.execute("SELECT full_name FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
            cursor.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT")

        # Add authentication fields to users if not exists
        try:
            cursor.execute("SELECT email FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
            cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
            cursor.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

        # Add admin field to users if not exists
        try:
            cursor.execute("SELECT is_admin FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")

        # Add notification preference columns if not exists
        try:
            cursor.execute("SELECT notify_messages FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN notify_messages INTEGER DEFAULT 1")
            cursor.execute("ALTER TABLE users ADD COLUMN notify_activities INTEGER DEFAULT 1")
            cursor.execute("ALTER TABLE users ADD COLUMN notify_stories INTEGER DEFAULT 1")
            cursor.execute("ALTER TABLE users ADD COLUMN notify_groups INTEGER DEFAULT 1")

        # Add language preference column if not exists
        try:
            cursor.execute("SELECT language FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN language TEXT DEFAULT 'en'")

        # Add is_verified column to users if not exists (for email verification)
        try:
            cursor.execute("SELECT is_verified FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0")

        # Email verification codes table (for registration)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                code TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_used INTEGER DEFAULT 0
            )
        ''')

        # Login OTP codes table (for login verification)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                code TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_used INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Trusted devices table (for 30-day OTP bypass)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trusted_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_token TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Auto-create default admin account if it doesn't exist
        from werkzeug.security import generate_password_hash
        admin_email = 'admin@togethersg.com'
        admin_exists = cursor.execute("SELECT id FROM users WHERE email = ?", (admin_email,)).fetchone()
        if not admin_exists:
            admin_password_hash = generate_password_hash('Admin@123')
            cursor.execute(
                """INSERT INTO users (username, email, password_hash, role, full_name, is_admin, is_verified) 
                   VALUES (?, ?, ?, ?, ?, 1, 1)""",
                ('admin', admin_email, admin_password_hash, 'youth', 'System Administrator')
            )
        
        conn.commit()
        conn.close()

    def query(self, query, args=(), one=False):
        """Helper method to execute queries."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, args)
        rv = cursor.fetchall()
        conn.commit()
        conn.close()
        return (rv[0] if rv else None) if one else rv
