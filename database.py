import sqlite3

class Database:
    _db_initialized = False

    def __init__(self, db_file="app.db"):
        self.db_file = db_file

    def get_connection(self):
        """Returns a connection to the SQLite database with optimized settings."""
        conn = sqlite3.connect(self.db_file, timeout=20)
        conn.row_factory = sqlite3.Row  # Access columns by name
        
        # Enable WAL mode for better concurrency
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.Error:
            pass
            
        return conn

    def init_db(self, force=False):
        """Initializes the database with necessary tables."""
        if Database._db_initialized and not force:
            return
        
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
                likes INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (story_id) REFERENCES stories (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Add likes column to comments if not exists
        try:
            cursor.execute("SELECT likes FROM comments LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE comments ADD COLUMN likes INTEGER DEFAULT 0")

        # Comment Likes Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comment_likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                comment_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (comment_id) REFERENCES comments (id),
                UNIQUE(user_id, comment_id)
            )
        ''')

        # Comment Replies Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comment_replies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                comment_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (comment_id) REFERENCES comments (id),
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

        # Group Posts Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                image_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                likes INTEGER DEFAULT 0,
                FOREIGN KEY (group_id) REFERENCES groups (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Group Post Comments Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_post_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (post_id) REFERENCES group_posts (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Group Post Likes Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_post_likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (post_id) REFERENCES group_posts (id),
                UNIQUE(user_id, post_id)
            )
        ''')

        # Messages Table (Enhanced)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                reply_to INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                is_delivered INTEGER DEFAULT 0,
                is_pinned INTEGER DEFAULT 0,
                is_deleted_sender INTEGER DEFAULT 0,
                is_deleted_receiver INTEGER DEFAULT 0,
                group_id INTEGER,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id),
                FOREIGN KEY (reply_to) REFERENCES messages (id)
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
                position INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (story_id) REFERENCES stories (id)
            )
        ''')

        # Add position column to story_images if not exists
        try:
            cursor.execute("SELECT position FROM story_images LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE story_images ADD COLUMN position INTEGER DEFAULT 0")

        # Story Tags Table (Up to 5 tags per story)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS story_tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                story_id INTEGER NOT NULL,
                tag TEXT NOT NULL,
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

        # Add attachment column to activities if not exists
        try:
            cursor.execute("SELECT attachment FROM activities LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE activities ADD COLUMN attachment TEXT")

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

        # Add likes column to group_posts if not exists
        try:
            cursor.execute("SELECT likes FROM group_posts LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE group_posts ADD COLUMN likes INTEGER DEFAULT 0")

        # Add notification preference columns if not exists
        try:
            cursor.execute("SELECT notify_messages FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN notify_messages INTEGER DEFAULT 1")
            cursor.execute("ALTER TABLE users ADD COLUMN notify_activities INTEGER DEFAULT 1")
            cursor.execute("ALTER TABLE users ADD COLUMN notify_stories INTEGER DEFAULT 1")
            cursor.execute("ALTER TABLE users ADD COLUMN notify_groups INTEGER DEFAULT 1")

        # UI Translations Cache Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ui_translations (
                text_key TEXT,
                language TEXT,
                translation TEXT,
                PRIMARY KEY(text_key, language)
            )
        ''')

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
        
        # Notifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                content TEXT NOT NULL,
                link TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Message Reactions Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS message_reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                reaction TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (message_id) REFERENCES messages (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(message_id, user_id, reaction)
            )
        ''')

        # Call Signals Table (WebRTC Signaling)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS call_signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                type TEXT NOT NULL, -- 'offer', 'answer', 'candidate', 'end'
                data TEXT NOT NULL, -- JSON data
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id)
            )
        ''')

        # Calls History Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                caller_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                call_type TEXT NOT NULL CHECK(call_type IN ('voice', 'video')),
                status TEXT NOT NULL CHECK(status IN ('completed', 'missed', 'rejected', 'ongoing')),
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP,
                duration INTEGER DEFAULT 0,
                FOREIGN KEY (caller_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id)
            )
        ''')

        # Archived Chats Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS archived_chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                archived_user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (archived_user_id) REFERENCES users (id),
                UNIQUE(user_id, archived_user_id)
            )
        ''')

        # Pinned Chats Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pinned_chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                pinned_user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (pinned_user_id) REFERENCES users (id),
                UNIQUE(user_id, pinned_user_id)
            )
        ''')

        # Pinned Groups Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pinned_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (group_id) REFERENCES groups (id),
                UNIQUE(user_id, group_id)
            )
        ''')

        # Nicknames Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS nicknames (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                target_user_id INTEGER NOT NULL,
                nickname TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (target_user_id) REFERENCES users (id),
                UNIQUE(user_id, target_user_id)
            )
        ''')

        # Muted Chats Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS muted_chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                muted_user_id INTEGER NOT NULL,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (muted_user_id) REFERENCES users (id),
                UNIQUE(user_id, muted_user_id)
            )
        ''')

        # --- Manual Migrations (Add missing columns to existing tables) ---

        # Messages table migrations
        columns_to_add = [
            ("reply_to", "INTEGER"),
            ("read_at", "TIMESTAMP"),
            ("is_delivered", "INTEGER DEFAULT 0"),
            ("is_pinned", "INTEGER DEFAULT 0"),
            ("is_deleted_sender", "INTEGER DEFAULT 0"),
            ("is_deleted_receiver", "INTEGER DEFAULT 0"),
            ("group_id", "INTEGER")
        ]
        for col_name, col_type in columns_to_add:
            try:
                cursor.execute(f"SELECT {col_name} FROM messages LIMIT 1")
            except sqlite3.OperationalError:
                cursor.execute(f"ALTER TABLE messages ADD COLUMN {col_name} {col_type}")

        # Users table migrations
        try:
            cursor.execute("SELECT last_activity FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN last_activity TIMESTAMP")

        # Calls table migration (fix for a specific schema issue seen in asherdb)
        try:
            cursor.execute("SELECT started_at FROM calls LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("DROP TABLE IF EXISTS calls")
            cursor.execute('''
                CREATE TABLE calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    caller_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    call_type TEXT NOT NULL CHECK(call_type IN ('voice', 'video')),
                    status TEXT NOT NULL CHECK(status IN ('completed', 'missed', 'rejected', 'ongoing')),
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    duration INTEGER DEFAULT 0,
                    FOREIGN KEY (caller_id) REFERENCES users (id),
                    FOREIGN KEY (receiver_id) REFERENCES users (id)
                )
            ''')

        # Settings Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')

        conn.commit()
        conn.close()
        Database._db_initialized = True

    def query(self, query, args=(), one=False):
        """Helper method to execute queries."""
        from flask import g, has_app_context
        # Use shared connection if in request context
        use_g = has_app_context()
        if use_g and hasattr(g, 'db_conn'):
            conn = g.db_conn
            should_close = False
        else:
            conn = self.get_connection()
            should_close = True

        try:
            cursor = conn.cursor()
            cursor.execute(query, args)
            rv = cursor.fetchall()
            # Only commit/close if we opened it here or it's not a read-only query
            # sqlite3 needs commit for writes but for consistency we commit if we opened it
            if should_close:
                conn.commit()
            return (rv[0] if rv else None) if one else rv
        finally:
            if should_close:
                conn.close()
    def set_setting(self, key, value):
        """Sets a value in the settings table."""
        from flask import g, has_app_context
        use_g = has_app_context()
        if use_g and hasattr(g, 'db_conn'):
            conn = g.db_conn
            should_close = False
        else:
            conn = self.get_connection()
            should_close = True

        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """, (key, value))
            conn.commit()
        finally:
            if should_close:
                conn.close()

    def get_setting(self, key):
        """Gets a value from the settings table."""
        res = self.query("SELECT value FROM settings WHERE key = ?", (key,), one=True)
        return res['value'] if res else None
