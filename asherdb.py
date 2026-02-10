import sqlite3

class Database:
    def __init__(self, db_file="app.db"):
        self.db_file = db_file
        # self.init_db()  <-- Removed to prevent overhead on every request. Init explicitly on startup.

    def get_connection(self):
        """Returns a connection to the SQLite database."""
        conn = sqlite3.connect(self.db_file, timeout=20.0) # Increased timeout to 20s
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
                reply_to INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                is_delivered INTEGER DEFAULT 0,
                is_pinned INTEGER DEFAULT 0,
                is_deleted_sender INTEGER DEFAULT 0,
                is_deleted_receiver INTEGER DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id),
                FOREIGN KEY (reply_to) REFERENCES messages (id)
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

        # Migration for calls table columns (fixing missing column error)
        try:
            cursor.execute("SELECT started_at FROM calls LIMIT 1")
        except sqlite3.OperationalError:
            # If table exists but columns are missing (e.g. from previous bad creation)
            # We'll just drop and recreate since it's a new feature with dummy data
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

        # Migration for reply_to
        try:
            cursor.execute("SELECT reply_to FROM messages LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE messages ADD COLUMN reply_to INTEGER")

        # Migration for is_delivered
        try:
            cursor.execute("SELECT is_delivered FROM messages LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE messages ADD COLUMN is_delivered INTEGER DEFAULT 0")

        # Migration for deletion flags
        try:
            cursor.execute("SELECT is_deleted_sender FROM messages LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE messages ADD COLUMN is_deleted_sender INTEGER DEFAULT 0")
            cursor.execute("ALTER TABLE messages ADD COLUMN is_deleted_receiver INTEGER DEFAULT 0")

        # Migration for read_at and is_pinned
        try:
            cursor.execute("SELECT read_at FROM messages LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE messages ADD COLUMN read_at TIMESTAMP")
            cursor.execute("ALTER TABLE messages ADD COLUMN is_pinned INTEGER DEFAULT 0")

        # Migration for group_id
        try:
            cursor.execute("SELECT group_id FROM messages LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE messages ADD COLUMN group_id INTEGER")

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

        # Add last_activity field to users for online status tracking
        try:
            cursor.execute("SELECT last_activity FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN last_activity TIMESTAMP")

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
