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
        
        # User table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL CHECK(role IN ('senior', 'youth')),
                bio TEXT
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
