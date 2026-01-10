from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from datetime import datetime

app = Flask(__name__)
DB_NAME = "intergenconnect.db"

# ----------------------
# Database Helper
# ----------------------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# ----------------------
# Init Database
# ----------------------
def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS memories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT,
        location TEXT,
        created_at TEXT,
        is_active INTEGER DEFAULT 1
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        memory_id INTEGER,
        content TEXT,
        created_at TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        memory_id INTEGER
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS recent_searches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        keyword TEXT,
        created_at TEXT
    )
    """)


    conn.commit()
    conn.close()

# ----------------------
# Routes
# ----------------------
@app.route("/")
def feed_memory():
    keyword = request.args.get("keyword", "")
    category = request.args.get("category", "")
    location = request.args.get("location", "")

    query = "SELECT * FROM memories WHERE is_active = 1"
    params = []

    if keyword:
        query += " AND (title LIKE ? OR content LIKE ?)"
        params.extend([f"%{keyword}%", f"%{keyword}%"])

    if category:
        query += " AND category = ?"
        params.append(category)

    if location:
        query += " AND location LIKE ?"
        params.append(f"%{location}%")

    query += " ORDER BY created_at DESC"

    # ✅ IMPORTANT: conn is created ONCE here
    conn = get_db()

    memories = conn.execute(query, params).fetchall()

    recent_searches = []
    if keyword:
        conn.execute(
            "INSERT INTO recent_searches (keyword, created_at) VALUES (?, ?)",
            (keyword, datetime.now().isoformat())
        )
        conn.commit()

    recent_searches = conn.execute("""
        SELECT DISTINCT keyword
        FROM recent_searches
        ORDER BY created_at DESC
        LIMIT 5
    """).fetchall()

    conn.close()

    return render_template(
        "memoryFeed.html",
        memories=memories,
        recent_searches=recent_searches,
        keyword=keyword,
        category=category,
        location=location
    )




@app.route("/memory/create", methods=["GET", "POST"])
def create_memory():
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        category = request.form["category"]
        location = request.form["location"]

        conn = get_db()
        conn.execute("""
            INSERT INTO memories (title, content, category, location, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (title, content, category, location, datetime.now().isoformat()))
        conn.commit()
        conn.close()

        return redirect(url_for("feed_memory"))

    return render_template("memoryCreate.html")

@app.route("/memory/<int:memory_id>")
def view_memory(memory_id):
    conn = get_db()

    memory = conn.execute(
        "SELECT * FROM memories WHERE id = ?", (memory_id,)
    ).fetchone()

    comments = conn.execute(
        "SELECT * FROM comments WHERE memory_id = ?", (memory_id,)
    ).fetchall()

    like_count = conn.execute(
        "SELECT COUNT(*) FROM likes WHERE memory_id = ?", (memory_id,)
    ).fetchone()[0]

    conn.close()
    return render_template(
        "memoryView.html",
        memory=memory,
        comments=comments,
        like_count=like_count
    )

@app.route("/memory/<int:memory_id>/comment", methods=["POST"])
def add_comment(memory_id):
    content = request.form["content"]

    conn = get_db()
    conn.execute("""
        INSERT INTO comments (memory_id, content, created_at)
        VALUES (?, ?, ?)
    """, (memory_id, content, datetime.now().isoformat()))
    conn.commit()
    conn.close()

    return redirect(url_for("view_memory", memory_id=memory_id))

@app.route("/memory/<int:memory_id>/like")
def like_memory(memory_id):
    conn = get_db()
    conn.execute(
        "INSERT INTO likes (memory_id) VALUES (?)", (memory_id,)
    )
    conn.commit()
    conn.close()

    return redirect(url_for("view_memory", memory_id=memory_id))

@app.route("/memory/<int:memory_id>/delete")
def delete_memory(memory_id):
    conn = get_db()
    conn.execute(
        "UPDATE memories SET is_active = 0 WHERE id = ?", (memory_id,)
    )
    conn.commit()
    conn.close()

    return redirect(url_for("feed_memory"))

# ----------------------
# Run App
# ----------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
