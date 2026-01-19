from flask import Flask, render_template, g, request, redirect, url_for
from database import Database

app = Flask(__name__)

# Database Helper to get db connection per request
def get_db():
    if 'db' not in g:
        g.db = Database()
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        # In this simple implementation, Database class opens connection on every query
        # so we might not need to strictly close the object itself if it doesn't hold a persistent connection
        # But for good practice if we changed implementation:
        pass

@app.route('/')
def dashboard():
    # Initialize DB (creates tables if not exist)
    db = get_db()
    
    # Fetch some sample data to display
    recent_stories = db.query("SELECT * FROM stories ORDER BY created_at DESC LIMIT 3")
    upcoming_activities = db.query("SELECT * FROM activities ORDER BY created_at DESC LIMIT 3")
    
    # Mock User Data (Simulation of logged-in user)
    user = {
        'full_name': 'Joden Lee',
        'user_type': 'Senior',
        'profile_pic': 'https://ui-avatars.com/api/?name=Joden+Lee&background=D35400&color=fff'
    }
    
    # Mock Stats (or we could count simple queries)
    stats = {
        'stories': len(db.query("SELECT id FROM stories")),
        'activities': len(db.query("SELECT id FROM activities")),
        'messages': 3, # Mock
        'groups': 5    # Mock
    }
    
    return render_template('dashboard.html', recent_stories=recent_stories, upcoming_activities=upcoming_activities, user=user, stats=stats)

@app.route('/stories')
def stories():
    db = get_db()
    
    # Get parameters
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'newest')
    location_filter = request.args.get('location', '')
    
    # Build Query
    query = "SELECT * FROM stories WHERE 1=1"
    args = []
    
    if search:
        query += " AND (title LIKE ? OR content LIKE ?)"
        args.extend([f'%{search}%', f'%{search}%'])
        
    if location_filter:
        query += " AND location LIKE ?"
        args.append(f'%{location_filter}%')
        
    if sort == 'likes':
        query += " ORDER BY likes DESC"
    else:
        query += " ORDER BY created_at DESC"
        
    stories_data = db.query(query, args)
    
    # Get user's bookmarks (Hardcoded user_id=1)
    bookmarks_query = "SELECT story_id FROM bookmarks WHERE user_id = ?"
    bookmarks = db.query(bookmarks_query, (1,))
    bookmarked_story_ids = [b['story_id'] for b in bookmarks]

    # Get user's liked stories (Hardcoded user_id=1)
    likes_query = "SELECT story_id FROM story_likes WHERE user_id = ?"
    liked_rows = db.query(likes_query, (1,))
    liked_story_ids = [l['story_id'] for l in liked_rows]
    
    return render_template('stories/index.html', stories=stories_data, bookmarked_story_ids=bookmarked_story_ids, liked_story_ids=liked_story_ids)

@app.route('/stories/new', methods=['GET', 'POST'])
def create_story():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        location = request.form['location']
        image_url = request.form['image_url']
        
        # Hardcoded author_id for now as we don't have login session yet
        # Assuming first user is the "logged in" one
        author_id = 1 
        
        db = get_db()
        conn = db.get_connection()
        conn.execute(
            "INSERT INTO stories (title, content, author_id, location, image_url) VALUES (?, ?, ?, ?, ?)",
            (title, content, author_id, location, image_url)
        )
        conn.commit()
        return redirect(url_for('stories'))
        
    return render_template('stories/create.html')

@app.route('/stories/<int:story_id>')
def view_story(story_id):
    db = get_db()
    # Join with users to get author name
    # Join with users to get author name
    query = """
        SELECT s.*, u.username as author_name 
        FROM stories s 
        LEFT JOIN users u ON s.author_id = u.id 
        WHERE s.id = ?
    """
    story = db.query(query, (story_id,), one=True)
    
    if not story:
        return "Story not found", 404
        
    # Check if bookmarked (Hardcoded user_id=1)
    is_bookmarked = False
    bookmark = db.query("SELECT * FROM bookmarks WHERE user_id = ? AND story_id = ?", (1, story_id), one=True)
    if bookmark:
        is_bookmarked = True
        
    # Check if liked
    is_liked = False
    like_check = db.query("SELECT * FROM story_likes WHERE user_id = ? AND story_id = ?", (1, story_id), one=True)
    if like_check:
        is_liked = True
        
    # Fetch Comments
    comments_query = """
        SELECT c.*, u.username, u.role 
        FROM comments c 
        JOIN users u ON c.user_id = u.id 
        WHERE c.story_id = ? 
        ORDER BY c.created_at DESC
    """
    comments = db.query(comments_query, (story_id,))
        
    return render_template('stories/view.html', story=story, is_bookmarked=is_bookmarked, is_liked=is_liked, comments=comments)

@app.route('/stories/bookmarks')
def my_bookmarks():
    db = get_db()
    # Hardcoded user_id=1
    query = """
        SELECT s.* FROM stories s
        JOIN bookmarks b ON s.id = b.story_id
        WHERE b.user_id = ?
    """
    bookmarks = db.query(query, (1,))
    
    # Also fetch the list of IDs for the icon logic (even though all here are bookmarked, it keeps template consistent)
    bookmarked_story_ids = [b['id'] for b in bookmarks]

    # Get user's liked stories (Hardcoded user_id=1)
    likes_query = "SELECT story_id FROM story_likes WHERE user_id = ?"
    liked_rows = db.query(likes_query, (1,))
    liked_story_ids = [l['story_id'] for l in liked_rows]
    
    return render_template('stories/favourites.html', stories=bookmarks, bookmarked_story_ids=bookmarked_story_ids, liked_story_ids=liked_story_ids)

@app.route('/stories/<int:story_id>/bookmark', methods=['POST'])
def toggle_bookmark(story_id):
    db = get_db()
    conn = db.get_connection()
    user_id = 1 # Hardcoded
    
    # Check exist
    exists = db.query("SELECT * FROM bookmarks WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
    if exists:
        conn.execute("DELETE FROM bookmarks WHERE user_id = ? AND story_id = ?", (user_id, story_id))
    else:
        conn.execute("INSERT INTO bookmarks (user_id, story_id) VALUES (?, ?)", (user_id, story_id))
        
    conn.commit()
    conn.commit()
    
    # Redirect back to where the user came from (feed or detail view)
    return redirect(request.referrer or url_for('view_story', story_id=story_id))

@app.route('/stories/<int:story_id>/like', methods=['POST'])
def toggle_like(story_id):
    db = get_db()
    conn = db.get_connection()
    user_id = 1 # Hardcoded
    
    # Check exist
    exists = db.query("SELECT * FROM story_likes WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
    
    if exists:
        # Unlike
        conn.execute("DELETE FROM story_likes WHERE user_id = ? AND story_id = ?", (user_id, story_id))
        conn.execute("UPDATE stories SET likes = likes - 1 WHERE id = ?", (story_id,))
    else:
        # Like
        conn.execute("INSERT INTO story_likes (user_id, story_id) VALUES (?, ?)", (user_id, story_id))
        conn.execute("UPDATE stories SET likes = likes + 1 WHERE id = ?", (story_id,))
        
    conn.commit()
    
    return redirect(request.referrer or url_for('stories'))

@app.route('/stories/<int:story_id>/edit', methods=['GET', 'POST'])
def edit_story(story_id):
    db = get_db()
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        location = request.form['location']
        image_url = request.form['image_url']
        
        conn = db.get_connection()
        conn.execute("UPDATE stories SET title=?, content=?, location=?, image_url=? WHERE id=?", 
                     (title, content, location, image_url, story_id))
        conn.commit()
        return redirect(url_for('view_story', story_id=story_id))
    
    story = db.query("SELECT * FROM stories WHERE id = ?", (story_id,), one=True)
    return render_template('stories/edit.html', story=story)

@app.route('/stories/<int:story_id>/delete', methods=['POST'])
def delete_story(story_id):
    db = get_db()
    conn = db.get_connection()
    # Delete related data first (FK constraints usually handled, but explicit is safe)
    conn.execute("DELETE FROM bookmarks WHERE story_id = ?", (story_id,))
    conn.execute("DELETE FROM story_likes WHERE story_id = ?", (story_id,))
    conn.execute("DELETE FROM comments WHERE story_id = ?", (story_id,))
    conn.execute("DELETE FROM stories WHERE id = ?", (story_id,))
    conn.commit()
    return redirect(url_for('stories'))

@app.route('/stories/<int:story_id>/comment', methods=['POST'])
def add_comment(story_id):
    content = request.form['content']
    if not content.strip():
        return redirect(url_for('view_story', story_id=story_id))
        
    user_id = 1 # Hardcoded
    db = get_db()
    conn = db.get_connection()
    conn.execute("INSERT INTO comments (story_id, user_id, content) VALUES (?, ?, ?)", (story_id, user_id, content))
    conn.commit()
    return redirect(url_for('view_story', story_id=story_id))

@app.route('/activities')
def activities():
    return render_template('index.html', stories=[], activities=[]) # Placeholder

@app.route('/messages')
def messages():
    return render_template('index.html', stories=[], activities=[]) # Placeholder

@app.route('/profile')
def profile():
    return render_template('index.html', stories=[], activities=[]) # Placeholder

@app.route('/community')
def community():
    return render_template('index.html', stories=[], activities=[]) # Placeholder

if __name__ == '__main__':
    app.run(debug=True)
