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
    # This is where we would fetch latest stories and activities
    recent_stories = db.query("SELECT * FROM stories ORDER BY created_at DESC LIMIT 3")
    upcoming_activities = db.query("SELECT * FROM activities ORDER BY created_at DESC LIMIT 3")
    
    return render_template('index.html', stories=recent_stories, activities=upcoming_activities)

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
    return render_template('stories/index.html', stories=stories_data)

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
    story = db.query("SELECT * FROM stories WHERE id = ?", (story_id,), one=True)
    if not story:
        return "Story not found", 404
        
    # Check if bookmarked (Hardcoded user_id=1)
    is_bookmarked = False
    bookmark = db.query("SELECT * FROM bookmarks WHERE user_id = ? AND story_id = ?", (1, story_id), one=True)
    if bookmark:
        is_bookmarked = True
        
    return render_template('stories/view.html', story=story, is_bookmarked=is_bookmarked)

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
    return render_template('stories/index.html', stories=bookmarks)

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
