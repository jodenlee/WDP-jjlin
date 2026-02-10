from flask import Flask, render_template, g, request, redirect, url_for, session, flash, abort, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.secret_key = 'togethersg-secret-key-change-in-production'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# ... (Upload Config and other routes) ...

# ===== SOCKET.IO EVENTS =====
@socketio.on('join')
def on_join(data):
    """User joins a chat room defined by user ID or unique pair."""
    room = data['room']
    join_room(room)
    # print(f"User joined room: {room}")

@socketio.on('leave')
def on_leave(data):
    """User leaves a chat room."""
    room = data['room']
    leave_room(room)
    # print(f"User left room: {room}")

@socketio.on('location_update')
def handle_location_update(data):
    """
    Receive location data from a client and broadcast it to the specific room.
    data format: {'room': 'chat_id', 'lat': 1.23, 'lng': 4.56, 'sender_id': 123}
    """
    room = data['room']
    emit('live_location_update', data, to=room, include_self=False)


from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from database import Database
import re
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'togethersg-secret-key-change-in-production'  # Change this in production!

# Upload Configuration
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp3', 'wav', 'm4a', 'ogg', 'mp4', 'mov', 'webm'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database Helper to get db connection per request
def get_db():
    if 'db' not in g:
        g.db = Database()
    return g.db

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function



# Get current user helper
def get_current_user():
    if 'user_id' in session:
        db = get_db()
        return db.query("SELECT * FROM users WHERE id = ?", (session['user_id'],), one=True)
    return None

@app.before_request
def load_logged_in_user():
    user = get_current_user()
    g.user = user
    # Update last_activity for online status tracking
    if user:
        try:
            from datetime import datetime
            db = get_db()
            conn = db.get_connection()
            conn.execute("UPDATE users SET last_activity = ? WHERE id = ?", 
                         (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), user['id']))
            conn.commit()
            conn.close()
        except Exception:
            pass # Ignore DB lock errors for this non-critical update

@app.context_processor
def inject_user():
    user_id = g.user['id'] if g.user else None
    return dict(current_user=g.user, current_user_id=user_id)


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        pass

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    error = None
    success = request.args.get('success')
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if not email or not password:
            error = 'Please enter both email and password.'
        else:
            db = get_db()
            user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
            
            if user and user['password_hash'] and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']

                flash('Welcome back!', 'success')
                return redirect(url_for('home'))
            else:
                error = 'Invalid email or password.'
    
    return render_template('auth/login.html', error=error, success=success)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    errors = []
    form = {}
    
    if request.method == 'POST':
        form['full_name'] = request.form.get('full_name', '').strip()
        form['username'] = request.form.get('username', '').strip().lower()
        form['email'] = request.form.get('email', '').strip().lower()
        form['role'] = request.form.get('role', 'youth')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        terms = request.form.get('terms')
        
        # Validation
        if not form['full_name']:
            errors.append('Full name is required.')
        
        if not form['username']:
            errors.append('Username is required.')
        elif not re.match(r'^[a-zA-Z0-9_]{3,20}$', form['username']):
            errors.append('Username must be 3-20 characters, letters, numbers, and underscores only.')
        
        if not form['email']:
            errors.append('Email is required.')
        elif not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', form['email']):
            errors.append('Please enter a valid email address.')
        
        if not password:
            errors.append('Password is required.')
        elif len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        if not terms:
            errors.append('You must agree to the terms.')
        
        # Check if username or email already exists
        if not errors:
            db = get_db()
            existing_user = db.query("SELECT * FROM users WHERE username = ? OR email = ?", 
                                     (form['username'], form['email']), one=True)
            if existing_user:
                if existing_user['username'] == form['username']:
                    errors.append('Username already taken.')
                if existing_user['email'] == form['email']:
                    errors.append('Email already registered.')
        
        # Create user if no errors
        if not errors:
            password_hash = generate_password_hash(password)
            db = get_db()
            conn = db.get_connection()
            try:
                conn.execute(
                    """INSERT INTO users (username, email, password_hash, role, full_name) 
                       VALUES (?, ?, ?, ?, ?)""",
                    (form['username'], form['email'], password_hash, form['role'], form['full_name'])
                )
                conn.commit()
                return redirect(url_for('login', success='Account created successfully! Please log in.'))
            except Exception as e:
                errors.append('An error occurred. Please try again.')
    
    return render_template('auth/register.html', errors=errors, form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
def home():
    db = get_db()
    
    # Fetch content for the public homepage (for both guests and logged-in users)
    recent_stories = db.query("SELECT * FROM stories ORDER BY created_at DESC LIMIT 3")
    upcoming_activities = db.query("SELECT * FROM activities ORDER BY created_at DESC LIMIT 3")
    
    # If explicitly "dashboard" data is needed for index.html (if we merge them), we can pass it.
    # But user requested "old dashboard", which implies index.html layout.
    
    if 'user_id' in session:
        # We can still pass user data if index.html wants to use it, 
        # but primarily we render index.html as the main view.
        pass

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
    
    # Get user's bookmarks and likes if logged in
    bookmarked_story_ids = []
    liked_story_ids = []
    
    if 'user_id' in session:
        user_id = session['user_id']
        bookmarks = db.query("SELECT story_id FROM bookmarks WHERE user_id = ?", (user_id,))
        bookmarked_story_ids = [b['story_id'] for b in bookmarks]
        
        liked_rows = db.query("SELECT story_id FROM story_likes WHERE user_id = ?", (user_id,))
        liked_story_ids = [l['story_id'] for l in liked_rows]
    
    return render_template('stories/index.html', stories=stories_data, bookmarked_story_ids=bookmarked_story_ids, liked_story_ids=liked_story_ids)

@app.route('/stories/new', methods=['GET', 'POST'])
@login_required
def create_story():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        location = request.form['location']
        
        # Handle file uploads
        images = request.files.getlist('images')
        saved_image_paths = []
        
        for image in images:
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                # Ensure unique filename to prevent overwrites (could use timestamp or uuid)
                import time
                filename = f"{int(time.time())}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(filepath)
                # Store relative path for DB
                saved_image_paths.append(f"uploads/{filename}")
        
        # Fallback to URL if provided (legacy support or alternative)
        image_url = request.form.get('image_url')
        if not saved_image_paths and image_url:
            main_image = image_url
        elif saved_image_paths:
            main_image = request.url_root + 'static/' + saved_image_paths[0] # Use first upload as main image for feed
        else:
            main_image = None
            
        author_id = session['user_id']
        
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO stories (title, content, author_id, location, image_url) VALUES (?, ?, ?, ?, ?)",
            (title, content, author_id, location, main_image)
        )
        story_id = cursor.lastrowid
        
        # Insert extra images into story_images table
        for img_path in saved_image_paths:
            full_url = request.url_root + 'static/' + img_path
            cursor.execute(
                "INSERT INTO story_images (story_id, image_path) VALUES (?, ?)",
                (story_id, full_url)
            )
            
        conn.commit()
        flash('Story created successfully!', 'success')
        return redirect(url_for('stories'))
        
    return render_template('stories/create.html')

@app.route('/stories/<int:story_id>')
def view_story(story_id):
    db = get_db()
    query = """
        SELECT s.*, u.username as author_name 
        FROM stories s 
        LEFT JOIN users u ON s.author_id = u.id 
        WHERE s.id = ?
    """
    story = db.query(query, (story_id,), one=True)
    
    if not story:
        return "Story not found", 404
        
    is_bookmarked = False
    is_liked = False
    
    if 'user_id' in session:
        user_id = session['user_id']
        bookmark = db.query("SELECT * FROM bookmarks WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
        is_bookmarked = bool(bookmark)
        
        like_check = db.query("SELECT * FROM story_likes WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
        is_liked = bool(like_check)
        
    # Fetch additional images
    additional_images = db.query("SELECT image_path FROM story_images WHERE story_id = ?", (story_id,))
    story_images = [img['image_path'] for img in additional_images]
    
    # If no additional images in story_images table but we have a main image_url, use that
    # If we have both, maybe combine them? For now, let's treat story_images as the carousel source
    # If story_images is empty, we fall back to story['image_url'] in the template logic
        
    # Fetch Comments
    comments_query = """
        SELECT c.*, u.username, u.role, u.profile_pic 
        FROM comments c 
        JOIN users u ON c.user_id = u.id 
        WHERE c.story_id = ? 
        ORDER BY c.created_at DESC
    """
    comments = db.query(comments_query, (story_id,))
        
    return render_template('stories/view.html', story=story, is_bookmarked=is_bookmarked, is_liked=is_liked, comments=comments, story_images=story_images)

@app.route('/stories/bookmarks')
@login_required
def my_bookmarks():
    db = get_db()
    user_id = session['user_id']
    query = """
        SELECT s.* FROM stories s
        JOIN bookmarks b ON s.id = b.story_id
        WHERE b.user_id = ?
    """
    bookmarks = db.query(query, (user_id,))
    
    bookmarked_story_ids = [b['id'] for b in bookmarks]

    likes_query = "SELECT story_id FROM story_likes WHERE user_id = ?"
    liked_rows = db.query(likes_query, (user_id,))
    liked_story_ids = [l['story_id'] for l in liked_rows]
    
    return render_template('stories/favourites.html', stories=bookmarks, bookmarked_story_ids=bookmarked_story_ids, liked_story_ids=liked_story_ids)

@app.route('/stories/<int:story_id>/bookmark', methods=['POST'])
@login_required
def toggle_bookmark(story_id):
    db = get_db()
    conn = db.get_connection()
    user_id = session['user_id']
    
    exists = db.query("SELECT * FROM bookmarks WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
    if exists:
        conn.execute("DELETE FROM bookmarks WHERE user_id = ? AND story_id = ?", (user_id, story_id))
    else:
        conn.execute("INSERT INTO bookmarks (user_id, story_id) VALUES (?, ?)", (user_id, story_id))
        
    conn.commit()
    
    return redirect(request.referrer or url_for('view_story', story_id=story_id))

@app.route('/stories/<int:story_id>/like', methods=['POST'])
@login_required
def toggle_like(story_id):
    db = get_db()
    conn = db.get_connection()
    user_id = session['user_id']
    
    exists = db.query("SELECT * FROM story_likes WHERE user_id = ? AND story_id = ?", (user_id, story_id), one=True)
    
    if exists:
        conn.execute("DELETE FROM story_likes WHERE user_id = ? AND story_id = ?", (user_id, story_id))
        conn.execute("UPDATE stories SET likes = likes - 1 WHERE id = ?", (story_id,))
    else:
        conn.execute("INSERT INTO story_likes (user_id, story_id) VALUES (?, ?)", (user_id, story_id))
        conn.execute("UPDATE stories SET likes = likes + 1 WHERE id = ?", (story_id,))
        
    conn.commit()
    
    return redirect(request.referrer or url_for('stories'))

@app.route('/stories/<int:story_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_story(story_id):
    db = get_db()
    story = db.query("SELECT * FROM stories WHERE id = ?", (story_id,), one=True)
    
    if not story:
        flash('Story not found.', 'danger')
        return redirect(url_for('stories'))
        
    if story['author_id'] != session['user_id']:
        flash('You are not authorized to edit this story.', 'danger')
        return redirect(url_for('stories'))
        
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        location = request.form['location']
        
        conn = db.get_connection()
        conn.execute("UPDATE stories SET title = ?, content = ?, location = ? WHERE id = ?", 
                     (title, content, location, story_id))
        
        # Handle Deletion of Main Image
        if request.form.get('delete_main_image'):
            conn.execute("UPDATE stories SET image_url = NULL WHERE id = ?", (story_id,))

        # Handle Deletion of Extra Images
        images_to_delete = request.form.getlist('delete_image_ids')
        if images_to_delete:
            for img_id in images_to_delete:
                conn.execute("DELETE FROM story_images WHERE id = ? AND story_id = ?", (img_id, story_id))

        # Handle File Uploads (New Images)
        images = request.files.getlist('images')
        saved_image_paths = []
        if images:
             for image in images:
                if image and allowed_file(image.filename):
                    filename = secure_filename(image.filename)
                    import time
                    filename = f"{int(time.time())}_{filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    image.save(filepath)
                    saved_image_paths.append(f"uploads/{filename}")
        
        # Insert new images
        for img_path in saved_image_paths:
            # Check if main image is empty, if so, make first new image the main one
            # Re-fetch story to check current state
            current_story = db.query("SELECT image_url FROM stories WHERE id=?", (story_id,), one=True)
            if not current_story['image_url']:
                 conn.execute("UPDATE stories SET image_url = ? WHERE id = ?", (request.url_root + 'static/' + img_path, story_id))
            else:
                 conn.execute("INSERT INTO story_images (story_id, image_path) VALUES (?, ?)", (story_id, img_path))
            
        conn.commit()
        flash('Story updated successfully!', 'success')
        return redirect(url_for('view_story', story_id=story_id))
    
    # Get extra images for template
    story_images = db.query("SELECT * FROM story_images WHERE story_id = ?", (story_id,))
    return render_template('stories/edit.html', story=story, story_images=story_images)

@app.route('/stories/<int:story_id>/delete', methods=['POST'])
@login_required
def delete_story(story_id):
    db = get_db()
    story = db.query("SELECT * FROM stories WHERE id = ?", (story_id,), one=True)
    
    if not story:
        return "Story not found", 404
        
    if story['author_id'] != session['user_id']:
        flash('You can only delete your own stories.', 'danger')
        return redirect(url_for('view_story', story_id=story_id))
        
    conn = db.get_connection()
    conn.execute("DELETE FROM bookmarks WHERE story_id = ?", (story_id,))
    conn.execute("DELETE FROM story_likes WHERE story_id = ?", (story_id,))
    conn.execute("DELETE FROM comments WHERE story_id = ?", (story_id,))
    conn.execute("DELETE FROM stories WHERE id = ?", (story_id,))
    conn.commit()
    flash('Story deleted successfully.', 'success')
    return redirect(url_for('stories'))

@app.route('/stories/<int:story_id>/comment', methods=['POST'])
@login_required
def add_comment(story_id):
    content = request.form['content']
    if not content.strip():
        return redirect(url_for('view_story', story_id=story_id))
        
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    conn.execute("INSERT INTO comments (story_id, user_id, content) VALUES (?, ?, ?)", (story_id, user_id, content))
    conn.commit()
    return redirect(url_for('view_story', story_id=story_id))

@app.route('/activities')
def activities():
    db = get_db()
    # Get activities with RSVP counts
    activities_data = db.query("""
        SELECT a.*, 
               (SELECT COUNT(*) FROM activity_rsvps WHERE activity_id = a.id) as rsvp_count
        FROM activities a
        ORDER BY a.event_date DESC, a.created_at DESC
    """)
    return render_template('activities/index.html', activities=activities_data)

@app.route('/activities/<int:activity_id>')
def view_activity(activity_id):
    db = get_db()
    activity = db.query("SELECT * FROM activities WHERE id = ?", (activity_id,), one=True)
    if not activity:
        return "Activity not found", 404
    
    is_joined = False
    rsvp_count = len(db.query("SELECT * FROM activity_rsvps WHERE activity_id = ?", (activity_id,)))
    
    if 'user_id' in session:
        user_id = session['user_id']
        rsvp = db.query("SELECT * FROM activity_rsvps WHERE activity_id = ? AND user_id = ?", (activity_id, user_id), one=True)
        is_joined = bool(rsvp)
    
    return render_template('activities/view.html', activity=activity, is_joined=is_joined, rsvp_count=rsvp_count)

@app.route('/activities/new', methods=['GET', 'POST'])
@login_required
def create_activity():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        activity_type = request.form['type']
        location = request.form.get('location', '')
        event_date = request.form.get('event_date', '')
        
        user_id = session['user_id']
        db = get_db()
        conn = db.get_connection()
        conn.execute(
            "INSERT INTO activities (title, description, type, location, event_date, organizer_id) VALUES (?, ?, ?, ?, ?, ?)",
            (title, description, activity_type, location, event_date, user_id)
        )
        conn.commit()
        return redirect(url_for('activities'))
    
    return render_template('activities/create.html')

@app.route('/activities/<int:activity_id>/join', methods=['POST'])
@login_required
def join_activity(activity_id):
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    try:
        conn.execute("INSERT INTO activity_rsvps (activity_id, user_id) VALUES (?, ?)", (activity_id, user_id))
        conn.commit()
    except:
        pass  # Already joined
    return redirect(url_for('view_activity', activity_id=activity_id))

@app.route('/activities/<int:activity_id>/leave', methods=['POST'])
@login_required
def leave_activity(activity_id):
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    conn.execute("DELETE FROM activity_rsvps WHERE activity_id = ? AND user_id = ?", (activity_id, user_id))
    conn.commit()
    return redirect(url_for('view_activity', activity_id=activity_id))

@app.route('/messages')
@login_required
def messages():
    db = get_db()
    user_id = session['user_id']
    
    # Ensure muted_chats table exists
    conn = db.get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS muted_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            muted_user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (muted_user_id) REFERENCES users(id),
            UNIQUE(user_id, muted_user_id)
        )
    """)
    conn.commit()
    
    # Get all users for starting new conversations
    users = db.query("SELECT * FROM users WHERE id != ?", (user_id,))
    
    # Get conversations (users we've messaged with) - include is_muted check
    # --- 1. Private Chats (1-on-1) ---
    # Fix for persistent deletion: Filter at the source (WHERE clause) for non-deleted messages
    private_chats = db.query("""
        SELECT 
            u.id as user_id,
            COALESCE(n.nickname, u.username) as username,
            u.username as original_username,
            u.profile_pic,
            'private' as type,
            
            -- Last Message (Subquery)
            (SELECT content FROM messages m2 
             WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id))
             AND m2.group_id IS NULL
             AND (CASE WHEN m2.sender_id = ? THEN m2.is_deleted_sender ELSE m2.is_deleted_receiver END = 0)
             ORDER BY m2.created_at DESC LIMIT 1) as last_message,
             
            -- Last Message Sender
            (SELECT sender_id FROM messages m2 
             WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id))
             AND m2.group_id IS NULL
             AND (CASE WHEN m2.sender_id = ? THEN m2.is_deleted_sender ELSE m2.is_deleted_receiver END = 0)
             ORDER BY m2.created_at DESC LIMIT 1) as last_message_sender_id,
             
            -- Last Message Is Read
            (SELECT is_read FROM messages m2 
             WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id))
             AND m2.group_id IS NULL
             AND (CASE WHEN m2.sender_id = ? THEN m2.is_deleted_sender ELSE m2.is_deleted_receiver END = 0)
             ORDER BY m2.created_at DESC LIMIT 1) as last_message_is_read,

            -- Last Message Time
            (SELECT created_at FROM messages m2 
             WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id))
             AND m2.group_id IS NULL
             AND (CASE WHEN m2.sender_id = ? THEN m2.is_deleted_sender ELSE m2.is_deleted_receiver END = 0)
             ORDER BY m2.created_at DESC LIMIT 1) as last_message_time,
             
            -- Unread Count
            (SELECT COUNT(*) FROM messages m4 
             WHERE m4.sender_id = u.id AND m4.receiver_id = ? AND m4.is_read = 0
             AND m4.group_id IS NULL
             AND m4.is_deleted_receiver = 0) as unread_count,
             
            -- Muted Status
            (SELECT COUNT(*) FROM muted_chats mc 
             WHERE mc.user_id = ? AND mc.muted_user_id = u.id
             AND (mc.expires_at IS NULL OR mc.expires_at > CURRENT_TIMESTAMP)) > 0 as is_muted,
             
            -- Archived Status
            (SELECT COUNT(*) FROM archived_chats ac 
             WHERE ac.user_id = ? AND ac.archived_user_id = u.id) > 0 as is_archived,
             
            -- Pinned Status
            (SELECT COUNT(*) FROM pinned_chats pc 
             WHERE pc.user_id = ? AND pc.pinned_user_id = u.id) > 0 as is_pinned
             
        FROM messages m
        JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
        LEFT JOIN nicknames n ON n.user_id = ? AND n.target_user_id = u.id
        WHERE (m.sender_id = ? OR m.receiver_id = ?)
        AND m.group_id IS NULL
        AND (CASE WHEN m.sender_id = ? THEN m.is_deleted_sender ELSE m.is_deleted_receiver END = 0)
        GROUP BY u.id
        HAVING last_message IS NOT NULL AND is_archived = 0
    """, (user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id))

    # --- 2. Group Chats ---
    group_chats = db.query("""
        SELECT 
            g.id as user_id,
            g.name as username,
            g.image_url as profile_pic,
            'group' as type,
            (SELECT content FROM messages m WHERE m.group_id = g.id ORDER BY m.created_at DESC LIMIT 1) as last_message,
            (SELECT sender_id FROM messages m WHERE m.group_id = g.id ORDER BY m.created_at DESC LIMIT 1) as last_message_sender_id,
            0 as last_message_is_read,
            (SELECT created_at FROM messages m WHERE m.group_id = g.id ORDER BY m.created_at DESC LIMIT 1) as last_message_time,
            0 as unread_count,
            0 as is_muted,
            0 as is_archived,
            (SELECT COUNT(*) FROM pinned_groups pg WHERE pg.user_id = ? AND pg.group_id = g.id) > 0 as is_pinned
        FROM groups g
        JOIN group_members gm ON gm.group_id = g.id
        WHERE gm.user_id = ?
    """, (user_id, user_id))
    
    # Combine and convert to dicts to support .get() and modification
    conversations = [dict(c) for c in private_chats + group_chats]
    
    # Convert rows to dicts for template compatibility
    conversations_list = []
    
    now = datetime.utcnow() + timedelta(hours=8) # Current SG time
    
    for row in conversations:
        d = dict(row)
        if d['last_message_time']:
            try:
                # Parse DB time (UTC)
                dt = datetime.strptime(d['last_message_time'], '%Y-%m-%d %H:%M:%S')
                dt_sg = dt + timedelta(hours=8)
                
                # Logic:
                # < 24h: H:MM am/pm (e.g. 9:30 am). Wait, user said "If over <24h, change to yesterday". 
                # This implies if it's NOT today.
                # Let's check dates.
                
                diff = now.date() - dt_sg.date()
                days = diff.days
                
                if days == 0:
                    # Today
                    d['last_message_time'] = dt_sg.strftime('%#I:%M %p').lower()
                elif days == 1:
                    # Yesterday
                    d['last_message_time'] = 'Yesterday'
                elif days < 7:
                    # Weekday
                    d['last_message_time'] = dt_sg.strftime('%A')
                else:
                    # > Week: D:M:YY (e.g. 10:2:26)
                    d['last_message_time'] = dt_sg.strftime('%d:%m:%y')
                
                # Add sorting timestamp (unix)
                d['timestamp'] = int(dt_sg.timestamp())
            except Exception as e:
                print(f"Date parse error: {e}")
                d['timestamp'] = 0
                pass
        else:
            d['timestamp'] = 0
            
        conversations_list.append(d)
    # Mark messages as delivered for the current user
    conn.execute("UPDATE messages SET is_delivered = 1 WHERE receiver_id = ?", (user_id,))
    conn.commit()
    
    # Get archived count
    archived_count_row = db.query("SELECT COUNT(*) as count FROM archived_chats WHERE user_id = ?", (user_id,), one=True)
    archived_count = archived_count_row['count'] if archived_count_row else 0
    
    return render_template('messages/index.html', conversations=conversations_list, users=users, archived_count=archived_count)

@app.route('/calls')
@login_required
def calls():
    db = get_db()
    user_id = session['user_id']
    
    # Check if we need to seed dummy calls for this user (for visualization)
    # Remove dummy seeding logic to use real history
    # Fetch calls logs
    calls_data = db.query("""
        SELECT c.*, 
               u_other.username as other_username, 
               u_other.profile_pic as other_profile_pic,
               CASE WHEN c.caller_id = ? THEN 1 ELSE 0 END as is_outgoing
        FROM calls c
        JOIN users u_other ON u_other.id = CASE WHEN c.caller_id = ? THEN c.receiver_id ELSE c.caller_id END
        WHERE c.caller_id = ? OR c.receiver_id = ?
        ORDER BY c.started_at DESC
        LIMIT 50
    """, (user_id, user_id, user_id, user_id))
    
    # Process for display
    from datetime import datetime, timedelta
    formatted_calls = []
    
    # Helper to parse time
    def parse_time(t_str):
        try:
            return datetime.strptime(t_str, '%Y-%m-%d %H:%M:%S')
        except:
            return datetime.utcnow() # Fallback

    for call in calls_data:
        c = dict(call)
        try:
            dt = parse_time(c['started_at'])
            dt_gmt8 = dt + timedelta(hours=8)
            
            # Format: Today, Yesterday, or Date
            now = datetime.utcnow() + timedelta(hours=8)
            if dt_gmt8.date() == now.date():
                c['display_time'] = dt_gmt8.strftime('%I:%M %p').lower()
                c['display_date'] = 'Today'
            elif dt_gmt8.date() == (now - timedelta(days=1)).date():
                c['display_time'] = dt_gmt8.strftime('%I:%M %p').lower()
                c['display_date'] = 'Yesterday'
            else:
                c['display_time'] = dt_gmt8.strftime('%I:%M %p').lower()
                c['display_date'] = dt_gmt8.strftime('%d/%m/%y')
        except Exception:
            c['display_time'] = ''
            c['display_date'] = ''
            
        formatted_calls.append(c)

    return render_template('messages/calls.html', calls=formatted_calls)

@app.route('/api/calls/log', methods=['POST'])
@login_required
def log_call():
    db = get_db()
    data = request.json
    caller_id = session['user_id']
    receiver_id = data.get('receiver_id')
    call_type = data.get('call_type', 'voice')
    status = data.get('status', 'missed') # Default to missed/canceled if not specified
    
    if not receiver_id:
        return jsonify({'error': 'Receiver ID required'}), 400

    conn = db.get_connection()
    try:
        conn.execute("""
            INSERT INTO calls (caller_id, receiver_id, call_type, status, started_at, duration)
            VALUES (?, ?, ?, ?, ?, 0)
        """, (caller_id, receiver_id, call_type, status, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
    finally:
        conn.close()
    
    return jsonify({'success': True})

@app.route('/messages/<int:user_id>')
@login_required
def chat(user_id):
    db = get_db()
    current_user_id = session['user_id']
    
    # Get other user details with nickname
    other_user = db.query("""
        SELECT u.*, COALESCE(n.nickname, u.username) as display_name, n.nickname
        FROM users u
        LEFT JOIN nicknames n ON n.user_id = ? AND n.target_user_id = u.id
        WHERE u.id = ?
    """, (current_user_id, user_id), one=True)
    
    if not other_user:
        return "User not found", 404
    
    # Get messages between users - Filter out messages deleted by the current user
    messages_data = db.query("""
        SELECT * FROM messages 
        WHERE (
            (sender_id = ? AND receiver_id = ? AND is_deleted_sender = 0) 
            OR 
            (sender_id = ? AND receiver_id = ? AND is_deleted_receiver = 0)
        )
        ORDER BY created_at ASC
    """, (current_user_id, user_id, user_id, current_user_id))
    
    # Process messages for timestamp formatting and reactions
    from datetime import datetime, timedelta
    formatted_messages = []
    for msg in messages_data:
        msg_dict = dict(msg)
        
        # Format timestamps (created_at)
        try:
            dt = datetime.strptime(msg_dict['created_at'], '%Y-%m-%d %H:%M:%S')
            dt_gmt8 = dt + timedelta(hours=8)
            msg_dict['display_time'] = dt_gmt8.strftime('%I:%M %p').lower()
        except Exception:
            msg_dict['display_time'] = msg_dict['created_at']

        # Format read_at
        if msg_dict['read_at']:
            try:
                rdt = datetime.strptime(msg_dict['read_at'], '%Y-%m-%d %H:%M:%S')
                rdt_gmt8 = rdt + timedelta(hours=8)
                msg_dict['display_read_at'] = rdt_gmt8.strftime('%I:%M %p').lower()
            except Exception:
                msg_dict['display_read_at'] = msg_dict['read_at']
        else:
            msg_dict['display_read_at'] = None

        # Fetch reactions with reactor avatars
        reactions = db.query("""
            SELECT mr.reaction, COUNT(*) as count, u.profile_pic, u.username
            FROM message_reactions mr
            JOIN users u ON mr.user_id = u.id
            WHERE mr.message_id = ? 
            GROUP BY mr.reaction
        """, (msg_dict['id'],))
        
        processed_reactions = []
        for r in reactions:
            processed_reactions.append({
                'reaction': r['reaction'],
                'count': r['count'],
                'avatar': r['profile_pic'] if r['profile_pic'] else f"https://ui-avatars.com/api/?name={r['username']}&background=random"
            })
        msg_dict['reactions'] = processed_reactions
        
        # Fetch reply_to_message data if this message is a reply
        if msg_dict.get('reply_to'):
            original_msg = db.query("""
                SELECT m.content, m.sender_id, u.username as sender_name
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE m.id = ?
            """, (msg_dict['reply_to'],), one=True)
            if original_msg:
                msg_dict['reply_to_message'] = {
                    'content': original_msg['content'],
                    'sender_id': original_msg['sender_id'],
                    'sender_name': original_msg['sender_name']
                }
            else:
                msg_dict['reply_to_message'] = None
        else:
            msg_dict['reply_to_message'] = None
        
        formatted_messages.append(msg_dict)
    
    # Mark messages as read and delivered, and set read_at if not already set
    conn = db.get_connection()
    now_utc = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute("""
        UPDATE messages 
        SET is_read = 1, is_delivered = 1, read_at = COALESCE(read_at, ?) 
        WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
    """, (now_utc, user_id, current_user_id))
    conn.commit()

    # Emit read receipt to the other user
    socketio.emit('read_receipt', {
        'reader_id': current_user_id,
        'sender_id': user_id
    }, room=f"user_{user_id}")
    
    # Check if current user has blocked the other user
    is_blocked = False
    try:
        blocked_row = db.query(
            "SELECT * FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
            (current_user_id, user_id), one=True
        )
        is_blocked = bool(blocked_row)
    except:
        pass  # Table doesn't exist yet

    # Check if current user has muted the other user
    is_muted = False
    try:
        muted_row = db.query(
            "SELECT * FROM muted_chats WHERE user_id = ? AND muted_user_id = ? AND (expires_at IS NULL OR expires_at > ?)",
            (current_user_id, user_id, now_utc), one=True
        )
        is_muted = bool(muted_row)
    except:
        pass
    
    return render_template('messages/chat.html', messages=formatted_messages, other_user=other_user, current_user_id=current_user_id, db=db, is_blocked=is_blocked, is_muted=is_muted)

@app.route('/messages/updates/<int:user_id>')
@login_required
def get_message_updates(user_id):
    current_user_id = session['user_id']
    db = get_db()
    
    # Status of messages I SENT to this user
    sent_messages = db.query("""
        SELECT id, is_read, is_delivered, read_at, is_deleted_sender FROM messages 
        WHERE sender_id = ? AND receiver_id = ?
        ORDER BY created_at DESC LIMIT 50
    """, (current_user_id, user_id))
    
    processed_updates = []
    from datetime import datetime, timedelta
    for msg in sent_messages:
        m = dict(msg)
        if m['read_at']:
            try:
                rdt = datetime.strptime(m['read_at'], '%Y-%m-%d %H:%M:%S')
                rdt_gmt8 = rdt + timedelta(hours=8)
                m['display_read_at'] = rdt_gmt8.strftime('%H:%M').lower()
            except Exception:
                m['display_read_at'] = m['read_at']
        else:
            m['display_read_at'] = None
        processed_updates.append(m)
    
    # IDs of messages I RECEIVED that are now deleted for me (possibly deleted for both by sender)
    deleted_received = db.query("""
        SELECT id FROM messages 
        WHERE sender_id = ? AND receiver_id = ? AND is_deleted_receiver = 1
        ORDER BY created_at DESC LIMIT 50
    """, (user_id, current_user_id))
    
    return {
        'status': 'success', 
        'updates': processed_updates,
        'deleted_ids': [m['id'] for m in deleted_received]
    }

@app.route('/messages/react/<int:message_id>', methods=['POST'])
@login_required
def react_to_message(message_id):
    current_user_id = session['user_id']
    reaction = request.form.get('reaction')
    if not reaction:
        return {'status': 'error', 'message': 'No reaction provided'}, 400
        
    db = get_db()
    conn = db.get_connection()
    
    try:
        # Check if already reacted with this emoji
        # We fetch all matching rows to handle potential duplicates from previous bugs
        existing_rows = db.query("SELECT * FROM message_reactions WHERE message_id = ? AND user_id = ? AND reaction = ?", 
                           (message_id, current_user_id, reaction))
        
        if existing_rows:
            # Toggle OFF: Delete all instances of this reaction from this user for this message
            conn.execute("DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND reaction = ?", 
                        (message_id, current_user_id, reaction))
        else:
            # Toggle ON: Insert new reaction
            conn.execute("INSERT INTO message_reactions (message_id, user_id, reaction) VALUES (?, ?, ?)", 
                        (message_id, current_user_id, reaction))
        conn.commit()
        
        # Get new reaction counts and reactor avatars
        # We query the database again through the same connection logic (db.query uses conn internally)
        counts = db.query("""
            SELECT mr.reaction, COUNT(*) as count, 
                   u.profile_pic, u.username
            FROM message_reactions mr
            JOIN users u ON mr.user_id = u.id
            WHERE mr.message_id = ? 
            GROUP BY mr.reaction
        """, (message_id,))
        
        # Process results to group by reaction
        reactions_list = []
        for row in counts:
            reactions_list.append({
                'reaction': row['reaction'],
                'count': row['count'],
                'avatar': row['profile_pic'] if row['profile_pic'] else f"https://ui-avatars.com/api/?name={row['username']}&background=random"
            })
            
        # Emit socket event
        msg = db.query("SELECT group_id, sender_id, receiver_id FROM messages WHERE id = ?", (message_id,), one=True)
        socket_data = {
            'message_id': message_id,
            'reactions': reactions_list
        }
        
        if msg:
            if msg['group_id']:
                socketio.emit('message_reaction', socket_data, room=f"group_{msg['group_id']}")
            else:
                # For 1:1, emit to both sender and receiver rooms (if they are online)
                # But typically we rely on client side update or room subscriptions?
                # Standard chat logic might expect 'message_reaction' in user room?
                # Let's emit to both user_sender and user_receiver rooms if they strictly follow user_<id> pattern
                # But actually, chat.html might be listening on specific room?
                # Assuming 'join' joins 'user_<id>' room? 
                # Let's emit to specific rooms:
                socketio.emit('message_reaction', socket_data, room=f"user_{msg['sender_id']}")
                socketio.emit('message_reaction', socket_data, room=f"user_{msg['receiver_id']}")
            
        return {'status': 'success', 'reactions': reactions_list}
    except Exception as e:
        print(f"Reaction error: {e}")
        return {'status': 'error', 'message': str(e)}, 500
    finally:
        conn.close()

@app.route('/messages/pin/<int:message_id>', methods=['POST'])
@login_required
def toggle_pin_message(message_id):
    current_user_id = session['user_id']
    db = get_db()
    
    message = db.query("SELECT * FROM messages WHERE id = ?", (message_id,), one=True)
    if not message:
        return {'status': 'error', 'message': 'Message not found'}, 404

    # Permission check
    if message['group_id']:
        # Check if user is member of the group
        is_member = db.query("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?", 
                           (message['group_id'], current_user_id), one=True)
        if not is_member:
             return {'status': 'error', 'message': 'Unauthorized'}, 403
    else:
        # Private chat check
        if message['sender_id'] != current_user_id and message['receiver_id'] != current_user_id:
            return {'status': 'error', 'message': 'Unauthorized'}, 403
        
    conn = db.get_connection()
    new_status = 1 if not message['is_pinned'] else 0
    conn.execute("UPDATE messages SET is_pinned = ? WHERE id = ?", (new_status, message_id))
    conn.commit()
    
    return {'status': 'success', 'is_pinned': bool(new_status)}

@app.route('/messages/delete-chat/<int:user_id>', methods=['POST'])
@login_required
def delete_chat(user_id):
    """Delete all messages between current user and specified user"""
    current_user_id = session['user_id']
    delete_for_both = request.form.get('delete_for_both') == 'true'
    
    db = get_db()
    conn = db.get_connection()
    
    try:
        if delete_for_both:
            # Actually delete messages for both parties
            conn.execute("""
                DELETE FROM messages 
                WHERE (sender_id = ? AND receiver_id = ?) 
                   OR (sender_id = ? AND receiver_id = ?)
            """, (current_user_id, user_id, user_id, current_user_id))
        else:
            # Delete messages where current user sent them
            conn.execute("""
                DELETE FROM messages 
                WHERE sender_id = ? AND receiver_id = ?
            """, (current_user_id, user_id))
            # For received messages, mark as deleted for receiver
            conn.execute("""
                UPDATE messages 
                SET is_deleted_receiver = 1
                WHERE sender_id = ? AND receiver_id = ?
            """, (user_id, current_user_id))
        
        conn.commit()
        return {'status': 'success'}
    except Exception as e:
        print(f"Delete chat error: {e}")
        return {'status': 'error', 'message': str(e)}, 500
    finally:
        conn.close()

@app.route('/users/block/<int:user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    """Block a user"""
    current_user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    
    try:
        # Create blocked_users table first if not exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                blocker_id INTEGER NOT NULL,
                blocked_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (blocker_id) REFERENCES users(id),
                FOREIGN KEY (blocked_id) REFERENCES users(id),
                UNIQUE(blocker_id, blocked_id)
            )
        """)
        conn.commit()
        
        # Now check if already blocked
        existing = db.query(
            "SELECT * FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
            (current_user_id, user_id), one=True
        )
        
        if existing:
            return {'status': 'error', 'message': 'User already blocked'}, 400
        
        conn.execute(
            "INSERT INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)",
            (current_user_id, user_id)
        )
        conn.commit()
        
        return {'status': 'success'}
    except Exception as e:
        print(f"Block user error: {e}")
        return {'status': 'error', 'message': str(e)}, 500
    finally:
        conn.close()

@app.route('/users/unblock/<int:user_id>', methods=['POST'])
@login_required
def unblock_user(user_id):
    """Unblock a user"""
    current_user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    
    try:
        conn.execute(
            "DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
            (current_user_id, user_id)
        )
        conn.commit()
        return {'status': 'success'}
    except Exception as e:
        print(f"Unblock user error: {e}")
        return {'status': 'error', 'message': str(e)}, 500
    finally:
        conn.close()

@app.route('/users/report/<int:user_id>', methods=['POST'])
@login_required
def report_user(user_id):
    """Report a user for inappropriate behavior"""
    current_user_id = session['user_id']
    reason = request.form.get('reason', 'Inappropriate behavior')
    
    db = get_db()
    conn = db.get_connection()
    
    try:
        # Create reports table if not exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_id INTEGER NOT NULL,
                reported_id INTEGER NOT NULL,
                reason TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',
                FOREIGN KEY (reporter_id) REFERENCES users(id),
                FOREIGN KEY (reported_id) REFERENCES users(id)
            )
        """)
        
        conn.execute(
            "INSERT INTO user_reports (reporter_id, reported_id, reason) VALUES (?, ?, ?)",
            (current_user_id, user_id, reason)
        )
        conn.commit()
        
        return {'status': 'success'}
    except Exception as e:
        print(f"Report user error: {e}")
        return {'status': 'error', 'message': str(e)}, 500
    finally:
        conn.close()

@app.route('/messages/mute/<int:user_id>', methods=['POST'])
@login_required
def toggle_mute_chat(user_id):
    """Toggle mute for a chat, optionally with duration (minutes)"""
    current_user_id = session['user_id']
    base_user = get_current_user()
    db = get_db()
    conn = db.get_connection()
    
    data = request.get_json() if request.is_json else {}
    duration = data.get('duration') # None, or int (minutes), or -1 (forever)

    try:
        # Create muted_chats table if not exists with expires_at
        # Note: We assume the column exists (added via migration command)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS muted_chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                muted_user_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (muted_user_id) REFERENCES users(id),
                UNIQUE(user_id, muted_user_id)
            )
        """)
        conn.commit()
        
        # Check if already muted
        existing = db.query(
            "SELECT * FROM muted_chats WHERE user_id = ? AND muted_user_id = ?",
            (current_user_id, user_id), one=True
        )
        
        if duration is not None:
            # Explicit Mute Requested
            expires_at = None
            if duration != -1:
                expires_at = (datetime.utcnow() + timedelta(minutes=int(duration))).strftime('%Y-%m-%d %H:%M:%S')
            
            if existing:
                conn.execute(
                    "UPDATE muted_chats SET expires_at = ?, created_at = CURRENT_TIMESTAMP WHERE user_id = ? AND muted_user_id = ?",
                    (expires_at, current_user_id, user_id)
                )
            else:
                conn.execute(
                    "INSERT INTO muted_chats (user_id, muted_user_id, expires_at) VALUES (?, ?, ?)",
                    (current_user_id, user_id, expires_at)
                )
            conn.commit()
            return {'status': 'success', 'is_muted': True, 'expires_at': expires_at}

        # Toggle behavior (fallback)
        if existing:
            # Unmute
            conn.execute(
                "DELETE FROM muted_chats WHERE user_id = ? AND muted_user_id = ?",
                (current_user_id, user_id)
            )
            conn.commit()
            return {'status': 'success', 'is_muted': False}
        else:
            # Mute Forever (default toggle)
            conn.execute(
                "INSERT INTO muted_chats (user_id, muted_user_id, expires_at) VALUES (?, ?, NULL)",
                (current_user_id, user_id)
            )
            conn.commit()
            return {'status': 'success', 'is_muted': True}
            
    except Exception as e:
        print(f"Mute chat error: {e}")
        return {'status': 'error', 'message': str(e)}, 500
    finally:
        conn.close()

@app.route('/messages/upload/<int:recipient_id>', methods=['POST'])
@login_required
def upload_media(recipient_id):
    if 'file' not in request.files:
        return {'status': 'error', 'message': 'No file part'}, 400
    
    file = request.files['file']
    if file.filename == '':
        return {'status': 'error', 'message': 'No selected file'}, 400
    
    if file:
        sender_id = session['user_id']
        filename = secure_filename(file.filename)
        
        # Handle blobs which might not have an extension
        if not '.' in filename:
            # Check mimetype for voice recording blobs
            mimetype = file.mimetype
            if mimetype == 'audio/webm':
                filename += '.webm'
            elif mimetype == 'audio/ogg':
                filename += '.ogg'
            elif mimetype == 'audio/wav':
                filename += '.wav'
            else:
                filename += '.bin'

        # Generate unique filename to avoid collisions
        import uuid
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # Determine message content (the file path)
        content = f"/static/uploads/{unique_filename}"
        
        reply_to = request.form.get('reply_to')
        
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO messages (sender_id, receiver_id, content, reply_to) VALUES (?, ?, ?, ?)",
                (sender_id, recipient_id, content, reply_to)
            )
            message_id = cursor.lastrowid
            
            # Unarchive for both
            cursor.execute("DELETE FROM archived_chats WHERE user_id = ? AND archived_user_id = ?", (sender_id, recipient_id))
            cursor.execute("DELETE FROM archived_chats WHERE user_id = ? AND archived_user_id = ?", (recipient_id, sender_id))
            
            conn.commit()
            
            from datetime import datetime
            display_time = datetime.now().strftime('%I:%M %p').lower()
            
            return {
                'status': 'success',
                'message': {
                    'id': message_id,
                    'content': content,
                    'display_time': display_time,
                    'sender_id': sender_id,
                    'reply_to': reply_to
                }
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}, 500

@app.route('/messages/send/<int:recipient_id>', methods=['POST'])
@login_required
def send_message(recipient_id):
    content = request.form.get('content', '').strip()
    if not content:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
            return {'status': 'error', 'message': 'Empty message'}, 400
        return redirect(url_for('chat', user_id=recipient_id))
        
    sender_id = session['user_id']
    
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    reply_to = request.form.get('reply_to')
    
    try:
        cursor.execute(
            "INSERT INTO messages (sender_id, receiver_id, content, reply_to) VALUES (?, ?, ?, ?)",
            (sender_id, recipient_id, content, reply_to)
        )
        message_id = cursor.lastrowid
        # Unarchive for both users
        conn.execute("DELETE FROM archived_chats WHERE user_id = ? AND archived_user_id = ?", (sender_id, recipient_id))
        conn.execute("DELETE FROM archived_chats WHERE user_id = ? AND archived_user_id = ?", (recipient_id, sender_id))
        conn.commit()
        
        # Format time for the response
        from datetime import datetime
        display_time = datetime.now().strftime('%I:%M %p').lower()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
            return {
                'status': 'success',
                'message': {
                    'id': message_id,
                    'content': content,
                    'display_time': display_time,
                    'sender_id': sender_id,
                    'reply_to': reply_to
                }
            }
            
        flash('Message sent!', 'success')
        return redirect(url_for('chat', user_id=recipient_id))
    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
            return {'status': 'error', 'message': str(e)}, 500
        flash('An error occurred.', 'danger')
        return redirect(url_for('chat', user_id=recipient_id))

@app.route('/messages/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    user_id = session['user_id']
    db = get_db()
    
    # Verify the message exists and belongs to the current user
    message = db.query("SELECT * FROM messages WHERE id = ?", (message_id,), one=True)
    
    if not message:
        flash('Message not found.', 'danger')
        return redirect(request.referrer or url_for('messages'))
        
    if message['sender_id'] != user_id and message['receiver_id'] != user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(request.referrer or url_for('messages'))
    
    recipient_id = message['receiver_id'] if message['sender_id'] == user_id else message['sender_id']
    for_everyone = request.form.get('for_everyone') == 'true'
    
    conn = db.get_connection()
    if for_everyone and message['sender_id'] == user_id:
        # Delete for both: set both flags to 1
        conn.execute("UPDATE messages SET is_deleted_sender = 1, is_deleted_receiver = 1 WHERE id = ?", (message_id,))
    else:
        # Delete for me: set flag based on user's role in the message
        if message['sender_id'] == user_id:
            conn.execute("UPDATE messages SET is_deleted_sender = 1 WHERE id = ?", (message_id,))
        else:
            conn.execute("UPDATE messages SET is_deleted_receiver = 1 WHERE id = ?", (message_id,))
    conn.commit()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
        return {'status': 'success', 'message': 'Message deleted'}
        
    flash('Message deleted.', 'info')
    return redirect(url_for('chat', user_id=recipient_id))

@app.route('/messages/delete-batch', methods=['POST'])
@login_required
def delete_batch_messages():
    try:
        current_user_id = session['user_id']
        message_ids = request.form.getlist('message_ids[]')
        for_everyone = request.form.get('for_everyone') == 'true'
        
        if not message_ids:
            return {'status': 'error', 'message': 'No messages selected'}, 400
            
        db = get_db()
        conn = db.get_connection()
        
        # We need to process each message to ensure ownership/permissions
        # Optimally we would do this in a single query, but for safety lets loop or use IN clause carefully
        
        # Placeholders for IN clause
        placeholders = ','.join(['?'] * len(message_ids))
        
        # Fetch messages to verify ownership
        query = f"SELECT * FROM messages WHERE id IN ({placeholders})"
        messages = db.query(query, tuple(message_ids))
        
        ids_to_delete_for_sender = []
        ids_to_delete_for_receiver = []
        ids_to_delete_for_both = []
        
        for msg in messages:
            # Security check: User must be sender or receiver
            if msg['sender_id'] != current_user_id and msg['receiver_id'] != current_user_id:
                continue
                
            if for_everyone and msg['sender_id'] == current_user_id:
                # Can only delete for everyone if you are the sender
                ids_to_delete_for_both.append(msg['id'])
            else:
                # Delete for me only
                if msg['sender_id'] == current_user_id:
                    ids_to_delete_for_sender.append(msg['id'])
                else:
                    ids_to_delete_for_receiver.append(msg['id'])
        
        # Execute updates
        if ids_to_delete_for_both:
            ph = ','.join(['?'] * len(ids_to_delete_for_both))
            conn.execute(f"UPDATE messages SET is_deleted_sender = 1, is_deleted_receiver = 1 WHERE id IN ({ph})", tuple(ids_to_delete_for_both))
            
        if ids_to_delete_for_sender:
            ph = ','.join(['?'] * len(ids_to_delete_for_sender))
            conn.execute(f"UPDATE messages SET is_deleted_sender = 1 WHERE id IN ({ph})", tuple(ids_to_delete_for_sender))
            
        if ids_to_delete_for_receiver:
            ph = ','.join(['?'] * len(ids_to_delete_for_receiver))
            conn.execute(f"UPDATE messages SET is_deleted_receiver = 1 WHERE id IN ({ph})", tuple(ids_to_delete_for_receiver))
            
        conn.commit()
        return {'status': 'success', 'count': len(messages)}
        
    except Exception as e:
        print(f"Batch delete error: {e}")
        return {'status': 'error', 'message': str(e)}, 500

@app.route('/messages/edit/<int:message_id>', methods=['POST'])
@login_required
def edit_message(message_id):
    new_content = request.form['content']
    user_id = session['user_id']
    db = get_db()
    
    # Verify the message exists and belongs to the current user
    message = db.query("SELECT * FROM messages WHERE id = ?", (message_id,), one=True)
    
    if not message:
        flash('Message not found.', 'danger')
        return redirect(request.referrer or url_for('messages'))
        
    if message['sender_id'] != user_id:
        flash('You can only edit your own messages.', 'danger')
        return redirect(request.referrer or url_for('messages'))
    
    conn = db.get_connection()
    conn.execute("UPDATE messages SET content = ? WHERE id = ?", (new_content, message_id))
    conn.commit()
    
    # Emit socket update
    try:
        msg_data = db.query("SELECT group_id, sender_id, receiver_id FROM messages WHERE id = ?", (message_id,), one=True)
        if msg_data:
            update_payload = {
                'id': message_id,
                'content': new_content,
                'group_id': msg_data['group_id']
            }
            if msg_data['group_id']:
                socketio.emit('message_update', update_payload, room=f"group_{msg_data['group_id']}")
            else:
                socketio.emit('message_update', update_payload, room=f"user_{msg_data['sender_id']}")
                socketio.emit('message_update', update_payload, room=f"user_{msg_data['receiver_id']}")
    except Exception as e:
        print(f"Socket emit error: {e}")
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
        return {'status': 'success', 'message': 'Message updated', 'content': new_content}
        
    flash('Message updated.', 'success')
    
    # Redirect based on context
    if message['group_id']:
        return redirect(url_for('group_chat', group_id=message['group_id']))
    else:
        recipient_id = message['receiver_id']
        return redirect(url_for('chat', user_id=recipient_id))

@app.route('/messages/<int:user_id>/delete-chat', methods=['POST'])
@login_required
def delete_chat_conversation(user_id):
    """Delete all messages between current user and specified user"""
    current_user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    
    # Hide all messages for the current user
    # If user is sender, set is_deleted_sender = 1
    # If user is receiver, set is_deleted_receiver = 1
    conn.execute("""
        UPDATE messages 
        SET is_deleted_sender = 1
        WHERE (sender_id = ? AND receiver_id = ?)
    """, (current_user_id, user_id))
    
    conn.execute("""
        UPDATE messages 
        SET is_deleted_receiver = 1
        WHERE (sender_id = ? AND receiver_id = ?)
    """, (user_id, current_user_id))
    
    conn.commit()
    
    flash('Chat deleted successfully.', 'info')
    return redirect(url_for('messages'))

# --- Comment Management ---
@app.route('/comment/<int:comment_id>/edit', methods=['POST'])
@login_required
def edit_comment(comment_id):
    new_content = request.form['content']
    user_id = session['user_id']
    
    db = get_db()
    # Verify ownership
    comment = db.query("SELECT * FROM comments WHERE id = ?", (comment_id,), one=True)
    
    if not comment:
        flash('Comment not found.', 'danger')
        return redirect(request.referrer)
        
    if comment['user_id'] != user_id:
        flash('You can only edit your own comments.', 'danger')
        return redirect(request.referrer)
        
    conn = db.get_connection()
    conn.execute("UPDATE comments SET content = ? WHERE id = ?", (new_content, comment_id))
    conn.commit()
    flash('Comment updated.', 'success')
    return redirect(request.referrer)

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    user_id = session['user_id']
    
    db = get_db()
    comment = db.query("SELECT * FROM comments WHERE id = ?", (comment_id,), one=True)
    
    if not comment:
        return redirect(request.referrer)
        
    if comment['user_id'] != user_id:
        flash('Unauthorized action.', 'danger')
        return redirect(request.referrer)
        
    conn = db.get_connection()
    conn.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    conn.commit()
    flash('Comment deleted.', 'info')
    return redirect(request.referrer)



@app.route('/profile')
@login_required
def profile():
    db = get_db()
    user_id = session['user_id']
    
    # Get user from database
    user_data = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    
    if user_data:
        user = {
            'id': user_data['id'],
            'full_name': user_data['full_name'] or user_data['username'],
            'username': user_data['username'],
            'user_type': user_data['role'].capitalize(),
            'bio': user_data['bio'],
            'profile_pic': user_data['profile_pic'] or f"https://ui-avatars.com/api/?name={user_data['username']}&background=8D6E63&color=fff"
        }
    else:
        # Fallback if user session is invalid
        return redirect(url_for('logout'))
    
    return render_template('profile.html', user=user)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    user_id = session['user_id']
    full_name = request.form.get('full_name', '')
    bio = request.form.get('bio', '')
    profile_pic = request.form.get('profile_pic', '')
    
    db = get_db()
    conn = db.get_connection()
    conn.execute(
        "UPDATE users SET full_name = ?, bio = ?, profile_pic = ? WHERE id = ?",
        (full_name, bio, profile_pic, user_id)
    )
    conn.commit()
    return redirect(url_for('profile'))

@app.route('/profile/delete', methods=['POST'])
@login_required
def delete_account():
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    
    # Optional: Delete all their data? cascade usually handles it or we manually delete.
    # For now, let's assume we just delete the user and rely on manual cleanup or cascade if configured.
    # Current DB setup might not cascade everything, but let's just delete the user row.
    
    try:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        session.clear()
        flash('Your account has been permanently deleted.', 'info')
    except Exception as e:
        flash('An error occurred while deleting your account.', 'danger')
        
    return redirect(url_for('home'))
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/community')
def community():
    db = get_db()
    # Get groups with member counts
    groups = db.query("""
        SELECT g.*, 
               (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
        FROM groups g
        ORDER BY g.created_at DESC
    """)
    return render_template('community/index.html', groups=groups)

@app.route('/community/<int:group_id>')
def view_group(group_id):
    db = get_db()
    group = db.query("SELECT * FROM groups WHERE id = ?", (group_id,), one=True)
    if not group:
        return "Group not found", 404
    
    is_member = False
    member_count = len(db.query("SELECT * FROM group_members WHERE group_id = ?", (group_id,)))
    
    if 'user_id' in session:
        user_id = session['user_id']
        membership = db.query("SELECT * FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user_id), one=True)
        is_member = bool(membership)
    
    # Get members
    members = db.query("""
        SELECT u.* FROM users u
        JOIN group_members gm ON u.id = gm.user_id
        WHERE gm.group_id = ?
    """, (group_id,))
    
    return render_template('community/view.html', group=group, is_member=is_member, member_count=member_count, members=members)

@app.route('/community/new', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        image_url = request.form.get('image_url', '')
        user_id = session['user_id']
        
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO groups (name, description, image_url, created_by) VALUES (?, ?, ?, ?)",
            (name, description, image_url, user_id)
        )
        group_id = cursor.lastrowid
        # Auto-join creator
        cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, user_id))
        conn.commit()
        flash(f'Group "{name}" created!', 'success')
        return redirect(url_for('community'))
    
    return render_template('community/create.html')

@app.route('/community/<int:group_id>/join', methods=['POST'])
@login_required
def join_group(group_id):
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    try:
        conn.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, user_id))
        conn.commit()
    except:
        pass  # Already a member
    return redirect(url_for('view_group', group_id=group_id))

@app.route('/community/<int:group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    conn.execute("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user_id))
    conn.commit()
    return redirect(url_for('view_group', group_id=group_id))


@app.route('/faq')
@login_required
def faq():
    return render_template('faq.html')


# --- User Status API ---
@app.route('/users/status/<int:user_id>')
@login_required
def get_user_status(user_id):
    from datetime import datetime, timedelta
    db = get_db()
    user = db.query("SELECT last_activity FROM users WHERE id = ?", (user_id,), one=True)
    
    if not user or not user['last_activity']:
        return {'status': 'unknown', 'text': 'last seen recently'}
    
    try:
        last_activity = datetime.strptime(user['last_activity'], '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return {'status': 'unknown', 'text': 'last seen recently'}
    
    now = datetime.utcnow()
    diff = now - last_activity
    diff_seconds = diff.total_seconds()
    
    if diff_seconds < 60:
        return {'status': 'online', 'text': 'online'}
    elif diff_seconds < 3600:  # Less than 60 minutes
        minutes = int(diff_seconds // 60)
        return {'status': 'away', 'text': f'last seen {minutes} min ago'}
    elif diff_seconds < 86400:  # Less than 24 hours
        hours = int(diff_seconds // 3600)
        return {'status': 'away', 'text': f'last seen {hours} hour{"s" if hours > 1 else ""} ago'}
    else:
        # More than 24 hours, show date
        last_activity_local = last_activity + timedelta(hours=8)  # SGT
        return {'status': 'offline', 'text': f'last seen {last_activity_local.strftime("%d %b")}'}


# --- Message Search API ---
@app.route('/messages/search/<int:user_id>')
@login_required
def search_messages(user_id):
    current_user_id = session['user_id']
    query_text = request.args.get('q', '').strip()
    
    if not query_text:
        return {'status': 'error', 'message': 'No search query provided'}
    
    db = get_db()
    messages = db.query("""
        SELECT id, content, created_at FROM messages 
        WHERE (
            (sender_id = ? AND receiver_id = ? AND is_deleted_sender = 0) 
            OR 
            (sender_id = ? AND receiver_id = ? AND is_deleted_receiver = 0)
        )
        AND content LIKE ?
        ORDER BY created_at DESC
        LIMIT 50
    """, (current_user_id, user_id, user_id, current_user_id, f'%{query_text}%'))
    
    return {'status': 'success', 'results': [dict(m) for m in messages]}





# --- Call Signaling API ---
@app.route('/calls/signal', methods=['POST'])
@login_required
def send_signal():
    try:
        data = request.json
        sender_id = session['user_id']
        receiver_id = data.get('receiver_id')
        signal_type = data.get('type')
        signal_data = data.get('data')

        if not receiver_id or not signal_type or not signal_data:
            return {'status': 'error', 'message': 'Missing data'}, 400

        db = get_db()
        conn = db.get_connection()
        try:
            conn.execute(
                "INSERT INTO call_signals (sender_id, receiver_id, type, data) VALUES (?, ?, ?, ?)",
                (sender_id, receiver_id, signal_type, str(signal_data)) # Store JSON as string
            )
            conn.commit()
        finally:
            conn.close()
        return {'status': 'success'}
    except Exception as e:
        print(f"Signal Error: {e}")
        return {'status': 'error', 'message': str(e)}, 500

@app.route('/calls/signals/<int:user_id>', methods=['GET'])
@login_required
def get_signals(user_id):
    # Get signals sent TO the current user FROM the specified user (or all if not specified, but usually we poll for a specific chat context)
    # Actually, for a global listener, we might want *all* signals for me.
    # But inside a chat room, we only care about that user.
    # Let's implement getting all pending signals for ME, and filters in JS.
    
    # Wait, the route says <int:user_id>, implying getting signals relevant to a specific partner.
    # Let's stick to that for the chat context.
    
    current_user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    
    # Fetch signals where I am the receiver
    signals = db.query("""
        SELECT * FROM call_signals 
        WHERE receiver_id = ? AND sender_id = ?
        ORDER BY created_at ASC
    """, (current_user_id, user_id))
    
    # Delete fetched signals so they aren't processed twice (Queue behavior)
    if signals:
        ids_to_delete = [s['id'] for s in signals]
        placeholders = ','.join(['?'] * len(ids_to_delete))
        conn.execute(f"DELETE FROM call_signals WHERE id IN ({placeholders})", tuple(ids_to_delete))
        conn.commit()
    
    results = []
    for s in signals:
        import ast
        try:
            # Safely evaluate string representation of dict/list
            data_obj = ast.literal_eval(s['data'])
        except:
            data_obj = s['data']
            
        results.append({
            'type': s['type'],
            'data': data_obj,
            'created_at': s['created_at']
        })
        
    return {'status': 'success', 'signals': results}


@app.route('/api/messages/mark_all_read', methods=['POST'])
@login_required
def mark_all_read():
    db = get_db()
    user_id = session['user_id']
    conn = db.get_connection()
    conn.execute("UPDATE messages SET is_read = 1, read_at = ? WHERE receiver_id = ? AND is_read = 0", 
                 (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), user_id))
    conn.commit()
    return jsonify({'status': 'success'})


# --- API: Get All Users (for New Chat / New Group) ---
@app.route('/api/users/all')
@login_required
def api_get_all_users():
    """Get all users except current user, with frequently contacted info"""
    current_user_id = session['user_id']
    db = get_db()
    
    # Get all users
    users = db.query("""
        SELECT u.id, u.username, u.profile_pic, u.bio,
        (SELECT COUNT(*) FROM messages m 
         WHERE (m.sender_id = ? AND m.receiver_id = u.id) 
         OR (m.sender_id = u.id AND m.receiver_id = ?)) as msg_count
        FROM users u
        WHERE u.id != ?
        ORDER BY u.username COLLATE NOCASE ASC
    """, (current_user_id, current_user_id, current_user_id))
    
    result = []
    for u in users:
        result.append({
            'id': u['id'],
            'username': u['username'],
            'profile_pic': u['profile_pic'] or f"https://ui-avatars.com/api/?name={u['username']}&background=A68A64&color=1c1c1e&bold=true",
            'bio': u['bio'] or '',
            'msg_count': u['msg_count'] or 0
        })
    
    return jsonify({'status': 'success', 'users': result})


# --- API: Create Group ---
@app.route('/api/groups/create', methods=['POST'])
@login_required
def api_create_group():
    """Create a new group chat"""
    current_user_id = session['user_id']
    data = request.get_json()
    
    name = data.get('name', '').strip()
    member_ids = data.get('member_ids', [])
    
    if not name:
        name = 'New Group'
    
    if len(member_ids) < 2:
        return jsonify({'status': 'error', 'message': 'Select at least 2 members'}), 400
    
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        # Generate group avatar (simple: use ui-avatars with group name)
        avatar_url = f"https://ui-avatars.com/api/?name={name.replace(' ', '+')}&background=A68A64&color=1c1c1e&bold=true&size=128"
        
        # Insert group
        cursor.execute(
            "INSERT INTO groups (name, description, image_url, created_by) VALUES (?, ?, ?, ?)",
            (name, '', avatar_url, current_user_id)
        )
        group_id = cursor.lastrowid
        
        # Add creator as member (admin)
        cursor.execute(
            "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
            (group_id, current_user_id)
        )
        
        # Add other members
        for member_id in member_ids:
            if member_id != current_user_id:
                cursor.execute(
                    "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
                    (group_id, int(member_id))
                )
        
        conn.commit()
        
        return jsonify({
            'status': 'success', 
            'group_id': group_id,
            'redirect_url': url_for('group_chat', group_id=group_id)
        })
        
    except Exception as e:
        print(f"Create group error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()


# --- Group Chat View ---
@app.route('/messages/group/<int:group_id>')
@login_required
def group_chat(group_id):
    """View a group chat"""
    current_user_id = session['user_id']
    db = get_db()
    
    # Verify membership
    membership = db.query(
        "SELECT * FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, current_user_id), one=True
    )
    
    if not membership:
        flash('You are not a member of this group.', 'danger')
        return redirect(url_for('messages'))
    
    # Get group info
    group = db.query("SELECT * FROM groups WHERE id = ?", (group_id,), one=True)
    if not group:
        flash('Group not found.', 'danger')
        return redirect(url_for('messages'))
    
    # Get members
    members = db.query("""
        SELECT u.id, u.username, u.profile_pic,
               COALESCE(n.nickname, u.username) as display_name
        FROM users u
        JOIN group_members gm ON gm.user_id = u.id
        LEFT JOIN nicknames n ON n.user_id = ? AND n.target_user_id = u.id
        WHERE gm.group_id = ?
    """, (current_user_id, group_id))
    
    # Get messages
    messages_data = db.query("""
        SELECT m.*, 
               u.username as sender_username, 
               u.profile_pic as sender_profile_pic,
               COALESCE(n.nickname, u.username) as sender_display_name
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        LEFT JOIN nicknames n ON n.user_id = ? AND n.target_user_id = u.id
        WHERE m.group_id = ?
        ORDER BY m.created_at ASC
    """, (current_user_id, group_id))
    
    # Format messages
    from datetime import datetime, timedelta
    formatted_messages = []
    for msg in messages_data:
        d = dict(msg)
        if d['created_at']:
            try:
                dt = datetime.strptime(d['created_at'], '%Y-%m-%d %H:%M:%S')
                dt_sg = dt + timedelta(hours=8)
                d['display_time'] = dt_sg.strftime('%I:%M %p').lower()
            except:
                d['display_time'] = ''
        formatted_messages.append(d)
    
    return render_template('messages/group_chat.html', 
                         group=dict(group), 
                         members=[dict(m) for m in members],
                         messages=formatted_messages,
                         current_user_id=current_user_id)


# --- API: Send Message to Group ---
@app.route('/messages/group/<int:group_id>/send', methods=['POST'])
@login_required
def send_group_message(group_id):
    """Send a message to a group"""
    current_user_id = session['user_id']
    content = request.form.get('content', '').strip()
    
    if not content:
        return jsonify({'status': 'error', 'message': 'Empty message'}), 400
    
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Verify membership
    membership = db.query(
        "SELECT * FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, current_user_id), one=True
    )
    
    if not membership:
        return jsonify({'status': 'error', 'message': 'Not a member'}), 403
    
    reply_to = request.form.get('reply_to')
    
    try:
        if reply_to:
            cursor.execute(
                "INSERT INTO messages (sender_id, receiver_id, content, group_id, reply_to) VALUES (?, 0, ?, ?, ?)",
                (current_user_id, content, group_id, reply_to)
            )
        else:
            cursor.execute(
                "INSERT INTO messages (sender_id, receiver_id, content, group_id) VALUES (?, 0, ?, ?)",
                (current_user_id, content, group_id)
            )
            
        message_id = cursor.lastrowid
        conn.commit()
        
        # Fetch reply context if needed
        reply_context = None
        if reply_to:
            original_msg = db.query("""
                SELECT m.content, u.username as sender_name 
                FROM messages m 
                JOIN users u ON m.sender_id = u.id 
                WHERE m.id = ?
            """, (reply_to,), one=True)
            if original_msg:
                reply_context = {
                    'sender_name': original_msg['sender_name'],
                    'content': original_msg['content']
                }

        # Get sender profile pic
        sender = db.query("SELECT profile_pic FROM users WHERE id = ?", (current_user_id,), one=True)
        sender_profile_pic = sender['profile_pic'] if sender else None

        from datetime import datetime
        display_time = datetime.now().strftime('%I:%M %p').lower()

        message_data = {
            'id': message_id,
            'content': content,
            'display_time': display_time,
            'sender_id': current_user_id,
            'sender_username': session['username'],
            'sender_profile_pic': sender_profile_pic,
            'group_id': group_id,
            'reply_to': reply_to,
            'reply_to_message': reply_context
        }

        # Socket.io emit to group room
        socketio.emit('group_message', message_data, room=f"group_{group_id}")
        
        return jsonify({
            'status': 'success',
            'message': message_data
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()


@app.route('/messages/group/<int:group_id>/upload', methods=['POST'])
@login_required
def upload_group_file(group_id):
    """Handle file uploads in groups"""
    current_user_id = session['user_id']
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'}), 400

    filename = secure_filename(file.filename)
    # Generate unique filename
    unique_filename = f"{int(time.time())}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(file_path)
    
    relative_path = f"/static/uploads/{unique_filename}"
    
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO messages (sender_id, receiver_id, content, group_id) VALUES (?, 0, ?, ?)",
            (current_user_id, relative_path, group_id)
        )
        message_id = cursor.lastrowid
        conn.commit()
        
        from datetime import datetime
        display_time = datetime.now().strftime('%I:%M %p').lower()
        
        message_data = {
            'id': message_id,
            'content': relative_path,
            'display_time': display_time,
            'sender_id': current_user_id,
            'sender_username': session['username'],
            'group_id': group_id
        }
        
        socketio.emit('group_message', message_data, room=f"group_{group_id}")
        
        return jsonify({
            'status': 'success',
            'message': message_data
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()


# --- Delete Calls API ---
@app.route('/api/calls/delete', methods=['POST'])
@login_required
def api_delete_calls():
    """Delete multiple calls"""
    current_user_id = session['user_id']
    data = request.get_json()
    call_ids = data.get('call_ids', [])
    
    if not call_ids:
        return jsonify({'status': 'error', 'message': 'No calls specified'}), 400
    
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        # Only delete calls where user is caller or receiver
        placeholders = ','.join(['?' for _ in call_ids])
        cursor.execute(f"""
            DELETE FROM calls 
            WHERE id IN ({placeholders}) 
            AND (caller_id = ? OR receiver_id = ?)
        """, (*[int(cid) for cid in call_ids], current_user_id, current_user_id))
        conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()


# --- Mark Messages as Read (for a specific user) ---
@app.route('/api/messages/mark_read/<int:user_id>', methods=['POST'])
@login_required
def api_mark_messages_read(user_id):
    """Mark all messages from a specific user as read"""
    current_user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE messages SET is_read = 1, read_at = CURRENT_TIMESTAMP WHERE sender_id = ? AND receiver_id = ? AND is_read = 0",
            (user_id, current_user_id)
        )
        conn.commit()

        # Emit read receipt to the other user
        socketio.emit('read_receipt', {
            'reader_id': current_user_id,
            'sender_id': user_id
        }, room=f"user_{user_id}")
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()


# --- Archive Chat API ---
@app.route('/api/chats/archive/<int:user_id>', methods=['POST'])
@login_required
def api_archive_chat(user_id):
    """Archive a chat with a user"""
    current_user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        # Check if already archived
        existing = db.query(
            "SELECT * FROM archived_chats WHERE user_id = ? AND archived_user_id = ?",
            (current_user_id, user_id), one=True
        )
        
        if existing:
            return jsonify({'status': 'success', 'message': 'Already archived'})
        
        cursor.execute(
            "INSERT INTO archived_chats (user_id, archived_user_id) VALUES (?, ?)",
            (current_user_id, user_id)
        )
        conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()


# --- Unarchive Chat API ---
@app.route('/api/chats/unarchive/<int:user_id>', methods=['POST'])
@login_required
def api_unarchive_chat(user_id):
    """Unarchive a chat with a user"""
    current_user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "DELETE FROM archived_chats WHERE user_id = ? AND archived_user_id = ?",
            (current_user_id, user_id)
        )
        conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()


# --- Pin Chat API ---
@app.route('/api/chats/pin/<int:user_id>', methods=['POST'])
@login_required
def api_pin_chat(user_id):
    """Pin a chat with a user"""
    current_user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        existing = db.query(
            "SELECT * FROM pinned_chats WHERE user_id = ? AND pinned_user_id = ?",
            (current_user_id, user_id), one=True
        )
        
        if existing:
            # Unpin
            cursor.execute(
                "DELETE FROM pinned_chats WHERE user_id = ? AND pinned_user_id = ?",
                (current_user_id, user_id)
            )
            conn.commit()
            return jsonify({'status': 'success', 'pinned': False})
        else:
            # Pin
            cursor.execute(
                "INSERT INTO pinned_chats (user_id, pinned_user_id) VALUES (?, ?)",
                (current_user_id, user_id)
            )
            conn.commit()
            return jsonify({'status': 'success', 'pinned': True})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()


# --- Pin Group API ---
@app.route('/api/chats/pin_group/<int:group_id>', methods=['POST'])
@login_required
def api_pin_group(group_id):
    """Pin a group chat"""
    current_user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        existing = db.query(
            "SELECT * FROM pinned_groups WHERE user_id = ? AND group_id = ?",
            (current_user_id, group_id), one=True
        )
        
        if existing:
            # Unpin
            cursor.execute(
                "DELETE FROM pinned_groups WHERE user_id = ? AND group_id = ?",
                (current_user_id, group_id)
            )
            conn.commit()
            return jsonify({'status': 'success', 'pinned': False})
        else:
            # Pin
            cursor.execute(
                "INSERT INTO pinned_groups (user_id, group_id) VALUES (?, ?)",
                (current_user_id, group_id)
            )
            conn.commit()
            return jsonify({'status': 'success', 'pinned': True})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()


# --- Archived Chats View ---
@app.route('/messages/archived')
@login_required
def archived_chats_view():
    """View archived chats"""
    user_id = session['user_id']
    db = get_db()
    
    # Get archived chats with user info
    archived = db.query("""
        SELECT 
            u.id as user_id,
            u.username,
            u.profile_pic,
            'private' as type,
            (SELECT content FROM messages m2 
             WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id))
             AND m2.group_id IS NULL
             ORDER BY m2.created_at DESC LIMIT 1) as last_message,
            (SELECT created_at FROM messages m2 
             WHERE ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id))
             AND m2.group_id IS NULL
             ORDER BY m2.created_at DESC LIMIT 1) as last_message_time
        FROM archived_chats ac
        JOIN users u ON u.id = ac.archived_user_id
        WHERE ac.user_id = ?
    """, (user_id, user_id, user_id, user_id, user_id))
    
    # Format time
    now = datetime.utcnow() + timedelta(hours=8)
    archived_list = []
    for row in archived:
        d = dict(row)
        if d['last_message_time']:
            try:
                dt = datetime.strptime(d['last_message_time'], '%Y-%m-%d %H:%M:%S')
                dt_sg = dt + timedelta(hours=8)
                diff = now.date() - dt_sg.date()
                if diff.days == 0:
                    d['last_message_time'] = dt_sg.strftime('%#I:%M %p').lower()
                elif diff.days == 1:
                    d['last_message_time'] = 'Yesterday'
                else:
                    d['last_message_time'] = dt_sg.strftime('%d/%m/%y')
            except:
                pass
        archived_list.append(d)
    
    return render_template('messages/archived.html', archived_chats=archived_list)


# --- Nickname API ---
@app.route('/api/chats/nickname/<int:user_id>', methods=['GET', 'POST'])
@login_required
def api_nickname(user_id):
    """Get or set nickname for a user"""
    current_user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Ensure nicknames table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nicknames (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target_user_id INTEGER NOT NULL,
            nickname TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, target_user_id)
        )
    """)
    
    # Ensure pinned_groups table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pinned_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, group_id)
        )
    """)
    conn.commit()
    
    if request.method == 'GET':
        result = db.query(
            "SELECT nickname FROM nicknames WHERE user_id = ? AND target_user_id = ?",
            (current_user_id, user_id), one=True
        )
        nickname = result['nickname'] if result else None
        return jsonify({'status': 'success', 'nickname': nickname})
    
    else:  # POST
        nickname = request.json.get('nickname', '').strip() if request.is_json else request.form.get('nickname', '').strip()
        
        try:
            if nickname:
                cursor.execute("""
                    INSERT OR REPLACE INTO nicknames (user_id, target_user_id, nickname)
                    VALUES (?, ?, ?)
                """, (current_user_id, user_id, nickname))
            else:
                cursor.execute(
                    "DELETE FROM nicknames WHERE user_id = ? AND target_user_id = ?",
                    (current_user_id, user_id)
                )
            conn.commit()
            return jsonify({'status': 'success', 'nickname': nickname if nickname else None})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
        finally:
            conn.close()



# --- AI Chatbot API ---
# Simple keyword-based response engine for TogetherSG helper
# In-memory rate limiting per session (no database needed)

_chatbot_rate = {}  # { session_id: [timestamp, ...] }

@app.route('/api/chatbot', methods=['POST'])
def api_chatbot():
    """
    Accepts { "message": "user text" }
    Returns  { "reply":  "bot response" }
    """
    # --- Rate limiting: max 10 requests per minute per session ---
    sid = session.get('user_id', request.remote_addr)
    now = datetime.now()
    window = _chatbot_rate.setdefault(sid, [])
    # Remove entries older than 60 seconds
    window[:] = [t for t in window if (now - t).total_seconds() < 60]
    if len(window) >= 10:
        return jsonify({'reply': 'You are sending messages too quickly. Please wait a moment and try again.'}), 429
    window.append(now)

    data = request.get_json(silent=True) or {}
    user_msg = (data.get('message') or '').strip()

    if not user_msg:
        return jsonify({'reply': 'Please type a question and I will do my best to help!'}), 200
    if len(user_msg) > 500:
        return jsonify({'reply': 'Your message is too long. Please keep it under 500 characters.'}), 200

    reply = _chatbot_get_reply(user_msg)
    return jsonify({'reply': reply}), 200


def _chatbot_get_reply(msg):
    """Match keywords in the user message and return a helpful response."""
    m = msg.lower()

    # --- Home / Dashboard ---
    if any(w in m for w in ['home', 'dashboard', 'main page', 'landing']):
        return (
            "The Home page is your starting point! From here you can:\n"
            "1. Jump to Stories, Community, Activities, Messages, or Profile.\n"
            "2. See the newest stories and upcoming events at a glance.\n"
            "Just click any card to explore that section."
        )

    # --- Messages / Chat ---
    if any(w in m for w in ['message', 'chat', 'inbox', 'conversation', 'dm', 'direct']):
        if any(w in m for w in ['archive', 'archived']):
            return (
                "To view archived chats:\n"
                "1. Go to Messages.\n"
                "2. Look for the 'Archived' section at the top.\n"
                "3. Click it to see all chats you have archived.\n"
                "You can unarchive a chat by long-pressing or using the menu."
            )
        if any(w in m for w in ['unread', 'new message', 'notification']):
            return (
                "Unread messages show a coloured badge next to the chat.\n"
                "To mark all as read, open Messages and look for the '...' menu, "
                "then select 'Read all'. You can also open each chat to mark it read."
            )
        if any(w in m for w in ['start', 'new', 'begin', 'create', 'how to']):
            return (
                "To start a new chat:\n"
                "1. Go to the Messages page.\n"
                "2. Click the '+' button at the top.\n"
                "3. Choose 'New contact' to send a direct message, "
                "or 'New group' to create a group chat.\n"
                "4. Select a user and start typing!"
            )
        if any(w in m for w in ['group', 'group chat']):
            return (
                "Group chats let you talk with multiple people at once.\n"
                "To create one: Messages → '+' → 'New group' → add members → set a name → create!\n"
                "You can share text, images, voice messages, and even your live location."
            )
        if any(w in m for w in ['delete', 'remove']):
            return (
                "To delete a message:\n"
                "1. Long-press (or right-click) the message.\n"
                "2. Select 'Delete' from the menu.\n"
                "Note: Deleting removes the message for everyone in the chat."
            )
        if any(w in m for w in ['edit', 'change', 'modify']):
            return (
                "To edit a message you sent:\n"
                "1. Long-press (or right-click) your message.\n"
                "2. Select 'Edit' from the context menu.\n"
                "3. Make your changes and press Enter to save.\n"
                "The other person will see the updated version."
            )
        # General messages help
        return (
            "The Messages page is where all your chats live.\n"
            "You can:\n"
            "• Send text, images, voice messages, and locations.\n"
            "• Pin, mute, archive, or delete chats.\n"
            "• Start a new chat with the '+' button.\n"
            "What specifically would you like help with?"
        )

    # --- FAQ / Help ---
    if any(w in m for w in ['faq', 'help', 'question', 'support']):
        return (
            "You can find answers to common questions on the FAQ & Help page.\n"
            "Topics include: Accounts & Access, Messages & Chat, Editing & Deleting, "
            "Stories, Groups, and Activities.\n"
            "Just click any question to expand the answer!"
        )

    # --- Stories ---
    if 'stor' in m:
        return (
            "Stories are public posts shared with the community.\n"
            "To read: go to Stories and click any title.\n"
            "To write: click 'Create Story', add a title and content, then publish.\n"
            "You can also like, comment on, and bookmark stories."
        )

    # --- Groups / Community ---
    if any(w in m for w in ['group', 'community', 'communities']):
        return (
            "Groups are communities of people with shared interests.\n"
            "To join one: go to Groups → browse → click 'Join'.\n"
            "To create one: Groups → 'Create Group' → fill in the details.\n"
            "Each group has its own chat where members can talk."
        )

    # --- Activities / Events ---
    if any(w in m for w in ['activit', 'event', 'workshop']):
        return (
            "Activities are events or workshops you can join.\n"
            "Go to Activities to see what's coming up.\n"
            "Click an activity for details, then hit 'Join' to sign up.\n"
            "You can also create your own activity!"
        )

    # --- Profile / Account ---
    if any(w in m for w in ['profile', 'account', 'settings', 'password', 'name']):
        return (
            "To manage your account: click your avatar in the top-right → Settings.\n"
            "From there you can update your name, bio, and profile picture.\n"
            "If you forgot your password, try the login page or ask an admin for help."
        )

    # --- Greetings ---
    if any(w in m for w in ['hello', 'hi', 'hey', 'good morning', 'good afternoon']):
        return "Hello! 👋 I'm the TogetherSG helper. How can I help you today?"

    if any(w in m for w in ['thanks', 'thank you', 'thx', 'cheers']):
        return "You're welcome! Let me know if there's anything else I can help with. 😊"

    if any(w in m for w in ['bye', 'goodbye', 'see you']):
        return "Goodbye! Have a great day! Feel free to chat anytime you need help. 👋"

    # --- Fallback ---
    return (
        "I'm not sure I understand. Could you try asking in a different way?\n"
        "I can help with:\n"
        "• Home / Dashboard\n"
        "• Messages & Chats\n"
        "• Stories, Groups, Activities\n"
        "• FAQ & Help\n"
        "• Profile & Account"
    )


if __name__ == '__main__':
    # Initialize DB schema if needed
    db = Database()
    db.init_db()
    
    # Use socketio.run instead of app.run
    socketio.run(app, debug=True, port=8000)

