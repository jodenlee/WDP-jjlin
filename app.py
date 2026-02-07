from flask import Flask, render_template, g, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from database import Database
import re
import os

app = Flask(__name__)
app.secret_key = 'togethersg-secret-key-change-in-production'  # Change this in production!

# Upload Configuration
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif'}
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


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        # In this simple implementation, Database class opens connection on every query
        # so we might not need to strictly close the object itself if it doesn't hold a persistent connection
        # But for good practice if we changed implementation:
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
    
    # Get all users for starting new conversations
    users = db.query("SELECT * FROM users WHERE id != ?", (user_id,))
    
    # Get conversations (users we've messaged with)
    conversations = db.query("""
        SELECT DISTINCT 
            CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as user_id,
            u.username,
            (SELECT content FROM messages m2 
             WHERE (m2.sender_id = u.id AND m2.receiver_id = ?) 
                OR (m2.sender_id = ? AND m2.receiver_id = u.id)
             ORDER BY m2.created_at DESC LIMIT 1) as last_message,
            (SELECT created_at FROM messages m3 
             WHERE (m3.sender_id = u.id AND m3.receiver_id = ?) 
                OR (m3.sender_id = ? AND m3.receiver_id = u.id)
             ORDER BY m3.created_at DESC LIMIT 1) as last_message_time,
            (SELECT COUNT(*) FROM messages m4 
             WHERE m4.sender_id = u.id AND m4.receiver_id = ? AND m4.is_read = 0) as unread_count
        FROM messages m
        JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
        WHERE m.sender_id = ? OR m.receiver_id = ?
        ORDER BY last_message_time DESC
    """, (user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id))
    
    return render_template('messages/index.html', conversations=conversations, users=users)

@app.route('/messages/<int:user_id>')
@login_required
def chat(user_id):
    db = get_db()
    current_user_id = session['user_id']
    
    other_user = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not other_user:
        return "User not found", 404
    
    # Get messages between users
    messages_data = db.query("""
        SELECT * FROM messages 
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY created_at ASC
    """, (current_user_id, user_id, user_id, current_user_id))
    
    # Mark messages as read
    conn = db.get_connection()
    conn.execute("UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ?", (user_id, current_user_id))
    conn.commit()
    
    return render_template('messages/chat.html', messages=messages_data, other_user=other_user, current_user_id=current_user_id)

@app.route('/messages/send/<int:recipient_id>', methods=['POST'])
@login_required
def send_message(recipient_id):
    content = request.form['content']
    sender_id = session['user_id']
    
    db = get_db()
    conn = db.get_connection()
    conn.execute(
        "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
        (sender_id, recipient_id, content)
    )
    conn.commit()
    flash('Message sent!', 'success')
    return redirect(url_for('chat', user_id=recipient_id))

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

# --- Community Routes ---

# Route to display the list of all community groups
@app.route('/community')
def community():
    db = get_db()
    # Query to fetch all groups along with their member count
    search_query = request.args.get('search', '').strip()
    
    query = """
        SELECT g.*, 
               (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
        FROM groups g
    """
    params = []
    
    if search_query:
        query += " WHERE g.name LIKE ? OR g.description LIKE ?"
        params.extend([f'%{search_query}%', f'%{search_query}%'])
        
    query += " ORDER BY g.created_at DESC"
    
    groups = db.query(query, params)
    return render_template('community/index.html', groups=groups)

# Route to view a specific group's details
@app.route('/community/<int:group_id>')
def view_group(group_id):
    db = get_db()
    # Fetch group details by ID
    group = db.query("SELECT * FROM groups WHERE id = ?", (group_id,), one=True)
    if not group:
        return "Group not found", 404
    
    is_member = False
    # Calculate total members in the group
    member_count = len(db.query("SELECT * FROM group_members WHERE group_id = ?", (group_id,)))
    
    # Check if the current user is a member of the group
    if 'user_id' in session:
        user_id = session['user_id']
        membership = db.query("SELECT * FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user_id), one=True)
        is_member = bool(membership)
    
    # Fetch all members of the group to display in the view
    members = db.query("""
        SELECT u.* FROM users u
        JOIN group_members gm ON u.id = gm.user_id
        WHERE gm.group_id = ?
    """, (group_id,))
    
    # Check if the current user is the owner (creator) of the group
    is_owner = False
    if 'user_id' in session:
        is_owner = (group['created_by'] == session['user_id'])
    
    # Fetch posts
    posts_query = """
        SELECT p.*, u.username, u.profile_pic, u.role
        FROM group_posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.group_id = ?
        ORDER BY p.created_at DESC
    """
    posts = db.query(posts_query, (group_id,))
    
    # Organize posts with their comments and like status
    posts_data = []
    user_id = session.get('user_id')
    
    for post in posts:
        comments_query = """
            SELECT c.*, u.username, u.profile_pic
            FROM group_post_comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.post_id = ?
            ORDER BY c.created_at ASC
        """
        comments = db.query(comments_query, (post['id'],))
        
        # Check if current user liked the post
        is_liked = False
        if user_id:
            like_check = db.query("SELECT * FROM group_post_likes WHERE user_id = ? AND post_id = ?", (user_id, post['id']), one=True)
            is_liked = bool(like_check)
            
        post_dict = dict(post)
        post_dict['comments'] = comments
        post_dict['is_liked'] = is_liked
        posts_data.append(post_dict)
    
    return render_template('community/view.html', group=group, is_member=is_member, is_owner=is_owner, member_count=member_count, members=members, posts=posts_data)

@app.route('/community/post/<int:post_id>/like', methods=['POST'])
@login_required
def toggle_group_post_like(post_id):
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    
    # Check if post exists
    post = db.query("SELECT * FROM group_posts WHERE id = ?", (post_id,), one=True)
    if not post:
        return redirect(request.referrer or url_for('community'))
        
    # Check if already liked
    like = db.query("SELECT * FROM group_post_likes WHERE user_id = ? AND post_id = ?", (user_id, post_id), one=True)
    
    if like:
        # Unlike
        conn.execute("DELETE FROM group_post_likes WHERE user_id = ? AND post_id = ?", (user_id, post_id))
        conn.execute("UPDATE group_posts SET likes = likes - 1 WHERE id = ?", (post_id,))
    else:
        # Like
        conn.execute("INSERT INTO group_post_likes (user_id, post_id) VALUES (?, ?)", (user_id, post_id))
        conn.execute("UPDATE group_posts SET likes = likes + 1 WHERE id = ?", (post_id,))
        
    conn.commit()
    return redirect(url_for('view_group', group_id=post['group_id']))

# Route to create a new community group
@app.route('/community/new', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        user_id = session['user_id']
        
        # Handle group image upload
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash('Files with images only', 'danger')
                    return render_template('community/create.html')
                filename = secure_filename(file.filename)
                import time
                filename = f"group_{int(time.time())}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image_url = f"uploads/{filename}"

        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()
        # Insert the new group into the database
        cursor.execute(
            "INSERT INTO groups (name, description, image_url, created_by) VALUES (?, ?, ?, ?)",
            (name, description, image_url, user_id)
        )
        group_id = cursor.lastrowid
        # Automatically add the creator as a member of the group
        cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, user_id))
        conn.commit()
        flash('Group created!', 'success')
        return redirect(url_for('community'))
    
    return render_template('community/create.html')

# Route for a user to join a group
@app.route('/community/<int:group_id>/join', methods=['POST'])
@login_required
def join_group(group_id):
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    try:
        # Add the user to the group_members table
        conn.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, user_id))
        conn.commit()
    except:
        pass  # User is already a member, ignore duplicate insertion
    return redirect(url_for('view_group', group_id=group_id))

# Route for a user to leave a group
@app.route('/community/<int:group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    user_id = session['user_id']
    db = get_db()
    conn = db.get_connection()
    # Remove the user from the group_members table
    conn.execute("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user_id))
    
    # Check if the group has any remaining members
    cursor = conn.execute("SELECT COUNT(*) FROM group_members WHERE group_id = ?", (group_id,))
    count = cursor.fetchone()[0]
    
    # If the group is empty, delete the group entirely
    if count == 0:
        conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        conn.commit()
        flash('Group deleted as it has no members.', 'info')
        return redirect(url_for('community'))
        
    conn.commit()
    return redirect(url_for('view_group', group_id=group_id))

# Route for the group owner to delete the group
@app.route('/community/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_group(group_id):
    user_id = session['user_id']
    db = get_db()
    
    group = db.query("SELECT * FROM groups WHERE id = ?", (group_id,), one=True)
    if not group:
         return "Group not found", 404

    # Ensure only the creator can delete the group
    if group['created_by'] != user_id:
        flash('Only the group creator can delete the group.', 'danger')
        return redirect(url_for('view_group', group_id=group_id))

    conn = db.get_connection()
    # Delete all members associated with the group
    conn.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
    # Delete the group itself
    conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    conn.commit()
    
    flash('Group deleted successfully.', 'success')
    return redirect(url_for('community'))

# Route for the group owner to update the group details
@app.route('/community/<int:group_id>/update', methods=['POST'])
@login_required
def update_group(group_id):
    user_id = session['user_id']
    db = get_db()
    
    group = db.query("SELECT * FROM groups WHERE id = ?", (group_id,), one=True)
    if not group:
         return "Group not found", 404

    # Ensure only the creator can update the group
    if group['created_by'] != user_id:
        flash('Only the group creator can update the group.', 'danger')
        return redirect(url_for('view_group', group_id=group_id))

    name = request.form.get('name', '').strip()
    if not name:
        flash('Group name is required.', 'danger')
        return redirect(url_for('view_group', group_id=group_id))

    description = request.form.get('description', '')
    
    conn = db.get_connection()
    
    # Handle group image upload
    # Check if an image file was included in the form submission
    if 'image' in request.files:
        file = request.files['image']
        # Check if a file was selected
        if file and file.filename:
            # Validate that the file has an allowed extension (png, jpg, jpeg, gif, webp, avif)
            if not allowed_file(file.filename):
                flash('Files with images only', 'danger')
                return redirect(url_for('view_group', group_id=group_id))
            
            # Delete old image if it exists to prevent orphaned files
            # This ensures the old profile picture is removed when replaced with a new one
            if group['image_url']:
                old_image_path = os.path.join('static', group['image_url'])
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)
            
            # Sanitize the filename to prevent directory traversal attacks
            filename = secure_filename(file.filename)
            # Add timestamp prefix to ensure unique filenames and prevent overwrites
            import time
            filename = f"group_{int(time.time())}_{filename}"
            # Save the new image to the uploads folder
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            # Store relative path in database for use in templates
            image_url = f"uploads/{filename}"
            # Update group with new name, description, and image
            conn.execute("UPDATE groups SET name = ?, description = ?, image_url = ? WHERE id = ?", (name, description, image_url, group_id))
        else:
            # No valid image file uploaded - update only name and description, keep existing image
            conn.execute("UPDATE groups SET name = ?, description = ? WHERE id = ?", (name, description, group_id))
    else:
        # No image field in form - update only name and description
         conn.execute("UPDATE groups SET name = ?, description = ? WHERE id = ?", (name, description, group_id))

    conn.commit()
    
    flash('Group updated successfully.', 'success')
    return redirect(url_for('view_group', group_id=group_id))

# Route to create a new post in a group
@app.route('/community/<int:group_id>/post', methods=['POST'])
@login_required
def create_group_post(group_id):
    """
    Creates a new post within a specific community group.
    
    Args:
        group_id (int): The ID of the group where the post will be created.
        
    Form Data:
        content (str): The text content of the post.
    """
    user_id = session['user_id']
    content = request.form['content']
    
    # Image upload removed as per user request
    image_url = None

    db = get_db()
    conn = db.get_connection()
    conn.execute(
        "INSERT INTO group_posts (group_id, user_id, content, image_url) VALUES (?, ?, ?, ?)",
        (group_id, user_id, content, image_url)
    )
    conn.commit()
    flash('Post created!', 'success')
    return redirect(url_for('view_group', group_id=group_id))

@app.route('/community/post/<int:post_id>/update', methods=['POST'])
@login_required
def update_group_post(post_id):
    user_id = session['user_id']
    new_content = request.form['content']
    
    db = get_db()
    post = db.query("SELECT * FROM group_posts WHERE id = ?", (post_id,), one=True)
    
    if not post:
        return redirect(request.referrer or url_for('community'))
        
    if post['user_id'] != user_id:
        flash('You can only edit your own posts.', 'danger')
        return redirect(url_for('view_group', group_id=post['group_id']))
        
    conn = db.get_connection()
    conn.execute("UPDATE group_posts SET content = ? WHERE id = ?", (new_content, post_id))
    conn.commit()
    
    flash('Post updated.', 'success')
    return redirect(url_for('view_group', group_id=post['group_id']))

@app.route('/community/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_group_post(post_id):
    user_id = session['user_id']
    
    db = get_db()
    post = db.query("SELECT * FROM group_posts WHERE id = ?", (post_id,), one=True)
    
    if not post:
        return redirect(request.referrer or url_for('community'))
        
    # Check if user is the owner of the post
    # (Optional: Allow group owner to delete any post? For now, just post owner as per prompt 'user that created the post')
    if post['user_id'] != user_id:
        flash('You can only delete your own posts.', 'danger')
        return redirect(url_for('view_group', group_id=post['group_id']))
        
    conn = db.get_connection()
    # Delete associated comments first
    conn.execute("DELETE FROM group_post_comments WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM group_posts WHERE id = ?", (post_id,))
    conn.commit()
    
    flash('Post deleted.', 'success')
    return redirect(url_for('view_group', group_id=post['group_id']))

# Route to add a comment to a group post
@app.route('/community/post/<int:post_id>/comment', methods=['POST'])
@login_required
def create_group_post_comment(post_id):
    """
    Adds a comment to an existing group post.
    
    Args:
        post_id (int): The ID of the post to comment on.
        
    Form Data:
        content (str): The text content of the comment.
    """
    user_id = session['user_id']
    content = request.form['content']
    
    db = get_db()
    conn = db.get_connection()
    # verify post exists first
    post = db.query("SELECT group_id FROM group_posts WHERE id = ?", (post_id,), one=True)
    if post:
        conn.execute(
            "INSERT INTO group_post_comments (post_id, user_id, content) VALUES (?, ?, ?)",
            (post_id, user_id, content)
        )
        conn.commit()
    
    if post:
        return redirect(url_for('view_group', group_id=post['group_id']))
    else:
        return redirect(url_for('community'))

@app.route('/community/post/comment/<int:comment_id>/update', methods=['POST'])
@login_required
def update_group_post_comment(comment_id):
    user_id = session['user_id']
    new_content = request.form['content']
    
    db = get_db()
    # verify comment ownership and get post_id for redirect
    comment = db.query("SELECT * FROM group_post_comments WHERE id = ?", (comment_id,), one=True)
    
    if not comment:
        return indent(redirect(request.referrer or url_for('community')))
        
    post = db.query("SELECT group_id FROM group_posts WHERE id = ?", (comment['post_id'],), one=True)
    
    if comment['user_id'] != user_id:
        flash('You can only edit your own comments.', 'danger')
        return redirect(url_for('view_group', group_id=post['group_id']))
        
    conn = db.get_connection()
    conn.execute("UPDATE group_post_comments SET content = ? WHERE id = ?", (new_content, comment_id))
    conn.commit()
    
    flash('Comment updated.', 'success')
    return redirect(url_for('view_group', group_id=post['group_id']))

@app.route('/community/post/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_group_post_comment(comment_id):
    user_id = session['user_id']
    
    db = get_db()
    comment = db.query("SELECT * FROM group_post_comments WHERE id = ?", (comment_id,), one=True)
    
    if not comment:
        return redirect(request.referrer or url_for('community'))
        
    post = db.query("SELECT group_id FROM group_posts WHERE id = ?", (comment['post_id'],), one=True)

    if comment['user_id'] != user_id:
        flash('You can only delete your own comments.', 'danger')
        return redirect(url_for('view_group', group_id=post['group_id']))
        
    conn = db.get_connection()
    conn.execute("DELETE FROM group_post_comments WHERE id = ?", (comment_id,))
    conn.commit()
    
    flash('Comment deleted.', 'success')
    return redirect(url_for('view_group', group_id=post['group_id']))

if __name__ == '__main__':
    app.run(debug=True)

