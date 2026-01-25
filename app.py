from flask import Flask, render_template, g, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from database import Database
import re
import os

try:
    from flask_babel import Babel, _
except ImportError:
    # Fallback if flask-babel not installed
    Babel = None
    def _(text): return text

app = Flask(__name__)
app.secret_key = 'togethersg-secret-key-change-in-production'  # Change this in production!

# Babel Configuration for Internationalization
SUPPORTED_LANGUAGES = ['en', 'zh', 'ms', 'ta', 'ko', 'ja']
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'

if Babel:
    babel = Babel(app)
    
    @babel.localeselector
    def get_locale():
        # 1. Check session for language preference
        if 'language' in session:
            return session['language']
        # 2. Check user preference from database
        if 'user_id' in session:
            try:
                from database import Database
                db = Database()
                user = db.query("SELECT language FROM users WHERE id = ?", (session['user_id'],), one=True)
                if user and user['language']:
                    return user['language']
            except:
                pass
        # 3. Fall back to browser preference
        return request.accept_languages.best_match(SUPPORTED_LANGUAGES)

# Upload Configuration
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
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
# Admin Check Decorator
@app.context_processor
def inject_notifications():
    if 'user_id' in session:
        db = get_db()
        try:
            notifications = db.query("SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC", (session['user_id'],))
            return {'notifications': notifications, 'unread_count': len(notifications)}
        except:
             return {'notifications': [], 'unread_count': 0}
    return {'notifications': [], 'unread_count': 0}

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        db = get_db()
        user = db.query("SELECT * FROM users WHERE id = ?", (session['user_id'],), one=True)
        
        if not user or not user['is_admin']:
            flash('Admin access required.', 'danger')
            return redirect(url_for('home'))
            
        return f(*args, **kwargs)
    return decorated_function
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
                # Set language preference from database
                try:
                    if user['language']:
                        session['language'] = user['language']
                except (KeyError, IndexError):
                    pass

                flash('Welcome back!', 'success')
                
                # Redirect to admin dashboard if user is admin
                if user['is_admin']:
                    return redirect(url_for('admin_dashboard'))
                    
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
        elif not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one capital letter.')
        elif not re.search(r'[0-9]', password):
            errors.append('Password must contain at least one number.')
        
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

    return render_template('auth/register.html', errors=errors, form=form)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        db = get_db()
        user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
        
        if user:
            # Email exists - redirect directly to reset password page
            token = f"reset_{user['id']}"
            return redirect(url_for('reset_password', token=token, email=email))
        else:
            # Email not found
            error = "Invalid email. No account found with this email address."
            
    return render_template('auth/forgot_password.html', error=error)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = request.args.get('email')
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('auth/reset_password.html', token=token, email=email)
        
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one capital letter.', 'danger')
            return render_template('auth/reset_password.html', token=token, email=email)
        
        if not re.search(r'[0-9]', password):
            flash('Password must contain at least one number.', 'danger')
            return render_template('auth/reset_password.html', token=token, email=email)
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/reset_password.html', token=token, email=email)
            
        # Update Password
        if email:
            db = get_db()
            conn = db.get_connection()
            new_hash = generate_password_hash(password)
            conn.execute("UPDATE users SET password_hash = ? WHERE email = ?", (new_hash, email))
            conn.commit()
            
            flash('Password has been reset successfully. Please login.', 'success')
            return redirect(url_for('login'))
        else:
             flash('Invalid link.', 'danger')
             return redirect(url_for('login'))
             
    return render_template('auth/reset_password.html', token=token, email=email)

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
        
        # Notify Author
        story_owner = db.query("SELECT author_id FROM stories WHERE id = ?", (story_id,), one=True)
        if story_owner:
            owner_id = story_owner['author_id']
            # Check preference
            owner_prefs = db.query("SELECT notify_stories FROM users WHERE id = ?", (owner_id,), one=True)
            if owner_id != user_id and owner_prefs and owner_prefs['notify_stories']:
                 conn.execute(
                    "INSERT INTO notifications (user_id, type, content, link) VALUES (?, ?, ?, ?)",
                    (owner_id, 'Story Like', f'{session.get("username", "Someone")} liked your story.', url_for('view_story', story_id=story_id))
                 )
        
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
    
    # Notify Author
    story_owner = db.query("SELECT author_id FROM stories WHERE id = ?", (story_id,), one=True)
    if story_owner:
        owner_id = story_owner['author_id']
        owner_prefs = db.query("SELECT notify_stories FROM users WHERE id = ?", (owner_id,), one=True)
        if owner_id != user_id and owner_prefs and owner_prefs['notify_stories']:
             conn.execute(
                "INSERT INTO notifications (user_id, type, content, link) VALUES (?, ?, ?, ?)",
                (owner_id, 'Comment', f'{session.get("username", "Someone")} commented on your story.', url_for('view_story', story_id=story_id))
             )

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
        
        # Notify Organizer? Or User? User requested "Reminders for activities you've joined" (implies self)
        # But immediate notification is also good.
        user_prefs = db.query("SELECT notify_activities FROM users WHERE id = ?", (user_id,), one=True)
        if user_prefs and user_prefs['notify_activities']:
             activity = db.query("SELECT title FROM activities WHERE id = ?", (activity_id,), one=True)
             conn.execute(
                "INSERT INTO notifications (user_id, type, content, link) VALUES (?, ?, ?, ?)",
                (user_id, 'Activity', f'You successfully joined "{activity["title"]}".', url_for('view_activity', activity_id=activity_id))
             )
        
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
    
    # Notify Receiver
    recipient_prefs = db.query("SELECT notify_messages FROM users WHERE id = ?", (recipient_id,), one=True)
    if recipient_prefs and recipient_prefs['notify_messages']:
         conn.execute(
            "INSERT INTO notifications (user_id, type, content, link) VALUES (?, ?, ?, ?)",
            (recipient_id, 'New Message', f'{session.get("username", "Someone")} sent you a message.', url_for('chat', user_id=sender_id))
         )

    conn.commit()
    # flash('Message sent!', 'success') # Optional: remove flash here too if desired, but user only mentioned profile.
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
        # Set session language based on user preference
        try:
            if user_data['language']:
                session['language'] = user_data['language']
        except (KeyError, IndexError):
            pass
        
        # Get language safely
        try:
            user_language = user_data['language'] or 'en'
        except (KeyError, IndexError):
            user_language = 'en'
        
        user = {
            'id': user_data['id'],
            'full_name': user_data['full_name'] or user_data['username'],
            'username': user_data['username'],
            'user_type': user_data['role'].capitalize(),
            'bio': user_data['bio'],
            'profile_pic': user_data['profile_pic'] or f"https://ui-avatars.com/api/?name={user_data['username']}&background=8D6E63&color=fff",
            'language': user_language,
            'notify_messages': user_data['notify_messages'],
            'notify_activities': user_data['notify_activities'],
            'notify_stories': user_data['notify_stories'],
            'notify_groups': user_data['notify_groups']
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
    
    # Handle Profile Pic Upload
    profile_pic = request.files.get('profile_pic')
    profile_pic_path = None
    
    if profile_pic and allowed_file(profile_pic.filename):
        filename = secure_filename(profile_pic.filename)
        import time
        filename = f"profile_{user_id}_{int(time.time())}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics')
        os.makedirs(filepath, exist_ok=True) # Ensure dir exists
        full_path = os.path.join(filepath, filename)
        profile_pic.save(full_path)
        profile_pic_path = f"uploads/profile_pics/{filename}"
    
    # Notification Settings
    notify_messages = 1 if 'notify_messages' in request.form else 0
    notify_activities = 1 if 'notify_activities' in request.form else 0
    notify_stories = 1 if 'notify_stories' in request.form else 0
    notify_groups = 1 if 'notify_groups' in request.form else 0

    db = get_db()
    conn = db.get_connection()
    
    # Construct update query dynamically to handle profile pic only if changed
    query = "UPDATE users SET full_name = ?, bio = ?, notify_messages = ?, notify_activities = ?, notify_stories = ?, notify_groups = ?"
    params = [full_name, bio, notify_messages, notify_activities, notify_stories, notify_groups]
    
    if profile_pic_path:
        query += ", profile_pic = ?"
        params.append(request.url_root + 'static/' + profile_pic_path)
    # else keep existing
        
    query += " WHERE id = ?"
    params.append(user_id)
    
    conn.execute(query, params)
    conn.commit()
    
    # flash('Profile updated successfully!', 'success')  <-- REMOVED as requested
    return redirect(url_for('profile'))

@app.route('/profile/update_notifications', methods=['POST'])
@login_required
def update_notifications():
    user_id = session['user_id']
    
    # Notification Settings
    notify_messages = 1 if 'notify_messages' in request.form else 0
    notify_activities = 1 if 'notify_activities' in request.form else 0
    notify_stories = 1 if 'notify_stories' in request.form else 0
    notify_groups = 1 if 'notify_groups' in request.form else 0

    db = get_db()
    conn = db.get_connection()
    
    conn.execute("""
        UPDATE users 
        SET notify_messages = ?, notify_activities = ?, notify_stories = ?, notify_groups = ?
        WHERE id = ?
    """, (notify_messages, notify_activities, notify_stories, notify_groups, user_id))
    conn.commit()
    
    return redirect(url_for('profile'))

@app.route('/profile/language', methods=['POST'])
@login_required
def update_language():
    """Update user's language preference and refresh the page"""
    language = request.form.get('language', 'en')
    
    # Validate language
    if language not in SUPPORTED_LANGUAGES:
        language = 'en'
    
    # Update session immediately
    session['language'] = language
    
    # Update database
    db = get_db()
    conn = db.get_connection()
    conn.execute("UPDATE users SET language = ? WHERE id = ?", (language, session['user_id']))
    conn.commit()
    
    # Redirect back to profile page (will refresh with new language)
    return redirect(url_for('profile'))

@app.route('/notifications/mark_read/<int:notif_id>', methods=['POST'])
@login_required
def mark_notification_read(notif_id):
    db = get_db()
    conn = db.get_connection()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?", (notif_id, session['user_id']))
    conn.commit()
    return "OK", 200

@app.route('/notifications/clear_all', methods=['POST'])
@login_required
def clear_all_notifications():
    db = get_db()
    conn = db.get_connection()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (session['user_id'],))
    conn.commit()
    return redirect(request.referrer)

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
        
        # Notify Group Creator
        group = db.query("SELECT created_by, name FROM groups WHERE id = ?", (group_id,), one=True)
        if group:
            creator_id = group['created_by']
            # Check preference
            creator_prefs = db.query("SELECT notify_groups FROM users WHERE id = ?", (creator_id,), one=True)
            if creator_id != user_id and creator_prefs and creator_prefs['notify_groups']:
                 conn.execute(
                    "INSERT INTO notifications (user_id, type, content, link) VALUES (?, ?, ?, ?)",
                    (creator_id, 'Group Join', f'{session.get("username", "Someone")} joined your group "{group["name"]}".', url_for('view_group', group_id=group_id))
                 )
        
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


# --- Admin Dashboard & Reporting ---

@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    role_filter = request.args.get('role')
    
    query = "SELECT * FROM users"
    args = []
    
    if role_filter:
        query += " WHERE role = ?"
        args.append(role_filter)
        
    all_users = db.query(query, args)
    
    # Separate admins and regular users for display
    # Note: If filtering by role (youth/senior), admins might be hidden if they have 'senior' role but we want to show them if they match?
    # Actually, let's just show what's requested. 
    # But fundamentally, the user wants "Admins" vs "Normal".
    
    admins = []
    normal_users = []
    
    for u in all_users:
        if u['is_admin']:
            admins.append(u)
        else:
            normal_users.append(u)
            
    return render_template('admin/users.html', admins=admins, users=normal_users, current_filter=role_filter)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    
    # Stats
    total_users = db.query("SELECT COUNT(*) as count FROM users")[0]['count']
    youth_count = db.query("SELECT COUNT(*) as count FROM users WHERE role = 'youth'")[0]['count']
    senior_count = db.query("SELECT COUNT(*) as count FROM users WHERE role = 'senior'")[0]['count']
    
    stats = {
        'total_users': total_users,
        'youth_count': youth_count,
        'senior_count': senior_count
    }
    
    # Reports
    reports = db.query("""
        SELECT r.*, u.username as reporter_name 
        FROM reports r 
        LEFT JOIN users u ON r.reporter_id = u.id 
        ORDER BY r.created_at DESC
    """)
    
    return render_template('admin/dashboard.html', stats=stats, reports=reports)

@app.route('/report/<target_type>/<int:target_id>', methods=['GET', 'POST'])
@login_required
def report_item(target_type, target_id):
    if target_type not in ['story', 'group', 'activity', 'comment']:
        abort(400)
        
    if request.method == 'POST':
        reason = request.form['reason']
        reporter_id = session['user_id']
        
        db = get_db()
        conn = db.get_connection()
        conn.execute(
            "INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES (?, ?, ?, ?)",
            (reporter_id, target_type, target_id, reason)
        )
        conn.commit()
        
        flash('Thank you for your report. Administrators will review it shortly.', 'success')
        return redirect(url_for('home')) # Redirect home or back
        
    return render_template('report.html', target_type=target_type, target_id=target_id)

@app.route('/admin/view_reported/<target_type>/<int:target_id>')
@admin_required
def view_reported_item(target_type, target_id):
    if target_type == 'story':
        return redirect(url_for('view_story', story_id=target_id))
    elif target_type == 'activity':
        return redirect(url_for('view_activity', activity_id=target_id))
    elif target_type == 'group':
        return redirect(url_for('view_group', group_id=target_id))
    elif target_type == 'comment':
        # Comments don't have a standalone view, so we redirect to the story they belong to
        # We need to find the story_id for the comment
        db = get_db()
        comment = db.query("SELECT story_id FROM comments WHERE id = ?", (target_id,), one=True)
        if comment:
            return redirect(url_for('view_story', story_id=comment['story_id']))
        else:
            flash('Comment not found (maybe already deleted).', 'warning')
            return redirect(url_for('admin_dashboard'))
    else:
        flash('Unknown content type.', 'warning')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/report/<int:report_id>/delete_content', methods=['POST'])
@admin_required
def delete_reported_item(report_id):
    db = get_db()
    report = db.query("SELECT * FROM reports WHERE id = ?", (report_id,), one=True)
    
    if not report:
        flash('Report not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
        
    target_type = report['target_type']
    target_id = report['target_id']
    conn = db.get_connection()
    
    try:
        if target_type == 'story':
             # Use existing logic or manual delete
             conn.execute("DELETE FROM bookmarks WHERE story_id = ?", (target_id,))
             conn.execute("DELETE FROM story_likes WHERE story_id = ?", (target_id,))
             conn.execute("DELETE FROM comments WHERE story_id = ?", (target_id,))
             conn.execute("DELETE FROM story_images WHERE story_id = ?", (target_id,))
             conn.execute("DELETE FROM stories WHERE id = ?", (target_id,))
        elif target_type == 'activity':
             conn.execute("DELETE FROM activity_rsvps WHERE activity_id = ?", (target_id,))
             conn.execute("DELETE FROM activities WHERE id = ?", (target_id,))
        elif target_type == 'group':
             conn.execute("DELETE FROM group_members WHERE group_id = ?", (target_id,))
             conn.execute("DELETE FROM groups WHERE id = ?", (target_id,))
        elif target_type == 'comment':
             conn.execute("DELETE FROM comments WHERE id = ?", (target_id,))
        
        # Update report status
        conn.execute("UPDATE reports SET status = 'resolved_deleted' WHERE id = ?", (report_id,))
        conn.commit()
        flash('Content deleted successfully.', 'success')
    except Exception as e:
        print(e)
        flash('Error deleting content.', 'danger')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/users/<int:user_id>')
@admin_required
def admin_view_user(user_id):
    db = get_db()
    
    # Get user info
    user = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Get groups joined
    groups = db.query("""
        SELECT g.* FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.user_id = ?
    """, (user_id,))
    
    # Get activities joined
    activities = db.query("""
        SELECT a.* FROM activities a
        JOIN activity_rsvps ar ON a.id = ar.activity_id
        WHERE ar.user_id = ?
    """, (user_id,))
    
    # Get stories posted
    stories = db.query("SELECT * FROM stories WHERE author_id = ?", (user_id,))
    
    # Counts
    stats = {
        'groups_count': len(groups),
        'activities_count': len(activities),
        'stories_count': len(stories)
    }
    
    return render_template('admin/user_detail.html', user=user, groups=groups, activities=activities, stories=stories, stats=stats)

@app.route('/admin/report/<int:report_id>/dismiss', methods=['POST'])
@admin_required
def dismiss_report(report_id):
    db = get_db()
    conn = db.get_connection()
    conn.execute("UPDATE reports SET status = 'dismissed' WHERE id = ?", (report_id,))
    conn.commit()
    flash('Report dismissed.', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/setup_admin_emergency')
def setup_admin_emergency():
    db = get_db()
    conn = db.get_connection()
    email = 'admin@gmail.com'
    password = 'admin123'
    
    # Check if exists
    user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
    msg = ""
    
    try:
        if user:
            # Force update password and admin status
            hashed = generate_password_hash(password)
            conn.execute("UPDATE users SET password_hash = ?, is_admin = 1, role = 'senior' WHERE email = ?", (hashed, email))
            msg = f"UPDATED existing user {email}. Password reset to {password}. Admin access ENABLED."
        else:
            # Create new
            hashed = generate_password_hash(password)
            conn.execute('''
                INSERT INTO users (username, full_name, email, password_hash, role, is_admin, bio)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ('admin_user', 'System Administrator', email, hashed, 'senior', 1, 'Emergency Created Admin'))
            msg = f"CREATED new user {email}. Password is {password}. Admin access ENABLED."
            
        conn.commit()
    except Exception as e:
        return f"ERROR: {str(e)}"
        
    return f"SUCCESS: {msg} <br><a href='/login'>Go to Login</a>"

@app.route('/debug_users')
def debug_users():
    db = get_db()
    users = db.query("SELECT * FROM users")
    # Get columns
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in cursor.fetchall()]
    
    html = f"<h3>User Table Columns: {cols}</h3>"
    html += "<table border='1'><tr>"
    for c in cols:
        html += f"<th>{c}</th>"
    html += "</tr>"
    
    for u in users:
        html += "<tr>"
        for c in cols:
            html += f"<td>{u[c]}</td>"
        html += "</tr>"
    html += "</table>"
    html += "<br><a href='/fix_schema' class='btn btn-danger'>Force Fix Schema</a>"
    return html

@app.route('/fix_schema')
def fix_schema_route():
    db = get_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    required = ['notify_messages', 'notify_activities', 'notify_stories', 'notify_groups', 'profile_pic', 'full_name', 'bio']
    log = []
    
    cursor.execute("PRAGMA table_info(users)")
    existing = [r[1] for r in cursor.fetchall()]
    
    for col in required:
        if col not in existing:
            try:
                col_type = 'TEXT' if col in ['profile_pic', 'full_name', 'bio'] else 'INTEGER DEFAULT 1'
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type}")
                log.append(f"ADDED {col}")
            except Exception as e:
                log.append(f"ERROR adding {col}: {str(e)}")
        else:
            log.append(f"EXISTS {col}")
            
    conn.commit()
    return "<br>".join(log) + "<br><a href='/debug_users'>Back to Debug</a>"

if __name__ == '__main__':
    app.run(debug=True)

