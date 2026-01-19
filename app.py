from flask import Flask, render_template, g, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from database import Database
import re

app = Flask(__name__)
app.secret_key = 'togethersg-secret-key-change-in-production'  # Change this in production!

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
                flash('Welcome back, ' + (user['full_name'] or user['username']) + '!', 'success')
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
    # Homepage with simple navigation grid
    db = get_db()
    
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
    
    user_id = 1  # Hardcoded
    rsvp = db.query("SELECT * FROM activity_rsvps WHERE activity_id = ? AND user_id = ?", (activity_id, user_id), one=True)
    rsvp_count = len(db.query("SELECT * FROM activity_rsvps WHERE activity_id = ?", (activity_id,)))
    
    return render_template('activities/view.html', activity=activity, is_joined=bool(rsvp), rsvp_count=rsvp_count)

@app.route('/activities/new', methods=['GET', 'POST'])
def create_activity():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        activity_type = request.form['type']
        location = request.form.get('location', '')
        event_date = request.form.get('event_date', '')
        
        db = get_db()
        conn = db.get_connection()
        conn.execute(
            "INSERT INTO activities (title, description, type, location, event_date, organizer_id) VALUES (?, ?, ?, ?, ?, ?)",
            (title, description, activity_type, location, event_date, 1)
        )
        conn.commit()
        return redirect(url_for('activities'))
    
    return render_template('activities/create.html')

@app.route('/activities/<int:activity_id>/join', methods=['POST'])
def join_activity(activity_id):
    user_id = 1  # Hardcoded
    db = get_db()
    conn = db.get_connection()
    try:
        conn.execute("INSERT INTO activity_rsvps (activity_id, user_id) VALUES (?, ?)", (activity_id, user_id))
        conn.commit()
    except:
        pass  # Already joined
    return redirect(url_for('view_activity', activity_id=activity_id))

@app.route('/activities/<int:activity_id>/leave', methods=['POST'])
def leave_activity(activity_id):
    user_id = 1  # Hardcoded
    db = get_db()
    conn = db.get_connection()
    conn.execute("DELETE FROM activity_rsvps WHERE activity_id = ? AND user_id = ?", (activity_id, user_id))
    conn.commit()
    return redirect(url_for('view_activity', activity_id=activity_id))

@app.route('/messages')
def messages():
    db = get_db()
    user_id = 1  # Hardcoded
    
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
def chat(user_id):
    db = get_db()
    current_user_id = 1  # Hardcoded
    
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

@app.route('/messages/<int:user_id>/send', methods=['POST'])
def send_message(user_id):
    content = request.form['content']
    if not content.strip():
        return redirect(url_for('chat', user_id=user_id))
    
    current_user_id = 1  # Hardcoded
    db = get_db()
    conn = db.get_connection()
    conn.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)", 
                 (current_user_id, user_id, content))
    conn.commit()
    return redirect(url_for('chat', user_id=user_id))

@app.route('/profile')
def profile():
    db = get_db()
    user_id = 1  # Hardcoded
    
    # Get user from database or use defaults
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
        user = {
            'id': 1,
            'full_name': 'Joden Lee',
            'username': 'joden',
            'user_type': 'Senior',
            'bio': '',
            'profile_pic': 'https://ui-avatars.com/api/?name=Joden+Lee&background=8D6E63&color=fff'
        }
    
    return render_template('profile.html', user=user)

@app.route('/profile/update', methods=['POST'])
def update_profile():
    user_id = 1  # Hardcoded
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
    
    user_id = 1  # Hardcoded
    membership = db.query("SELECT * FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user_id), one=True)
    member_count = len(db.query("SELECT * FROM group_members WHERE group_id = ?", (group_id,)))
    
    # Get members
    members = db.query("""
        SELECT u.* FROM users u
        JOIN group_members gm ON u.id = gm.user_id
        WHERE gm.group_id = ?
    """, (group_id,))
    
    return render_template('community/view.html', group=group, is_member=bool(membership), member_count=member_count, members=members)

@app.route('/community/new', methods=['GET', 'POST'])
def create_group():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        image_url = request.form.get('image_url', '')
        
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO groups (name, description, image_url, created_by) VALUES (?, ?, ?, ?)",
            (name, description, image_url, 1)
        )
        group_id = cursor.lastrowid
        # Auto-join creator
        cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, 1))
        conn.commit()
        return redirect(url_for('community'))
    
    return render_template('community/create.html')

@app.route('/community/<int:group_id>/join', methods=['POST'])
def join_group(group_id):
    user_id = 1  # Hardcoded
    db = get_db()
    conn = db.get_connection()
    try:
        conn.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, user_id))
        conn.commit()
    except:
        pass  # Already a member
    return redirect(url_for('view_group', group_id=group_id))

@app.route('/community/<int:group_id>/leave', methods=['POST'])
def leave_group(group_id):
    user_id = 1  # Hardcoded
    db = get_db()
    conn = db.get_connection()
    conn.execute("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, user_id))
    conn.commit()
    return redirect(url_for('view_group', group_id=group_id))

if __name__ == '__main__':
    app.run(debug=True)

