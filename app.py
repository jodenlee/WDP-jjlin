# ============================================================================
# IMPORTS AND CONFIGURATION
# ============================================================================
from flask import Flask, render_template, g, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from database import Database
from datetime import datetime, timedelta
import re
import os

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = 'togethersg-secret-key-change-in-production'  # Change this in production!

# Initialize Flask-Mail for email verification
from email_utils import init_mail, generate_otp, get_otp_expiry, send_verification_email
init_mail(app)

# Google OAuth Configuration
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID', ''),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET', ''),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

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


# ============================================================================
# AUTHENTICATION FEATURE - Login, Register, Forgot Password, Logout
# ============================================================================
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
                # Check if email is verified
                try:
                    is_verified = user['is_verified']
                except (KeyError, IndexError):
                    is_verified = 1  # Default to verified for older accounts
                
                if not is_verified:
                    # User not verified, redirect to verification
                    session['pending_verification_email'] = email
                    flash('Please verify your email first.', 'warning')
                    return redirect(url_for('verify_email'))
                
                # Check if user is admin - skip OTP for admin
                if user['is_admin']:
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    flash('Welcome back, Admin!', 'success')
                    return redirect(url_for('admin_dashboard'))
                
                # Check for trusted device
                device_token = request.cookies.get('trusted_device')
                if device_token:
                    trusted = db.query(
                        """SELECT * FROM trusted_devices 
                           WHERE user_id = ? AND device_token = ? AND expires_at > ?""",
                        (user['id'], device_token, datetime.now()), one=True
                    )
                    if trusted:
                        # Device is trusted - skip OTP
                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        try:
                            if user['language']:
                                session['language'] = user['language']
                        except (KeyError, IndexError):
                            pass
                        flash('Welcome back!', 'success')
                        return redirect(url_for('home'))
                
                # Regular user - generate login OTP
                otp_code = generate_otp()
                expires_at = get_otp_expiry()
                
                conn = db.get_connection()
                conn.execute(
                    """INSERT INTO login_otps (user_id, email, code, expires_at) 
                       VALUES (?, ?, ?, ?)""",
                    (user['id'], email, otp_code, expires_at)
                )
                conn.commit()
                conn.close()
                
                # Send OTP email
                email_sent = send_verification_email(email, otp_code, purpose='login')
                
                # Store user id in session for OTP verification
                session['pending_login_user_id'] = user['id']
                session['pending_login_email'] = email
                
                if email_sent:
                    flash('Please check your email for the login verification code.', 'info')
                else:
                    flash('Could not send verification code. Please try again.', 'warning')
                
                return redirect(url_for('verify_login_otp'))
            else:
                error = 'Invalid email or password.'
    
    return render_template('auth/login.html', error=error, success=success)

# Google OAuth Routes
@app.route('/auth/google')
def google_login():
    """Initiate Google OAuth login flow"""
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            flash('Could not get user info from Google.', 'danger')
            return redirect(url_for('login'))
        
        email = user_info.get('email', '').lower()
        name = user_info.get('name', '')
        
        if not email:
            flash('Could not get email from Google account.', 'danger')
            return redirect(url_for('login'))
        
        # Check if user exists
        db = get_db()
        user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
        
        if not user:
            # New user - redirect to account setup page
            # Store Google info in session temporarily
            session['google_setup_email'] = email
            session['google_setup_name'] = name
            session['google_setup_suggested_username'] = email.split('@')[0].lower()
            
            return redirect(url_for('google_setup'))
        
        # Existing user - log them in directly (Google already verified their identity)
        session['user_id'] = user['id']
        session['username'] = user['username']
        
        flash(f'Welcome back, {user["username"]}!', 'success')
        return redirect(url_for('home'))
        
    except Exception as e:
        print(f"Google OAuth error: {e}")
        flash('Google login failed. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/auth/google/setup')
def google_setup():
    """Display account setup page for new Google users"""
    email = session.get('google_setup_email')
    if not email:
        flash('Please start the Google login process again.', 'warning')
        return redirect(url_for('login'))
    
    return render_template('auth/google_setup.html',
                          email=email,
                          name=session.get('google_setup_name', ''),
                          suggested_username=session.get('google_setup_suggested_username', ''))

@app.route('/auth/google/setup/complete', methods=['POST'])
def complete_google_setup():
    """Handle account setup form submission"""
    email = session.get('google_setup_email')
    if not email:
        flash('Session expired. Please start the Google login process again.', 'warning')
        return redirect(url_for('login'))
    
    full_name = request.form.get('full_name', '').strip()
    username = request.form.get('username', '').strip().lower()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    role = request.form.get('role', 'youth')
    
    error = None
    
    # Validate username
    if not username or not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        error = 'Username must be 3-20 characters with only letters, numbers, and underscores.'
    
    # Check if username is taken
    db = get_db()
    if not error:
        existing = db.query("SELECT id FROM users WHERE username = ?", (username,), one=True)
        if existing:
            error = 'That username is already taken. Please choose another.'
    
    # Validate password
    if not error and len(password) < 8:
        error = 'Password must be at least 8 characters.'
    
    if not error and password != confirm_password:
        error = 'Passwords do not match.'
    
    # Validate role
    if not error and role not in ['youth', 'senior']:
        error = 'Please select a valid role.'
    
    if error:
        return render_template('auth/google_setup.html',
                              email=email,
                              name=full_name,
                              suggested_username=username,
                              error=error)
    
    # Create the user account
    password_hash = generate_password_hash(password)
    
    conn = db.get_connection()
    conn.execute(
        """INSERT INTO users (username, email, password_hash, role, full_name, is_verified) 
           VALUES (?, ?, ?, ?, ?, 1)""",
        (username, email, password_hash, role, full_name)
    )
    conn.commit()
    conn.close()
    
    # Get the newly created user
    user = db.query("SELECT * FROM users WHERE email = ?", (email,), one=True)
    
    # Clear setup session vars
    session.pop('google_setup_email', None)
    session.pop('google_setup_name', None)
    session.pop('google_setup_suggested_username', None)
    
    # Log them in directly (skip OTP for first-time setup since they just came from Google)
    session['user_id'] = user['id']
    session['username'] = user['username']
    
    flash(f'Welcome to TogetherSG, {full_name or username}!', 'success')
    return redirect(url_for('home'))

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
        elif not re.match(r'^[a-zA-Z0-9._%+-]+@gmail\.com$', form['email']):
            errors.append('Please use a Gmail address (@gmail.com) to register.')
        
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
        
        # Create user if no errors (with is_verified=0)
        if not errors:
            password_hash = generate_password_hash(password)
            db = get_db()
            conn = db.get_connection()
            try:
                # Insert user as unverified
                conn.execute(
                    """INSERT INTO users (username, email, password_hash, role, full_name, is_verified) 
                       VALUES (?, ?, ?, ?, ?, 0)""",
                    (form['username'], form['email'], password_hash, form['role'], form['full_name'])
                )
                conn.commit()
                
                # Generate OTP and save to email_verifications table
                otp_code = generate_otp()
                expires_at = get_otp_expiry()
                conn.execute(
                    """INSERT INTO email_verifications (email, code, expires_at) 
                       VALUES (?, ?, ?)""",
                    (form['email'], otp_code, expires_at)
                )
                conn.commit()
                conn.close()
                
                # Send verification email
                email_sent = send_verification_email(form['email'], otp_code, purpose='registration')
                
                # Store email in session for verification page
                session['pending_verification_email'] = form['email']
                
                if email_sent:
                    flash('Please check your email for the verification code.', 'info')
                else:
                    flash('Account created but verification email failed. Please try resending.', 'warning')
                
                return redirect(url_for('verify_email'))
            except Exception as e:
                print(f"Registration error: {e}")
                errors.append('An error occurred. Please try again.')
    
    return render_template('auth/register.html', errors=errors, form=form)

# Email Verification Route (for registration)
@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    email = session.get('pending_verification_email')
    if not email:
        flash('No pending verification. Please register first.', 'warning')
        return redirect(url_for('register'))
    
    error = None
    
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        
        if not code:
            error = 'Please enter the verification code.'
        else:
            db = get_db()
            # Check for valid, unused, non-expired OTP
            verification = db.query(
                """SELECT * FROM email_verifications 
                   WHERE email = ? AND code = ? AND is_used = 0 AND expires_at > ?
                   ORDER BY created_at DESC LIMIT 1""",
                (email, code, datetime.now()), one=True
            )
            
            if verification:
                conn = db.get_connection()
                # Mark OTP as used
                conn.execute("UPDATE email_verifications SET is_used = 1 WHERE id = ?", (verification['id'],))
                # Mark user as verified
                conn.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
                conn.commit()
                conn.close()
                
                # Clear session
                session.pop('pending_verification_email', None)
                
                flash('Email verified successfully! You can now log in.', 'success')
                return redirect(url_for('login'))
            else:
                error = 'Invalid or expired verification code. Please try again or request a new code.'
    
    return render_template('auth/verify_email.html', email=email, error=error)

# Resend Email Verification Code
@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    email = session.get('pending_verification_email')
    if not email:
        flash('No pending verification.', 'warning')
        return redirect(url_for('register'))
    
    # Generate new OTP
    otp_code = generate_otp()
    expires_at = get_otp_expiry()
    
    db = get_db()
    conn = db.get_connection()
    conn.execute(
        """INSERT INTO email_verifications (email, code, expires_at) 
           VALUES (?, ?, ?)""",
        (email, otp_code, expires_at)
    )
    conn.commit()
    conn.close()
    
    # Send email
    email_sent = send_verification_email(email, otp_code, purpose='registration')
    
    if email_sent:
        flash('New verification code sent to your email.', 'success')
    else:
        flash('Could not send verification code. Please try again.', 'danger')
    
    return redirect(url_for('verify_email'))

# Login OTP Verification Route
@app.route('/verify-login-otp', methods=['GET', 'POST'])
def verify_login_otp():
    user_id = session.get('pending_login_user_id')
    email = session.get('pending_login_email')
    
    if not user_id or not email:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    
    error = None
    
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        
        if not code:
            error = 'Please enter the verification code.'
        else:
            db = get_db()
            # Check for valid, unused, non-expired OTP
            otp_record = db.query(
                """SELECT * FROM login_otps 
                   WHERE user_id = ? AND code = ? AND is_used = 0 AND expires_at > ?
                   ORDER BY created_at DESC LIMIT 1""",
                (user_id, code, datetime.now()), one=True
            )
            
            if otp_record:
                conn = db.get_connection()
                # Mark OTP as used
                conn.execute("UPDATE login_otps SET is_used = 1 WHERE id = ?", (otp_record['id'],))
                conn.commit()
                conn.close()
                
                # Get user and complete login
                user = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
                
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                # Set language preference
                try:
                    if user['language']:
                        session['language'] = user['language']
                except (KeyError, IndexError):
                    pass
                
                # Clear pending login session vars
                session.pop('pending_login_user_id', None)
                session.pop('pending_login_email', None)
                
                flash('Welcome back!', 'success')
                
                # Prepare response
                if user['is_admin']:
                    response = redirect(url_for('admin_dashboard'))
                else:
                    response = redirect(url_for('home'))
                
                # Handle trust device checkbox
                trust_device = request.form.get('trust_device')
                if trust_device:
                    import secrets
                    device_token = secrets.token_urlsafe(32)
                    expires_at = datetime.now() + timedelta(days=30)
                    
                    conn = db.get_connection()
                    conn.execute(
                        """INSERT INTO trusted_devices (user_id, device_token, expires_at) 
                           VALUES (?, ?, ?)""",
                        (user['id'], device_token, expires_at)
                    )
                    conn.commit()
                    conn.close()
                    
                    # Set cookie for 30 days
                    response.set_cookie('trusted_device', device_token, max_age=30*24*60*60, httponly=True)
                
                return response
            else:
                error = 'Invalid or expired code. Please try again or request a new code.'
    
    return render_template('auth/verify_login_otp.html', email=email, error=error)

# Resend Login OTP
@app.route('/resend-login-otp', methods=['POST'])
def resend_login_otp():
    user_id = session.get('pending_login_user_id')
    email = session.get('pending_login_email')
    
    if not user_id or not email:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    
    # Generate new OTP
    otp_code = generate_otp()
    expires_at = get_otp_expiry()
    
    db = get_db()
    conn = db.get_connection()
    conn.execute(
        """INSERT INTO login_otps (user_id, email, code, expires_at) 
           VALUES (?, ?, ?, ?)""",
        (user_id, email, otp_code, expires_at)
    )
    conn.commit()
    conn.close()
    
    # Send email
    email_sent = send_verification_email(email, otp_code, purpose='login')
    
    if email_sent:
        flash('New verification code sent to your email.', 'success')
    else:
        flash('Could not send verification code. Please try again.', 'danger')
    
    return redirect(url_for('verify_login_otp'))

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

# ============================================================================
# STORIES FEATURE - View, Create, Edit, Delete Stories, Comments, Likes, Bookmarks
# ============================================================================
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


# ============================================================================
# ACTIVITIES FEATURE - View, Create, Join, Leave Events & Workshops
# ============================================================================
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


# ============================================================================
# MESSAGING FEATURE - Direct Messages Between Users
# ============================================================================
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


# ============================================================================
# PROFILE FEATURE - User Profile, Settings, Notifications Preferences
# ============================================================================
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
    new_username = request.form.get('username', '').strip()
    
    # Validate username format
    if new_username and not re.match(r'^[a-zA-Z0-9_]{3,20}$', new_username):
        flash('Username must be 3-20 characters with only letters, numbers, and underscores.', 'danger')
        return redirect(url_for('profile'))
    
    # Check if username is already taken by someone else
    db = get_db()
    existing_user = db.query("SELECT id FROM users WHERE username = ? AND id != ?", (new_username, user_id), one=True)
    if existing_user:
        flash('That username is already taken. Please choose another.', 'danger')
        return redirect(url_for('profile'))
    
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

    conn = db.get_connection()
    
    # Construct update query dynamically to handle profile pic only if changed
    query = "UPDATE users SET full_name = ?, bio = ?, username = ?, notify_messages = ?, notify_activities = ?, notify_stories = ?, notify_groups = ?"
    params = [full_name, bio, new_username, notify_messages, notify_activities, notify_stories, notify_groups]
    
    if profile_pic_path:
        query += ", profile_pic = ?"
        params.append(request.url_root + 'static/' + profile_pic_path)
    # else keep existing
        
    query += " WHERE id = ?"
    params.append(user_id)
    
    conn.execute(query, params)
    conn.commit()
    
    # Update session username if changed
    if new_username:
        session['username'] = new_username
    
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

@app.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        user_id = session['user_id']
        db = get_db()
        user = db.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
        
        # Verify current password
        if not check_password_hash(user['password_hash'], current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('auth/change_password.html')
        
        # Validate new password
        if len(new_password) < 6:
            flash('New password must be at least 6 characters.', 'danger')
            return render_template('auth/change_password.html')
        
        if not re.search(r'[A-Z]', new_password):
            flash('New password must contain at least one capital letter.', 'danger')
            return render_template('auth/change_password.html')
        
        if not re.search(r'[0-9]', new_password):
            flash('New password must contain at least one number.', 'danger')
            return render_template('auth/change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('auth/change_password.html')
        
        # Update password
        conn = db.get_connection()
        new_hash = generate_password_hash(new_password)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        conn.commit()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('profile'))
        
    return render_template('auth/change_password.html')


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

@app.route('/api/notifications')
@login_required
def api_notifications():
    """API endpoint for real-time notification polling"""
    from flask import jsonify
    db = get_db()
    notifications = db.query(
        """SELECT id, type, content, link, created_at 
           FROM notifications 
           WHERE user_id = ? AND is_read = 0 
           ORDER BY created_at DESC 
           LIMIT 10""", 
        (session['user_id'],)
    )
    
    # Convert to list of dicts for JSON serialization
    notif_list = []
    for n in notifications:
        notif_list.append({
            'id': n['id'],
            'type': n['type'],
            'content': n['content'],
            'link': n['link'],
            'created_at': str(n['created_at'])[:16] if n['created_at'] else ''
        })
    
    return jsonify({
        'notifications': notif_list,
        'unread_count': len(notifications)
    })

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


# ============================================================================
# COMMUNITY FEATURE - Groups, Join/Leave Groups
# ============================================================================
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
        
        group = db.query("SELECT created_by, name FROM groups WHERE id = ?", (group_id,), one=True)
        if group:
            # Notify the user who joined (if they have notifications on)
            user_prefs = db.query("SELECT notify_groups FROM users WHERE id = ?", (user_id,), one=True)
            if user_prefs and user_prefs['notify_groups']:
                conn.execute(
                    "INSERT INTO notifications (user_id, type, content, link) VALUES (?, ?, ?, ?)",
                    (user_id, 'Group Joined', f'You successfully joined "{group["name"]}".', url_for('view_group', group_id=group_id))
                )
            
            # Notify Group Creator (if different from joiner)
            creator_id = group['created_by']
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


# ============================================================================
# ADMIN FEATURE - Dashboard, User Management, Reports
# ============================================================================

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

@app.route('/admin/reports')
@admin_required
def admin_reports():
    db = get_db()
    filter_type = request.args.get('type')  # story, activity, group, comment
    
    # Base query
    base_query = """
        SELECT r.*, u.username as reporter_name 
        FROM reports r 
        LEFT JOIN users u ON r.reporter_id = u.id
    """
    
    # Build where clause for type filter
    where_clause = ""
    params = ()
    if filter_type and filter_type in ['story', 'activity', 'group', 'comment']:
        where_clause = " WHERE r.target_type = ?"
        params = (filter_type,)
    
    # Get reports by status
    pending_query = base_query + where_clause + (" AND" if where_clause else " WHERE") + " r.status = 'pending' ORDER BY r.created_at DESC"
    deleted_query = base_query + where_clause + (" AND" if where_clause else " WHERE") + " r.status = 'resolved_deleted' ORDER BY r.created_at DESC"
    dismissed_query = base_query + where_clause + (" AND" if where_clause else " WHERE") + " r.status = 'dismissed' ORDER BY r.created_at DESC"
    
    pending_reports = db.query(pending_query, params)
    deleted_reports = db.query(deleted_query, params)
    dismissed_reports = db.query(dismissed_query, params)
    
    # Get counts for filter badges
    counts = {
        'all': db.query("SELECT COUNT(*) as c FROM reports WHERE status = 'pending'")[0]['c'],
        'story': db.query("SELECT COUNT(*) as c FROM reports WHERE status = 'pending' AND target_type = 'story'")[0]['c'],
        'activity': db.query("SELECT COUNT(*) as c FROM reports WHERE status = 'pending' AND target_type = 'activity'")[0]['c'],
        'group': db.query("SELECT COUNT(*) as c FROM reports WHERE status = 'pending' AND target_type = 'group'")[0]['c'],
        'comment': db.query("SELECT COUNT(*) as c FROM reports WHERE status = 'pending' AND target_type = 'comment'")[0]['c'],
    }
    
    return render_template('admin/reports.html', 
                          pending_reports=pending_reports,
                          deleted_reports=deleted_reports,
                          dismissed_reports=dismissed_reports,
                          filter_type=filter_type,
                          counts=counts)

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


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================
if __name__ == '__main__':
    app.run(debug=True)
